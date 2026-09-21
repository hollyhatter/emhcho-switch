/* EMHCHO 远程开关 · 核心逻辑（无 UI、无网络）
 *
 * 与 Mac 上 scripts/license/emhcho_crypto.py 逐字节兼容：
 *   canonical(obj)  == json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False)
 *   makeToken()     == cx.make_token()   -> "<payload_b64u>.<sig_b64u>"
 *   openToken()     == cx.open_token()
 * 签名用 tweetnacl（RFC 8032 Ed25519，确定性签名，与 Python 端字节一致）。
 *
 * 浏览器里挂到 window.EmhchoCore；Node 里 module.exports。
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./nacl-fast.min.js")); // 与页面用的是同一份文件
  } else {
    root.EmhchoCore = factory(root.nacl);
  }
})(typeof self !== "undefined" ? self : this, function (nacl) {
  "use strict";
  if (!nacl || !nacl.sign) throw new Error("tweetnacl 未加载");

  // ---------------------------------------------------------------- bytes --
  const te = new TextEncoder();
  const td = new TextDecoder();
  const utf8 = (s) => te.encode(s);
  const fromUtf8 = (b) => td.decode(b);

  function hexToBytes(hex) {
    const h = String(hex).trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]*$/.test(h) || h.length % 2) throw new Error("不是合法的 hex");
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToHex(b) {
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  }
  function concat(...arrs) {
    const n = arrs.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }
  function eq(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  // base64url（无填充），与 Python base64.urlsafe_b64encode(...).rstrip("=") 一致
  function b64u(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    const b64 = (typeof btoa === "function") ? btoa(bin) : Buffer.from(bin, "binary").toString("base64");
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function ub64u(s) {
    let b64 = String(s).trim().replace(/-/g, "+").replace(/_/g, "/");
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
    const bin = (typeof atob === "function") ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ------------------------------------------------------- canonical JSON --
  // 递归按键排序 + 紧凑分隔符。键全是 ASCII 时排序结果与 Python 一致。
  function sortDeep(v) {
    if (Array.isArray(v)) return v.map(sortDeep);
    if (v && typeof v === "object") {
      const o = {};
      for (const k of Object.keys(v).sort()) o[k] = sortDeep(v[k]);
      return o;
    }
    return v;
  }
  function canonical(obj) {
    return JSON.stringify(sortDeep(obj));
  }

  // ------------------------------------------------------------- Ed25519 --
  function pubFromSeed(seed) {
    if (seed.length !== 32) throw new Error("seed 必须是 32 字节（64 个 hex 字符）");
    return nacl.sign.keyPair.fromSeed(seed).publicKey;
  }
  function sign(msgBytes, seed) {
    const kp = nacl.sign.keyPair.fromSeed(seed);
    return nacl.sign.detached(msgBytes, kp.secretKey); // 64 字节
  }
  function verify(sig, msgBytes, pub) {
    try { return nacl.sign.detached.verify(msgBytes, sig, pub); } catch (e) { return false; }
  }

  // ---------------------------------------------------------- token layer --
  function makeToken(obj, seed) {
    const payload = utf8(canonical(obj));
    const sig = sign(payload, seed);
    return b64u(payload) + "." + b64u(sig);
  }
  function openToken(token, pub) {
    const parts = String(token).trim().split(".");
    if (parts.length !== 2) throw new Error("token 格式不对（应为 payload.sig）");
    const payload = ub64u(parts[0]);
    const sig = ub64u(parts[1]);
    if (!verify(sig, payload, pub)) throw new Error("签名校验失败（不是这把公钥签的，或内容被改过）");
    return JSON.parse(fromUtf8(payload));
  }

  // ------------------------------------------------------------- the feed --
  function nowIso() {
    // 与 Python: datetime.now(utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
    return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  }
  function buildFeed({ products = [], licIds = [], killAll = false, asOf = null } = {}) {
    return {
      v: 1,
      as_of: asOf || nowIso(),
      kill_all: !!killAll,
      revoked_lic_ids: Array.from(licIds),
      revoked_products: Array.from(products),
    };
  }
  function feedState(feed) {
    if (!feed) return "unknown";
    if (feed.kill_all) return "kill_all";
    if ((feed.revoked_products || []).length || (feed.revoked_lic_ids || []).length) return "partial";
    return "clear";
  }

  // ----------------------------------------------- PIN 加密（本机保存用） --
  // KDF：迭代 SHA-512（nacl.hash），不依赖 WebCrypto，file:// 里也能用。
  // 默认 120000 轮，手机上约 0.3–1 s。
  const KDF_ITERS = 120000;
  function deriveKey(pin, salt, iters = KDF_ITERS) {
    let h = nacl.hash(concat(salt, utf8(String(pin))));
    for (let i = 0; i < iters; i++) h = nacl.hash(concat(h, salt));
    return h.slice(0, nacl.secretbox.keyLength);
  }
  function sealSecrets(obj, pin, iters = KDF_ITERS) {
    const salt = nacl.randomBytes(16);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const key = deriveKey(pin, salt, iters);
    const box = nacl.secretbox(utf8(JSON.stringify(obj)), nonce, key);
    return { v: 1, kdf: "sha512-iter", iters, salt: b64u(salt), nonce: b64u(nonce), box: b64u(box) };
  }
  function openSecrets(blob, pin) {
    if (!blob || blob.v !== 1) throw new Error("保险箱格式不对");
    const key = deriveKey(pin, ub64u(blob.salt), blob.iters || KDF_ITERS);
    const plain = nacl.secretbox.open(ub64u(blob.box), ub64u(blob.nonce), key);
    if (!plain) throw new Error("PIN 不对");
    return JSON.parse(fromUtf8(plain));
  }

  return {
    utf8, fromUtf8, hexToBytes, bytesToHex, concat, eq, b64u, ub64u,
    canonical, pubFromSeed, sign, verify, makeToken, openToken,
    nowIso, buildFeed, feedState,
    deriveKey, sealSecrets, openSecrets, KDF_ITERS,
  };
});

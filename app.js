/* EMHCHO 远程开关 · 界面与流程（依赖 core.js / tweetnacl）
 *
 * 数据放哪：
 *   localStorage["emhcho.vault"]  PIN 加密后的 {seedHex, token}（nacl.secretbox）
 *   localStorage["emhcho.cfg"]    明文配置 {owner, gist, file, pubHex}（不含秘密）
 *   localStorage["emhcho.log"]    最近 60 条操作记录（不含秘密）
 * 解锁后 seed/token 只在内存里；切后台或 3 分钟不动就清掉并回到锁屏。
 */
(function () {
  "use strict";
  const C = window.EmhchoCore;
  const $ = (id) => document.getElementById(id);
  const LS_VAULT = "emhcho.vault", LS_CFG = "emhcho.cfg", LS_LOG = "emhcho.log";
  const IDLE_MS = 3 * 60 * 1000;
  const PRODUCTS = { gf5b: "EMHCHO-GF5B", dq1: "EMHCHO-DQ1" };

  let secrets = null;      // {seedHex, token}
  let cfg = null;          // {owner, gist, file, pubHex}
  let currentFeed = null;  // 最近一次从 API 读到并验过签的清单
  let idleTimer = null;
  let cdnPoll = null;
  let lastScopes = null;   // 最近一次 API 响应里的 X-OAuth-Scopes（数组；classic 令牌才有）
  const PIN_RULE = /^\S{6,}$/;
  const PIN_HINT = "口令至少 6 位、不含空格（建议 10 位以上、字母数字混合）";

  // ------------------------------------------------------------ helpers --
  const loadJSON = (k) => { try { return JSON.parse(localStorage.getItem(k) || "null"); } catch (e) { return null; } };
  const saveJSON = (k, v) => localStorage.setItem(k, JSON.stringify(v));

  function show(name) {
    document.querySelectorAll(".screen").forEach((s) => s.classList.toggle("on", s.id === "screen-" + name));
    $("btn-lock").style.display = name === "main" ? "" : "none";
    $("hdr-sub").textContent = name === "main" ? (cfg ? `${cfg.owner}/${cfg.gist.slice(0, 8)}… · ${cfg.file}` : "") :
      name === "setup" ? "首次配置" : "已锁定";
  }

  let toastTimer = null;
  function toast(msg, kind) {
    const t = $("toast");
    t.textContent = msg; t.className = "toast on" + (kind ? " " + kind : "");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.className = "toast"), 3200);
  }

  function confirmBox({ title, text, typed, okText = "确定", danger = true }) {
    return new Promise((resolve) => {
      $("ovl-title").textContent = title; $("ovl-text").textContent = text;
      const inp = $("ovl-input");
      inp.style.display = typed ? "" : "none"; inp.value = ""; inp.placeholder = typed ? `请输入「${typed}」` : "";
      const ok = $("ovl-ok"); ok.textContent = okText; ok.className = "btn small " + (danger ? "bad" : "ok");
      $("ovl").classList.add("on");
      if (typed) setTimeout(() => inp.focus(), 50);
      const done = (v) => { $("ovl").classList.remove("on"); ok.onclick = null; $("ovl-cancel").onclick = null; resolve(v); };
      ok.onclick = () => { if (typed && inp.value.trim() !== typed) { toast(`要输入「${typed}」才能继续`, "bad"); return; } done(true); };
      $("ovl-cancel").onclick = () => done(false);
    });
  }

  function promptBox({ title, text, password = false, numeric = false }) {
    return new Promise((resolve) => {
      $("ovl-title").textContent = title; $("ovl-text").textContent = text;
      const inp = $("ovl-input");
      inp.style.display = ""; inp.value = ""; inp.placeholder = ""; inp.type = password ? "password" : "text";
      inp.inputMode = numeric ? "numeric" : "text";
      const ok = $("ovl-ok"); ok.textContent = "确定"; ok.className = "btn small ok";
      $("ovl").classList.add("on"); setTimeout(() => inp.focus(), 50);
      const done = (v) => { $("ovl").classList.remove("on"); inp.type = "text"; ok.onclick = null; $("ovl-cancel").onclick = null; resolve(v); };
      ok.onclick = () => done(inp.value);
      $("ovl-cancel").onclick = () => done(null);
    });
  }

  function log(line) {
    const arr = loadJSON(LS_LOG) || [];
    arr.unshift(`${C.nowIso().replace("T", " ").replace("Z", "Z")}  ${line}`);
    saveJSON(LS_LOG, arr.slice(0, 60));
    renderLog();
  }
  function renderLog() {
    const arr = loadJSON(LS_LOG) || [];
    $("log").textContent = arr.length ? arr.join("\n") : "（空）";
  }

  // ------------------------------------------------------------ locking --
  function lock(reason) {
    secrets = null; currentFeed = null;
    if (cdnPoll) { clearInterval(cdnPoll); cdnPoll = null; }
    $("lock-pin").value = ""; $("lock-err").textContent = reason || "";
    show("lock");
  }
  function armIdle() {
    clearTimeout(idleTimer);
    if (secrets) idleTimer = setTimeout(() => lock("3 分钟没有操作，已自动锁定"), IDLE_MS);
  }
  ["pointerdown", "keydown", "touchstart"].forEach((ev) => document.addEventListener(ev, armIdle, { passive: true }));
  document.addEventListener("visibilitychange", () => { if (document.hidden && secrets) lock("切到后台，已自动锁定"); });

  // ------------------------------------------------------------- GitHub --
  function apiUrl() { return `https://api.github.com/gists/${encodeURIComponent(cfg.gist)}`; }
  function rawUrl() { return `https://gist.githubusercontent.com/${encodeURIComponent(cfg.owner)}/${encodeURIComponent(cfg.gist)}/raw/${encodeURIComponent(cfg.file)}`; }

  async function gh(method, body, token) {
    let r;
    try {
      r = await fetch(apiUrl(), {
        method,
        headers: {
          "Authorization": "Bearer " + (token || secrets.token),
          "Accept": "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        cache: "no-store",
      });
    } catch (e) {
      throw new Error("连不上 api.github.com —— 国内网络需要先开 VPN / 代理（" + e.message + "）");
    }
    const sc = r.headers.get("X-OAuth-Scopes");   // GitHub 通过 CORS 暴露了这个头（实测）
    lastScopes = sc == null ? null : sc.split(",").map((s) => s.trim()).filter(Boolean);
    if (r.status === 401) throw new Error("GitHub 令牌无效或已过期（401）");
    if (r.status === 403) throw new Error("被 GitHub 拒绝（403）：令牌权限不够，或触发限流");
    if (r.status === 404) throw new Error("找不到这个 gist（404）：ID 不对，或令牌没有 gist 权限");
    if (!r.ok) throw new Error(`GitHub 返回 ${r.status}`);
    return r.json();
  }

  function pubBytes() { return C.hexToBytes(cfg.pubHex); }

  async function readViaApi(token) {
    const j = await gh("GET", null, token);
    const f = j.files && j.files[cfg.file];
    if (!f) throw new Error(`gist 里没有 ${cfg.file} 这个文件`);
    const raw = String(f.content || "").trim();
    const feed = C.openToken(raw, pubBytes());
    return { feed, raw, updated: j.updated_at };
  }

  async function readViaCdn() {
    // 不加 cache-bust：这就是服务器读到的那个 URL 与那份缓存
    let r;
    try { r = await fetch(rawUrl(), { cache: "no-store" }); }
    catch (e) { throw new Error("连不上 gist.githubusercontent.com（" + e.message + "）"); }
    if (!r.ok) throw new Error(`raw 返回 ${r.status}`);
    const raw = (await r.text()).trim();
    return { feed: C.openToken(raw, pubBytes()), raw };
  }

  async function writeFeed(feedObj) {
    const token = C.makeToken(feedObj, C.hexToBytes(secrets.seedHex));
    // 写之前先自己验一遍：签出来的必须能被生产公钥打开
    const chk = C.openToken(token, pubBytes());
    if (C.canonical(chk) !== C.canonical(feedObj)) throw new Error("本地自检失败：签名内容与预期不一致");
    await gh("PATCH", { files: { [cfg.file]: { content: token } } });
    const back = await readViaApi();
    if (back.raw !== token) throw new Error("写入后回读不一致（可能有别处同时在改这个 gist）");
    return back;
  }

  // ------------------------------------------------------------ display --
  function describe(feed) {
    const st = C.feedState(feed);
    const prods = feed.revoked_products || [], lics = feed.revoked_lic_ids || [];
    let big, chip, cls;
    if (st === "kill_all") { big = "已全部停止"; chip = "全停"; cls = "c-bad"; }
    else if (st === "partial") { big = "部分停止"; chip = `已停 ${prods.length} 项 · ${lics.length} 张牌`; cls = "c-warn"; }
    else { big = "运行中"; chip = "全部任务可启动"; cls = "c-ok"; }
    return { st, big, chip, cls, prods, lics };
  }

  function renderStatus(api, cdn, latestRaw) {
    if (api) {
      currentFeed = api.feed;
      const d = describe(api.feed);
      $("st-big").textContent = d.big;
      $("st-chip").textContent = d.chip; $("st-chip").className = "chip " + d.cls;
      const friendly = (p) => p.replace(/^EMHCHO-/, "");
      $("st-detail").innerHTML =
        `已停止的卫星：<b>${d.prods.length ? d.prods.map(friendly).join("、") : "无（全部在运行）"}</b>` +
        (d.lics.length ? `<br>另按牌号停了 <b>${d.lics.length}</b> 张` : "") +
        `<br><span class="muted">最新版时间 ${api.feed.as_of || "?"}</span>`;
      // 按钮文案随状态切换
      $("act-gf5b").innerHTML = d.prods.includes(PRODUCTS.gf5b) ? "恢复 GF5B<small>取消对 EMHCHO-GF5B 的吊销</small>" : "停 GF5B<small>EMHCHO-GF5B · cron #17 #18</small>";
      $("act-gf5b").className = "btn " + (d.prods.includes(PRODUCTS.gf5b) ? "ok" : "bad");
      $("act-dq1").innerHTML = d.prods.includes(PRODUCTS.dq1) ? "恢复 DQ1<small>取消对 EMHCHO-DQ1 的吊销</small>" : "停 DQ1<small>EMHCHO-DQ1 · cron #21</small>";
      $("act-dq1").className = "btn " + (d.prods.includes(PRODUCTS.dq1) ? "ok" : "bad");
    }
    if (cdn) {
      const ref = api ? api.raw : latestRaw;   // 以哪一版为「最新」来比对
      const same = ref != null && cdn.raw === ref;
      const d = describe(cdn.feed);
      $("st-cdn").innerHTML = `服务器视角（CDN 缓存）· as_of <code>${cdn.feed.as_of || "?"}</code> · ${d.big} ` +
        (ref == null ? "" : same ? `<span class="chip c-ok">已与最新版一致</span>` : `<span class="chip c-warn">还是旧版，等 CDN 更新</span>`);
    }
  }

  async function refresh(silent) {
    if (!secrets) return;
    if (!silent) { $("st-chip").textContent = "读取中"; $("st-chip").className = "chip c-info"; }
    try {
      const api = await readViaApi();
      let cdn = null;
      try { cdn = await readViaCdn(); } catch (e) { $("st-cdn").innerHTML = `<span class="muted">服务器视角读取失败：${e.message}</span>`; }
      renderStatus(api, cdn);
      $("act-err").textContent = "";
      return { api, cdn };
    } catch (e) {
      $("st-big").textContent = "读取失败"; $("st-chip").textContent = "—"; $("st-chip").className = "chip c-bad";
      $("st-detail").textContent = e.message;
      throw e;
    }
  }

  function startCdnPoll(wantRaw) {
    if (cdnPoll) clearInterval(cdnPoll);
    let n = 0;
    cdnPoll = setInterval(async () => {
      n++;
      try {
        const cdn = await readViaCdn();
        renderStatus(null, { feed: cdn.feed, raw: cdn.raw }, wantRaw);
        if (cdn.raw === wantRaw) {
          log(`CDN 已更新到 as_of=${cdn.feed.as_of}（第 ${n} 次轮询）`);
          toast("服务器视角已更新，下一次任务启动即生效", "ok");
          clearInterval(cdnPoll); cdnPoll = null;
        }
      } catch (e) { /* 忽略单次失败 */ }
      if (n >= 24) { clearInterval(cdnPoll); cdnPoll = null; log("等 CDN 超过 6 分钟仍未更新，停止轮询（可手动刷新）"); }
    }, 15000);
  }

  // ------------------------------------------------------------ actions --
  async function applyChange(label, mutate, opts = {}) {
    if (!secrets) return;
    $("act-err").textContent = "";
    let base = currentFeed;
    try { if (!base) base = (await refresh(true)).api.feed; }
    catch (e) { $("act-err").textContent = "先读不到当前清单，未执行：" + e.message; return; }

    const next = mutate({
      products: new Set(base.revoked_products || []),
      licIds: new Set(base.revoked_lic_ids || []),
      killAll: !!base.kill_all,
    });
    const feedObj = C.buildFeed({ products: [...next.products].sort(), licIds: [...next.licIds].sort(), killAll: next.killAll });
    const d = describe(feedObj);
    const ok = await confirmBox({
      title: label,
      text: `写入后清单将变为：${d.big}（产品 ${d.prods.length ? d.prods.join("、") : "无"}；牌 ${d.lics.length} 张）。服务器约 2–5 分钟后读到。`,
      typed: opts.typed, okText: opts.okText || "签名并写入", danger: opts.danger !== false,
    });
    if (!ok) return;

    const btns = document.querySelectorAll("#screen-main button");
    btns.forEach((b) => (b.disabled = true));
    toast("正在签名并写入 gist…");
    try {
      const back = await writeFeed(feedObj);
      log(`${label} → 已写入 gist，as_of=${feedObj.as_of}，回读校验通过`);
      toast("已写入并校验通过，等待 CDN 传播", "ok");
      renderStatus(back, null);
      $("st-cdn").innerHTML = `<span class="muted">正在等 CDN 把新版给到服务器（每 15 s 查一次）…</span>`;
      startCdnPoll(back.raw);
    } catch (e) {
      log(`${label} → 失败：${e.message}`);
      $("act-err").textContent = e.message;
      toast("失败：" + e.message, "bad");
    } finally {
      btns.forEach((b) => (b.disabled = false));
    }
  }

  function toggleProduct(name) {
    return (s) => {
      if (s.products.has(name)) s.products.delete(name); else s.products.add(name);
      return s;
    };
  }

  $("act-gf5b").onclick = () => {
    const revoked = currentFeed && (currentFeed.revoked_products || []).includes(PRODUCTS.gf5b);
    applyChange(revoked ? "恢复 GF5B" : "吊销 GF5B（EMHCHO-GF5B）", toggleProduct(PRODUCTS.gf5b), { danger: !revoked, okText: revoked ? "签名并恢复" : "签名并吊销" });
  };
  $("act-dq1").onclick = () => {
    const revoked = currentFeed && (currentFeed.revoked_products || []).includes(PRODUCTS.dq1);
    applyChange(revoked ? "恢复 DQ1" : "吊销 DQ1（EMHCHO-DQ1）", toggleProduct(PRODUCTS.dq1), { danger: !revoked, okText: revoked ? "签名并恢复" : "签名并吊销" });
  };
  $("act-kill").onclick = () => applyChange("一键全部停止", (s) => { s.killAll = true; return s; }, { okText: "确认停止全部" });
  $("act-clear").onclick = () => applyChange("恢复运行（全部恢复）", (s) => { s.products.clear(); s.licIds.clear(); s.killAll = false; return s; }, { danger: false, okText: "确认恢复" });
  $("act-lic-revoke").onclick = () => {
    const id = $("act-licid").value.trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(id)) { $("act-err").textContent = "lic_id 应是 32 位 hex"; return; }
    applyChange(`吊销牌 ${id.slice(0, 8)}…`, (s) => { s.licIds.add(id); return s; });
  };
  $("act-lic-restore").onclick = () => {
    const id = $("act-licid").value.trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(id)) { $("act-err").textContent = "lic_id 应是 32 位 hex"; return; }
    applyChange(`恢复牌 ${id.slice(0, 8)}…`, (s) => { s.licIds.delete(id); return s; }, { danger: false, okText: "签名并恢复" });
  };
  // ------------------------------------------------------- purge（危险） --
  // 销毁走「单独签名的指令」：签一条独立 payload 写到 gist 的 purge.json（不是 revocation.json）。
  // 服务器端销毁代理默认不动手，核验签名+目标机+时效+防重放全通过、且单独武装才执行。
  function randNonce() { return C.bytesToHex(nacl.randomBytes(12)); }
  async function publishPurge(kind) {
    const obj = { purge: kind, target: "sthl-server:EMHCHO", as_of: C.nowIso(), nonce: randNonce() };
    const token = C.makeToken(obj, C.hexToBytes(secrets.seedHex));
    const chk = C.openToken(token, pubBytes());              // 写前自检：能被生产公钥打开
    if (C.canonical(chk) !== C.canonical(obj)) throw new Error("本地自检失败：签名内容与预期不一致");
    let r;
    try {
      r = await fetch(apiUrl(), {
        method: "PATCH",
        headers: { "Authorization": "Bearer " + secrets.token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" },
        body: JSON.stringify({ files: { "purge.json": { content: token } } }),
        cache: "no-store",
      });
    } catch (e) { throw new Error("连不上 api.github.com（" + e.message + "）"); }
    if (!r.ok) throw new Error("写入 purge.json 失败：GitHub " + r.status);
    return obj;
  }
  async function doPurge(kind) {
    if (!secrets) return;
    $("purge-err").textContent = "";
    if ($("purge-confirm").value.trim() !== "DESTROY EMHCHO") { $("purge-err").textContent = "要逐字输入 DESTROY EMHCHO 才能继续"; return; }
    const label = kind === "hard" ? "硬销毁（rm -rf 我们的部署目录，不可逆）" : "软销毁（只擦授权物料，代码留着）";
    const ok = await confirmBox({
      title: "远程销毁 · 二次确认",
      text: `确定要签发【${label}】指令并写入 gist 吗？服务器端销毁代理若已武装，将在下一次运行时执行；未武装则不动手。此操作用于放弃部署，不是日常停用。`,
      typed: "DESTROY EMHCHO", okText: "签发销毁指令",
    });
    if (!ok) return;
    const btns = document.querySelectorAll("#screen-main button");
    btns.forEach((b) => (b.disabled = true));
    toast("正在签发销毁指令…");
    try {
      const obj = await publishPurge(kind);
      log(`签发销毁指令 ${kind} → 写入 purge.json，as_of=${obj.as_of}，nonce=${obj.nonce.slice(0, 8)}…`);
      toast("销毁指令已写入（服务器代理武装后才会执行）", "ok");
      $("purge-confirm").value = "";
    } catch (e) {
      log(`签发销毁指令失败：${e.message}`);
      $("purge-err").textContent = e.message; toast("失败：" + e.message, "bad");
    } finally {
      btns.forEach((b) => (b.disabled = false));
    }
  }
  $("act-purge-soft").onclick = () => doPurge("soft");
  $("act-purge-hard").onclick = () => doPurge("hard");

  $("btn-refresh").onclick = () => refresh().catch(() => {});
  $("btn-clearlog").onclick = () => { localStorage.removeItem(LS_LOG); renderLog(); };
  $("btn-lock").onclick = () => lock("");

  // ----------------------------------------------------------- settings --
  $("btn-nettest").onclick = async () => {
    $("set-net").textContent = "测试中…";
    const t0 = Date.now();
    try {
      const r = await fetch("https://api.github.com/", { cache: "no-store" });
      $("set-net").innerHTML = `<span class="chip c-ok">能连 api.github.com（HTTP ${r.status}，${Date.now() - t0} ms）</span>`;
    } catch (e) {
      $("set-net").innerHTML = `<span class="chip c-bad">连不上（${e.message}）—— 国内需先开 VPN / 代理</span>`;
    }
  };
  $("btn-changepin").onclick = async () => {
    const oldPin = await promptBox({ title: "修改口令", text: "先输入当前口令", password: true });
    if (oldPin == null) return;
    const vault = loadJSON(LS_VAULT);
    let sec;
    try { sec = C.openSecrets(vault, oldPin); } catch (e) { toast("当前口令不对", "bad"); return; }
    const p1 = await promptBox({ title: "修改口令", text: "输入新口令（" + PIN_HINT + "）", password: true });
    if (p1 == null) return;
    if (!PIN_RULE.test(p1)) { toast(PIN_HINT, "bad"); return; }
    const p2 = await promptBox({ title: "修改口令", text: "再输一次新口令", password: true });
    if (p2 !== p1) { toast("两次输入不一致", "bad"); return; }
    saveJSON(LS_VAULT, C.sealSecrets(sec, p1));
    log("已修改口令");
    toast("口令已修改", "ok");
  };
  async function wipe() {
    const ok = await confirmBox({ title: "擦除本机全部数据", text: "将删除加密保存的私钥、令牌、配置和操作记录。Mac 上的 seed.hex 不受影响。", typed: "擦除", okText: "擦除" });
    if (!ok) return;
    localStorage.clear(); secrets = null; cfg = null; currentFeed = null;
    location.reload();
  }
  $("btn-wipe").onclick = wipe;
  $("btn-wipe-lock").onclick = wipe;

  // -------------------------------------------------------------- setup --
  function seedCheck() {
    const seedHex = $("su-seed").value.trim().toLowerCase();
    const el = $("su-pubcheck");
    if (!seedHex) { el.textContent = ""; return null; }
    try {
      const pub = C.bytesToHex(C.pubFromSeed(C.hexToBytes(seedHex)));
      const want = $("su-pub").value.trim().toLowerCase();
      if (pub === want) el.innerHTML = `<span class="chip c-ok">seed 正确：推出的公钥与期望一致</span>`;
      else el.innerHTML = `<span class="chip c-bad">seed 推出的公钥是 ${pub.slice(0, 12)}…，与期望不一致</span>`;
      return pub;
    } catch (e) { el.innerHTML = `<span class="chip c-bad">${e.message}</span>`; return null; }
  }
  $("su-seed").addEventListener("input", seedCheck);
  $("su-pub").addEventListener("input", seedCheck);

  $("btn-save").onclick = async () => {
    const err = $("su-err"); err.textContent = "";
    const seedHex = $("su-seed").value.trim().toLowerCase();
    const pubHex = $("su-pub").value.trim().toLowerCase();
    const token = $("su-token").value.trim();
    const owner = $("su-owner").value.trim(), gist = $("su-gist").value.trim(), file = $("su-file").value.trim();
    const pin = $("su-pin").value, pin2 = $("su-pin2").value;
    try {
      if (!/^[0-9a-f]{64}$/.test(seedHex)) throw new Error("seed 必须是 64 个 hex 字符");
      if (!/^[0-9a-f]{64}$/.test(pubHex)) throw new Error("期望公钥必须是 64 个 hex 字符");
      if (C.bytesToHex(C.pubFromSeed(C.hexToBytes(seedHex))) !== pubHex) throw new Error("seed 推出的公钥与期望公钥不一致，拒绝保存（贴错了？）");
      if (!token) throw new Error("请填 GitHub 令牌");
      if (/^github_pat_/.test(token)) throw new Error("这是 fine-grained 令牌，GitHub 不允许它访问 gist；请新建 classic token 并只勾 gist");
      if (!owner || !/^[0-9a-f]{20,}$/i.test(gist) || !file) throw new Error("gist 所有者 / ID / 文件名不完整");
      if (!PIN_RULE.test(pin)) throw new Error(PIN_HINT);
      if (pin !== pin2) throw new Error("两次口令不一致");
      $("btn-save").disabled = true; $("btn-save").textContent = "正在向 GitHub 试读 gist…";
      cfg = { owner, gist, file, pubHex };
      lastScopes = null;
      const probe = await readViaApi(token);     // 令牌 + gist + 现有清单签名 一次全验
      // 令牌权限范围：只许 gist。Mac 上那把全权限令牌（repo/admin/delete_repo…）绝不能进手机。
      if (lastScopes && lastScopes.some((s) => s !== "gist")) {
        const extra = lastScopes.filter((s) => s !== "gist");
        throw new Error(`拒收：这个令牌除 gist 外还带 ${extra.length} 项权限（${extra.slice(0, 4).join(", ")}${extra.length > 4 ? "…" : ""}）。` +
          "请到 github.com/settings/tokens 新建一个 classic token，只勾 gist 一项。");
      }
      if (lastScopes && !lastScopes.includes("gist")) throw new Error("这个令牌没有 gist 权限，写不了吊销清单");
      $("btn-save").textContent = "正在加密保存…";
      await new Promise((r) => setTimeout(r, 30));
      saveJSON(LS_VAULT, C.sealSecrets({ seedHex, token }, pin));
      saveJSON(LS_CFG, cfg);
      secrets = { seedHex, token };
      ["su-seed", "su-token", "su-pin", "su-pin2"].forEach((id) => ($(id).value = ""));
      log(`完成首次配置；令牌权限=${lastScopes ? lastScopes.join(",") : "未知"}；gist 当前 as_of=${probe.feed.as_of}`);
      enterMain();
    } catch (e) {
      err.textContent = e.message;
    } finally {
      $("btn-save").disabled = false; $("btn-save").textContent = "校验并加密保存到本机";
    }
  };

  // ------------------------------------------------------------- unlock --
  $("btn-unlock").onclick = async () => {
    const pin = $("lock-pin").value;
    const vault = loadJSON(LS_VAULT);
    $("lock-err").textContent = ""; $("btn-unlock").disabled = true; $("btn-unlock").textContent = "解锁中…";
    await new Promise((r) => setTimeout(r, 30));
    try {
      secrets = C.openSecrets(vault, pin);
      cfg = loadJSON(LS_CFG);
      $("lock-pin").value = "";
      enterMain();
    } catch (e) {
      $("lock-err").textContent = e.message;
    } finally {
      $("btn-unlock").disabled = false; $("btn-unlock").textContent = "解锁";
    }
  };
  $("lock-pin").addEventListener("keydown", (e) => { if (e.key === "Enter") $("btn-unlock").click(); });

  function describeEnv() {
    const standalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
    const secure = window.isSecureContext && location.protocol !== "file:";
    const sw = !!(navigator.serviceWorker && navigator.serviceWorker.controller);
    if (location.protocol === "file:") return `<span class="chip c-warn">本地文件打开</span> 数据随浏览器对 file:// 的处理而定，不建议长期用`;
    if (!secure) return `<span class="chip c-warn">HTTP（局域网）</span> 只能在线打开，装不成离线 App；要离线 / 外网可用需 HTTPS 托管`;
    return `<span class="chip c-ok">HTTPS</span> ${standalone ? "已作为 App 安装" : "浏览器内"} · ${sw ? "壳已缓存，可离线打开" : "首次打开，缓存中…"}`;
  }

  function enterMain() {
    show("main");
    $("set-pub").textContent = cfg.pubHex.slice(0, 16) + "…" + cfg.pubHex.slice(-8);
    $("set-gist").textContent = `${cfg.owner}/${cfg.gist} · ${cfg.file}`;
    $("set-env").innerHTML = describeEnv();
    renderLog(); armIdle();
    refresh().catch(() => {});
  }

  // --------------------------------------------------------------- boot --
  (function boot() {
    if (!window.EmhchoCore) { document.body.innerHTML = "<p style='padding:20px'>core.js 未加载</p>"; return; }
    renderLog();
    if (loadJSON(LS_VAULT) && loadJSON(LS_CFG)) show("lock"); else show("setup");
    // 只在安全上下文（HTTPS）里注册 Service Worker；局域网 HTTP 下浏览器本来就不允许，静默跳过。
    if ("serviceWorker" in navigator && window.isSecureContext && location.protocol !== "file:") {
      navigator.serviceWorker.register("./sw.js").catch(() => {});
    }
  })();
})();

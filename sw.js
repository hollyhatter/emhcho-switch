/* EMHCHO 远程开关 · Service Worker
 * 只做一件事：把 App 壳（本目录这几个文件）缓存下来，装到桌面后断网也能打开到锁屏。
 * 绝不碰跨域请求（api.github.com / gist.githubusercontent.com 一律直接走网络、不缓存）。
 * 改任何 www/ 文件后把 VERSION 加一，旧缓存会在 activate 时清掉。
 */
const VERSION = "2026-09-21b";
const CACHE = "emhcho-shell-" + VERSION;
const SHELL = ["./", "./index.html", "./core.js", "./app.js", "./nacl-fast.min.js",
  "./manifest.webmanifest", "./icon-192.png", "./icon-512.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;                       // PATCH 等一律放行
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;        // 跨域（GitHub）不拦
  // 同源：先给缓存（离线可开），同时后台拉新版刷进缓存（下次打开就是新版）
  e.respondWith(
    caches.open(CACHE).then(async (c) => {
      const hit = await c.match(req, { ignoreSearch: true });
      const net = fetch(req).then((r) => { if (r && r.ok) c.put(req, r.clone()); return r; }).catch(() => null);
      return hit || (await net) || new Response("offline", { status: 503 });
    })
  );
});

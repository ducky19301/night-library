/* Library service worker. Shell + encrypted blobs cached; data.bin network-first. */
const VERSION = "f7704e3db3cd";
const SHELL = ["./", "app.js", "icons/apple-touch-icon.png", "icons/icon-192.png", "icons/icon-512.png", "icons/icon-maskable-512.png", "index.html", "keyinfo.json", "manifest.webmanifest", "robots.txt", "styles.css", "vendor/marked.min.js", "vendor/pdf.min.mjs", "vendor/pdf.worker.min.mjs", "vendor/purify.min.js", "vendor/standard_fonts/FoxitDingbats.pfb", "vendor/standard_fonts/FoxitFixed.pfb", "vendor/standard_fonts/FoxitFixedBold.pfb", "vendor/standard_fonts/FoxitFixedBoldItalic.pfb", "vendor/standard_fonts/FoxitFixedItalic.pfb", "vendor/standard_fonts/FoxitSerif.pfb", "vendor/standard_fonts/FoxitSerifBold.pfb", "vendor/standard_fonts/FoxitSerifBoldItalic.pfb", "vendor/standard_fonts/FoxitSerifItalic.pfb", "vendor/standard_fonts/FoxitSymbol.pfb", "vendor/standard_fonts/LICENSE_FOXIT", "vendor/standard_fonts/LICENSE_LIBERATION", "vendor/standard_fonts/LiberationSans-Bold.ttf", "vendor/standard_fonts/LiberationSans-BoldItalic.ttf", "vendor/standard_fonts/LiberationSans-Italic.ttf", "vendor/standard_fonts/LiberationSans-Regular.ttf"];
const SHELL_CACHE = "lib-shell-" + VERSION;
const BLOB_CACHE = "lib-blobs-v1";
const DATA_CACHE = "lib-data-v1";

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(SHELL_CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) {
      if (k.startsWith("lib-shell-") && k !== SHELL_CACHE) await caches.delete(k);
    }
    await self.clients.claim();
  })());
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  const p = url.pathname;
  if (/\/f\/[0-9a-f]+\.bin$/.test(p)) {           // immutable, content-addressed
    e.respondWith(caches.open(BLOB_CACHE).then(async (c) => {
      const hit = await c.match(e.request);
      if (hit) return hit;
      const r = await fetch(e.request);
      if (r.ok) c.put(e.request, r.clone());
      return r;
    }));
    return;
  }
  if (/(data|search)\.bin$|keyinfo\.json$/.test(p)) { // network-first, offline fallback
    e.respondWith((async () => {
      const c = await caches.open(DATA_CACHE);
      try {
        const r = await fetch(e.request, { cache: "no-store" });
        if (r.ok) c.put(e.request, r.clone());
        return r;
      } catch (err) {
        const hit = await c.match(e.request);
        if (hit) return hit;
        throw err;
      }
    })());
    return;
  }
  e.respondWith(caches.match(e.request, { ignoreSearch: true }).then((hit) => hit || fetch(e.request).catch(() => caches.match("./"))));
});

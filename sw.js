// Service Worker — مُحكَم للمحاسبة. أصول مُجزَّأة بالتجزئة: كاش أولًا. الصفحة وconfig.js: الشبكة أولًا. واجهة Supabase: لا تُخزَّن أبدًا.
const V = 'acc-15a8adedd4'; /* الرمز المؤقت في اسم الكاش يُستبدل ببصمة المحتوى عند البناء (vite.config.ts) فيتغير الملف مع كل إصدار */ const SHELL = ['./', './index.html', './manifest.webmanifest', './icon-192.png', './icon-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(V).then(c => c.addAll(SHELL)).catch(() => { /* */ })); /* بلا تفعيل فوري: النسخة الجديدة تنتظر حتى يضغط المستخدم «تحديث الآن» (UpdateNotice) */ });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('message', e => { if (e.data === 'skip') self.skipWaiting(); });
self.addEventListener('fetch', e => {
  const r = e.request; if (r.method !== 'GET') return; const u = new URL(r.url);
  if (u.origin !== location.origin) return; // Supabase وغيره: مباشرة للشبكة
  if (/\/assets\/.+\.(js|css|woff2|png|jpg|svg)$/.test(u.pathname)) { // ملفات ببصمة المحتوى: لا تتغير
    e.respondWith(caches.match(r).then(h => h || fetch(r).then(n => { if (n.ok) { const c = n.clone(); caches.open(V).then(x => x.put(r, c)); } return n; }))); return; }
  // الصفحة، config.js، manifest: الشبكة أولًا مع رجوع للكاش (يعمل دون إنترنت)
  e.respondWith(fetch(r).then(n => { if (n.ok && !/config\.js$/.test(u.pathname)) { const c = n.clone(); caches.open(V).then(x => x.put(r, c)); } return n; })
    .catch(() => caches.match(r).then(h => h || (r.mode === 'navigate' ? caches.match('./index.html') : Response.error()))));
});

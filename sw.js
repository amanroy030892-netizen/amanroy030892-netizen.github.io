// SafarSaathi Service Worker - Cache ID: ss-v2-zero-scratch-cache
const CACHE_NAME = 'ss-v2-zero-scratch-cache';
const PRECACHE_URLS = [
  './index.html',
  './admin.html',
  './manifest.json'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE_URLS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  // Network first for realtime database and APIs, fallback to cache
  if (event.request.url.includes('firebase') || event.request.url.includes('agora')) {
    return;
  }
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});

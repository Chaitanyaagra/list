const CACHE='tota-price-manager-v275';
const CATALOG_CACHE='pm-viewer-catalogs-v228';
const LOCAL=['./','./index.html','./firebase-config.js','./secure-access.js','./manifest.json','./icon-192.png','./icon-512.png','./icon-512-maskable.png'];
const VENDOR=[
 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js',
 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js',
 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
 'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js',
 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js',
 'https://www.gstatic.com/firebasejs/10.13.2/firebase-app-compat.js',
 'https://www.gstatic.com/firebasejs/10.13.2/firebase-auth-compat.js',
 'https://www.gstatic.com/firebasejs/10.13.2/firebase-firestore-compat.js',
 'https://www.gstatic.com/firebasejs/10.13.2/firebase-storage-compat.js'
];
self.addEventListener('install',e=>{e.waitUntil((async()=>{
  const c=await caches.open(CACHE);
  await c.addAll(LOCAL);
  // Optional CDN dependencies must never prevent a new app shell from installing.
  await Promise.allSettled(VENDOR.map(async u=>{try{const r=await fetch(new Request(u,{mode:'cors'}));if(r&&r.ok)await c.put(u,r)}catch(_){}}));
})());self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil((async()=>{
  const keys=await caches.keys();await Promise.all(keys.filter(k=>(k.startsWith('tota-price-manager-')&&k!==CACHE)||(k.startsWith('pm-viewer-catalogs-')&&k!==CATALOG_CACHE)).map(k=>caches.delete(k)));await self.clients.claim();
})())});
async function networkWithTimeout(req,ms=2600){
  const ctrl=new AbortController(),t=setTimeout(()=>ctrl.abort(),ms);try{return await fetch(req,{signal:ctrl.signal})}finally{clearTimeout(t)}
}

self.addEventListener('message',e=>{if(e.data&&e.data.type==='SKIP_WAITING')self.skipWaiting()});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  const url=e.request.url,isVendor=VENDOR.includes(url);
  if(isVendor){e.respondWith((async()=>{const hit=await caches.match(e.request);if(hit)return hit;const r=await fetch(e.request);if(r&&r.ok){const c=await caches.open(CACHE);c.put(e.request,r.clone()).catch(()=>{})}return r})());return}
  const u=new URL(url);if(u.origin!==self.location.origin)return; // Firebase/Storage remain network-managed, not general-cache data.
  if(e.request.mode==='navigate'){
    e.respondWith((async()=>{const cached=(await caches.match('./index.html'))||(await caches.match('./'));try{const r=await networkWithTimeout(e.request);if(r&&r.ok){const c=await caches.open(CACHE);c.put('./index.html',r.clone()).catch(()=>{});return r}return cached||r}catch(_){return cached}})());return;
  }
  // Versioned/local assets: instant cache response, then refresh in the background.
  e.respondWith((async()=>{const hit=await caches.match(e.request);const refresh=fetch(e.request).then(async r=>{if(r&&r.ok){const c=await caches.open(CACHE);await c.put(e.request,r.clone())}return r}).catch(()=>null);if(hit){e.waitUntil(refresh);return hit}const r=await refresh;if(r)return r;throw new Error('offline')})());
});

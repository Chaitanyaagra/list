const CACHE='tota-price-manager-v230';
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
self.addEventListener('install',e=>{e.waitUntil((async()=>{const c=await caches.open(CACHE);await c.addAll(LOCAL);await Promise.allSettled(VENDOR.map(u=>c.add(new Request(u,{mode:'cors'}))))})());self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>
  (k.startsWith('tota-price-manager-')&&k!==CACHE) ||
  (k.startsWith('pm-viewer-catalogs-')&&k!==CATALOG_CACHE)
).map(k=>caches.delete(k)))));self.clients.claim()});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  const url=e.request.url,isVendor=VENDOR.includes(url);
  if(isVendor){
    e.respondWith(caches.match(e.request).then(hit=>hit||fetch(e.request).then(res=>{if(res&&res.ok){const cp=res.clone();caches.open(CACHE).then(c=>c.put(e.request,cp)).catch(()=>{})}return res})));
    return;
  }
  // Never put arbitrary cross-origin/Firebase/Storage responses in the general PWA cache.
  const reqUrl=new URL(url);
  if(reqUrl.origin!==self.location.origin)return;
  e.respondWith(fetch(e.request).then(res=>{if(res&&res.ok){const cp=res.clone();caches.open(CACHE).then(c=>c.put(e.request,cp)).catch(()=>{})}return res}).catch(async()=>{
    const hit=await caches.match(e.request);if(hit)return hit;
    if(e.request.mode==='navigate')return (await caches.match('./index.html'))||(await caches.match('./'));
    throw new Error('offline');
  }));
});

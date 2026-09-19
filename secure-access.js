(()=>{
  const CACHE_PREFIX='pm-restricted-payload-v228:';
  const PAYLOAD_SCHEMA=3, PUBLISH_REV='v270-r1', PART_CHARS=150000, OFFLINE_TTL=24*60*60*1000;
  const VIEWER_SESSION_KEY='pm-viewer-session-v271', VIEWER_SESSION_APP='pm-viewer-session-v271', VIEWER_SESSION_MS=6*60*60*1000;
  let cloudSession=null, publishTimer=null, publishSuppress=false, restrictedSyncQueue=Promise.resolve(), cloudPublishDirty265=true, viewerSessionTimer271=null;
  const safe=x=>String(x??''), norm=x=>safe(x).trim().toLowerCase(), clone=x=>x==null?x:JSON.parse(JSON.stringify(x));
  const round2=x=>Math.round((+x||0)*100)/100;
  const fmtRate=x=>x==null||isNaN(x)?'—':((S.settings&&S.settings.currency)||'₹')+Number(x).toLocaleString('en-IN',{minimumFractionDigits:Number(x)%1?2:0,maximumFractionDigits:2});
  const api=()=>window.PMFirebase41||null;
  S.catalogFiles=S.catalogFiles||[];

  async function ready(){
    const a=api();if(!a)throw Error('Firebase module is not ready');
    const cfg=await a.getSavedConfig();if(!cfg)throw Error('Firebase is not configured. Add firebase-config.js or connect Firebase in Settings.');
    a.ensureFirebase(cfg);
    const storage=(typeof firebase!=='undefined'&&firebase.storage&&a.app)?a.app.storage():null;
    return {cfg,auth:a.auth,db:a.db,storage};
  }
  async function sha256(s){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
  // Legacy deterministic address is kept only for backward-compatible sign-in.
  async function loginEmail(name,pid){const n=norm(name),slug=(n.replace(/[^a-z0-9._-]+/g,'.').replace(/^\.+|\.+$/g,'').slice(0,36)||'user'),h=(await sha256(n+'|'+pid)).slice(0,10);return `${slug}.${h}@access.${safe(pid).replace(/[^a-z0-9.-]/gi,'')}.app`}
  // v2 address also binds the PIN. A deleted/orphaned legacy Auth user can no longer permanently block recreating the same username.
  async function loginEmailV2(name,pin,pid){const n=norm(name),slug=(n.replace(/[^a-z0-9._-]+/g,'.').replace(/^\.+|\.+$/g,'').slice(0,28)||'user'),h=(await sha256(`${n}|${safe(pin)}|${pid}|v2`)).slice(0,16);return `${slug}.${h}@access.${safe(pid).replace(/[^a-z0-9.-]/gi,'')}.app`}
  async function loginPassword(name,pin,pid){return 'Pm!'+(await sha256(`${pid}|${norm(name)}|${safe(pin)}`)).slice(0,36)}
  function cloudErrorMessage(e){
    const code=safe(e&&e.code),msg=safe(e&&e.message);
    if(code==='auth/operation-not-allowed')return 'Email/Password sign-in is disabled in Firebase Authentication. Enable it under Authentication → Sign-in method.';
    if(code==='auth/unauthorized-domain')return 'This website domain is not authorised in Firebase Authentication. Add the deployed domain under Authentication → Settings → Authorised domains.';
    if(code==='auth/too-many-requests')return 'Firebase temporarily throttled account creation/sign-in. Wait a little and use Retry cloud.';
    if(code==='auth/network-request-failed'||/network|failed to fetch/i.test(msg))return 'Firebase could not be reached. Check internet connection and Firebase configuration, then retry.';
    if(code==='permission-denied'||/permission/i.test(msg))return 'Firestore rejected the cloud publish. Publish the firestore.rules included with this build and confirm the Owner Firebase account is signed in.';
    if(code==='auth/requires-recent-login')return 'Firebase requires a fresh Owner sign-in. Sign out/in under Firebase Settings and retry.';
    if(code==='auth/email-already-in-use')return 'A stale Firebase Auth account is using this login identity. This build can repair most stale accounts; retry once after refreshing the app.';
    return msg||code||'Cloud login could not be created.';
  }
  function b64(bytes){let s='';bytes.forEach(x=>s+=String.fromCharCode(x));return btoa(s)}
  async function offlineVerifier(name,pin,pid){
    const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(safe(pin)),{name:'PBKDF2'},false,['deriveBits']);
    const salt=new TextEncoder().encode(`pm227|${pid}|${norm(name)}`);
    const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:120000,hash:'SHA-256'},key,256);
    return b64(new Uint8Array(bits));
  }
  async function ensureOwner(db,uid){
    const sec=db.collection('meta').doc('security'),snap=await sec.get();
    if(snap.exists){if(snap.data().ownerUid!==uid)throw Error('This Firebase project is linked to a different owner account (uid on file: '+snap.data().ownerUid+'). Sign in with that account, or start a fresh Firebase project for a new owner.');return true}
    // v2.67 secure bootstrap: a fresh Firebase project must be pre-authorized in the
    // Firestore console by creating meta/bootstrap with { ownerUid: '<OWNER_AUTH_UID>' }.
    // Clients cannot create/update that document under the included rules, removing the
    // old first-signed-in-user owner-claim race.
    let boot;try{boot=await db.collection('meta').doc('bootstrap').get()}catch(e){throw Error('Secure Owner bootstrap is not ready. Publish the v2.67 firestore.rules, then create meta/bootstrap in Firestore with ownerUid set to this Owner Auth UID ('+uid+').')}
    if(!boot.exists)throw Error('Secure Owner bootstrap required. In Firestore Console create document meta/bootstrap with field ownerUid = '+uid+', then retry “Initialize security”.');
    if(String(boot.data()?.ownerUid||'')!==String(uid))throw Error('The Firebase bootstrap document authorizes a different Owner UID. Expected '+uid+'. Update meta/bootstrap from the Firebase Console using the intended Owner account UID.');
    await sec.set({ownerUid:uid,createdAt:firebase.firestore.FieldValue.serverTimestamp()});return true;
  }
  async function secondary(cfg,label){const app=firebase.initializeApp(cfg,'pm227-'+label+'-'+Date.now()+'-'+Math.random().toString(36).slice(2));return {app,auth:app.auth(),db:app.firestore(),storage:firebase.storage?app.storage():null}}
  async function viewerSecondary271(cfg){
    let app=null;try{app=firebase.app(VIEWER_SESSION_APP)}catch(e){}
    if(app&&safe(app.options?.projectId)!==safe(cfg?.projectId)){try{await app.auth().signOut()}catch(e){}try{await app.delete()}catch(e){}app=null}
    if(!app)app=firebase.initializeApp(cfg,VIEWER_SESSION_APP);
    const auth=app.auth();try{await auth.setPersistence(firebase.auth.Auth.Persistence.LOCAL)}catch(e){}
    return {app,auth,db:app.firestore(),storage:firebase.storage?app.storage():null};
  }
  function readViewerSession271(){try{const x=JSON.parse(localStorage.getItem(VIEWER_SESSION_KEY)||'null');return x&&x.uid&&x.expiresAt?x:null}catch(e){return null}}
  function clearViewerSessionMarker271(){try{localStorage.removeItem(VIEWER_SESSION_KEY)}catch(e){}}
  function sessionExpiry271(payload){return Math.min(Date.now()+VIEWER_SESSION_MS,(+payload?.accessExpiresAt||Infinity))}
  function persistViewerSession271(cs){
    if(!cs||cs.uid==='offline')return;const expiresAt=sessionExpiry271(cs.payload);cs.sessionExpiresAt271=expiresAt;
    try{localStorage.setItem(VIEWER_SESSION_KEY,JSON.stringify({v:1,uid:cs.uid,loginName:cs.loginName||cs.payload?.user?.name||'',projectId:safe(cs.app?.options?.projectId||''),expiresAt,createdAt:Date.now()}))}catch(e){}
    scheduleViewerSessionExpiry271(cs);
  }
  function scheduleViewerSessionExpiry271(cs){
    clearTimeout(viewerSessionTimer271);if(!cs||!cs.sessionExpiresAt271)return;const ms=Math.max(0,cs.sessionExpiresAt271-Date.now());
    viewerSessionTimer271=setTimeout(()=>{if(cloudSession===cs)closeViewerSession46({reason:'For security, this login session expired after 6 hours. Please log in again.'})},Math.min(ms,2147483000));
  }
  function waitAuthReady271(auth,timeout=5000){return new Promise(resolve=>{let done=false,t=null,unsub=null;const finish=u=>{if(done)return;done=true;if(t)clearTimeout(t);try{unsub&&unsub()}catch(e){}resolve(u||null)};try{unsub=auth.onAuthStateChanged(finish,()=>finish(null));t=setTimeout(()=>finish(auth.currentUser),timeout)}catch(e){finish(auth.currentUser)}})}
  async function restoreViewerSession271(){
    if(cloudSession)return true;const marker=readViewerSession271();if(!marker)return false;
    let sec=null;try{
      const a=api();if(!a)return false;const cfg=await a.getSavedConfig();if(!cfg)return false;
      if(marker.projectId&&safe(marker.projectId)!==safe(cfg.projectId)){clearViewerSessionMarker271();return false}
      sec=await viewerSecondary271(cfg);
      if(+marker.expiresAt<=Date.now()){clearViewerSessionMarker271();try{await sec.auth.signOut()}catch(e){}return false}
      const user=await waitAuthReady271(sec.auth);if(!user||user.uid!==marker.uid){clearViewerSessionMarker271();try{if(user)await sec.auth.signOut()}catch(e){}return false}
      let pd=null,p=null,offline=false;
      try{
        const pr=await sec.db.collection('accessProfiles').doc(user.uid).get();pd=pr.exists?pr.data():null;
        if(!pd||pd.active!==true||profileExpired230(pd))throw Object.assign(Error(profileExpired230(pd)?'This login has expired.':'This login was disabled or removed.'),{__authoritative:true});
        p=await readPayload(sec.db,user.uid);if(!p)throw Object.assign(Error('No price data has been published for this login.'),{__authoritative:true});
        if(pd.accessVersion&&p.accessVersion&&pd.accessVersion!==p.accessVersion)throw Error('Published access is being updated.');
        if(p.accessExpiresAt&&+p.accessExpiresAt<=Date.now())throw Object.assign(Error('This login has expired.'),{__authoritative:true});
      }catch(e){
        if(authoritative(e))throw e;const c=cached(marker.loginName);
        if(!c||(+c.offlineValidUntil||0)<=Date.now()||(c.accessExpiresAt&&+c.accessExpiresAt<=Date.now()))throw e;p=c;offline=true;
      }
      cloudSession={uid:user.uid,loginName:(pd?.username||marker.loginName||p.user?.name||''),payload:p,app:sec.app,auth:sec.auth,db:sec.db,storage:sec.storage,unsubProfile:null,sessionExpiresAt271:+marker.expiresAt};
      window.__restrictedFirebaseSession46=true;show(p,offline);if(!offline)watchProfile46(cloudSession);else watchProfile46(cloudSession);scheduleViewerSessionExpiry271(cloudSession);return true;
    }catch(e){
      clearViewerSessionMarker271();try{if(sec?.auth)await sec.auth.signOut()}catch(_){}try{if(sec?.app)await sec.app.delete()}catch(_){}
      cloudSession=null;window.__restrictedFirebaseSession46=false;if(authoritative(e))toast(e.message||'This login is no longer available.');return false;
    }
  }
  window.restoreViewerSession271=restoreViewerSession271;
  function splitText(s){const a=[];for(let i=0;i<s.length;i+=PART_CHARS)a.push(s.slice(i,i+PART_CHARS));return a}

  async function deletePayload(db,uid,{bestEffort=false}={}){
    if(!uid)return true;
    try{
      const ref=db.collection('viewerPayloads').doc(uid),parts=await ref.collection('parts').get();
      await Promise.all(parts.docs.map(d=>d.ref.delete()));
      await ref.delete();
      return true;
    }catch(e){if(bestEffort)return false;throw e}
  }
  async function writePayload(db,uid,payload){
    const ref=db.collection('viewerPayloads').doc(uid),old=await ref.get(),oldIds=old.exists&&Array.isArray(old.data().partIds)?old.data().partIds:[];
    const raw=JSON.stringify(payload),parts=splitText(raw),version=Date.now().toString(36)+'_'+Math.random().toString(36).slice(2,7),ids=parts.map((_,i)=>`p_${version}_${String(i).padStart(4,'0')}`),written=[];
    try{for(let i=0;i<parts.length;i++){await ref.collection('parts').doc(ids[i]).set({schema:PAYLOAD_SCHEMA,version,index:i,data:parts[i]});written.push(ids[i])}await ref.set({schema:PAYLOAD_SCHEMA,version,partIds:ids,partCount:ids.length,updatedAt:payload.updatedAt,offlineValidUntil:payload.offlineValidUntil,accessVersion:payload.accessVersion})}
    catch(e){for(const id of written)ref.collection('parts').doc(id).delete().catch(()=>{});throw e}
    for(const id of oldIds)if(!ids.includes(id))ref.collection('parts').doc(id).delete().catch(()=>{});
  }
  async function readPayload(db,uid){
    const ref=db.collection('viewerPayloads').doc(uid),snap=await ref.get();if(!snap.exists)return null;const d=snap.data();
    if(d.schema===PAYLOAD_SCHEMA&&Array.isArray(d.partIds)){const docs=await Promise.all(d.partIds.map(id=>ref.collection('parts').doc(id).get()));if(docs.some(x=>!x.exists))throw Error('Published price data is incomplete. Ask the owner to publish again.');if(docs.some((x,i)=>x.data().version!==d.version||(+x.data().index||0)!==i))throw Error('Published price data parts do not match the active version. Ask the owner to publish again.');return JSON.parse(docs.map(x=>x.data().data||'').join(''))}
    return d; // legacy v2 payload
  }

  function sanitizeCfg(c){
    const allow=new Set(['code','name','size','packing','barcode','netWt','mrp','final']),idx=[],cols=[];
    (c.columns||[]).forEach((x,i)=>{if(allow.has(x.key)){idx.push(i);cols.push({...x})}});
    const groups=(c.groups||[]).map(g=>({name:g.name,rows:(g.rows||[]).map(r=>idx.map(i=>r[i]))}));
    return {columns:cols,groups,landscape:!!c.landscape,firm:c.firm||S.settings.firm||'Price List',meta:c.meta||'',title:c.title||'Price list',count:groups.reduce((z,g)=>z+g.rows.length,0),sub:c.sub||'',footer:c.footer||''};
  }
  function withBookConfig(cfg,fn){
    const keys=['catalog','cats','party','excluded','customerCols','exactDecimal30','hideNoPrice','onlyStock','includeOnDemand','includeComingSoon','landscape','title','targetUnit30','extraPct','overrides','qtyBasis26','changedOnly26','productUoms227','rateOnRequest230','brandingTemplateId230'];
    const saved={};keys.forEach(k=>saved[k]=clone(ui.list[k]));
    keys.forEach(k=>{if(k==='cats'||k==='excluded')ui.list[k]=[];else if(k==='customerCols')ui.list[k]={code:true,size:true,packing:true,mrp:true,barcode:false,netWt:false};else if(['overrides','productUoms227','rateOnRequest230'].includes(k))ui.list[k]={};else if(['hideNoPrice','onlyStock','includeOnDemand','includeComingSoon','landscape','changedOnly26'].includes(k))ui.list[k]=false;else ui.list[k]=''});
    Object.keys(cfg||{}).forEach(k=>ui.list[k]=clone(cfg[k]));
    try{return fn()}finally{keys.forEach(k=>{if(saved[k]===undefined)delete ui.list[k];else ui.list[k]=saved[k]})}
  }
  function nativePieces(p){try{const x=+window.piecesPerNativeUnit43(p);if(x>0)return x}catch(e){}if(['pc','piece'].includes(norm(p.priceUnit)))return 1;const r=(S.uomMaster||[]).find(x=>x.productId===p.id&&norm(x.unit)===norm(p.priceUnit));return r&&+r.pcsPerUnit>0?+r.pcsPerUnit:null}
  function rateForProduct(p){const L=ui.list||{},party=L.party||'',qty=+L.qtyBasis26||1,extra=+L.extraPct||0,ov=L.overrides&&Object.prototype.hasOwnProperty.call(L.overrides,p.id)?+L.overrides[p.id]:null;try{const x=window.PriceManagerAPI?.pricing26?.(p,party,qty,extra,null,ov);if(x&&x.final!=null)return +x.final}catch(e){}try{return +priceOf(p,profileFor(party,extra)).net}catch(e){return p.price==null?null:+p.price}}
  function uomRatesFor(p,nativeRate){
    if(nativeRate==null||isNaN(nativeRate))return[];const out=[],seen=new Set(),add=(u,r)=>{u=safe(u||'Unit').trim()||'Unit';const k=norm(u);if(!k||seen.has(k)||r==null||isNaN(r))return;seen.add(k);out.push({u,r:round2(r)})};
    const native=safe(p.priceUnit||'Unit').trim()||'Unit';add(native,nativeRate);const pcs=nativePieces(p);if(pcs&&pcs>0){const perPc=nativeRate/pcs;add('Pc',perPc);(S.uomMaster||[]).filter(x=>x.productId===p.id&&+x.pcsPerUnit>0).forEach(x=>add(x.unit,perPc*(+x.pcsPerUnit)))}return out;
  }
  function structuredBook(pb,cfg){return withBookConfig(cfg||pb?.config||{},()=>{const products=typeof listItems==='function'?listItems():[],defaults=(cfg||pb?.config||{}).productUoms227||{},ror=(cfg||pb?.config||{}).rateOnRequest230||{};return products.map(p=>{const onRequest=!!ror[p.id],native=onRequest?null:rateForProduct(p),rates=onRequest?[]:uomRatesFor(p,native),wanted=defaults[p.id]||p.priceListUnit||p.priceUnit||'Unit',def=rates.find(x=>norm(x.u)===norm(wanted))||rates[0]||null;return{id:p.id||'',code:p.code||'',name:p.name||'',size:p.size||'',category:p.category||'',packing:p.packing||'',barcode:p.barcode||'',mrp:p.mrp??null,keywords:safe(p.keywords||p.tags||''),rateOnRequest:onRequest,defaultUom:def?def.u:wanted,uomRates:rates}})})}
  function cfgForBook(cfg){return withBookConfig(cfg||{},()=>sanitizeCfg(listConfig()))}
  function changeSet(oldItems,newItems){const a=new Map((oldItems||[]).map(x=>[x.id||x.code,x])),b=new Map((newItems||[]).map(x=>[x.id||x.code,x]));const details=[];let changed=0,increased=0,decreased=0,added=0,removed=0;const primary=x=>x.rateOnRequest?null:((x.uomRates||[]).find(r=>norm(r.u)===norm(x.defaultUom))||(x.uomRates||[])[0]||{}).r;for(const [k,n] of b){const o=a.get(k);if(!o){added++;details.push({code:n.code,name:n.name,type:'New product',oldRate:null,newRate:primary(n),onRequest:n.rateOnRequest,uom:n.defaultUom});continue}const or=primary(o),nr=primary(n),different=!!o.rateOnRequest!==!!n.rateOnRequest||Math.abs((+or||0)-(+nr||0))>.009||norm(o.defaultUom)!==norm(n.defaultUom);if(different){changed++;if(or!=null&&nr!=null&&nr>or)increased++;if(or!=null&&nr!=null&&nr<or)decreased++;details.push({code:n.code,name:n.name,type:'Rate changed',oldRate:or,newRate:nr,oldOnRequest:o.rateOnRequest,onRequest:n.rateOnRequest,oldUom:o.defaultUom,uom:n.defaultUom})}}for(const [k,o] of a)if(!b.has(k)){removed++;details.push({code:o.code,name:o.name,type:'Removed',oldRate:primary(o),newRate:null,oldUom:o.defaultUom})}return{changed,increased,decreased,added,removed,details:details.slice(0,250)}}
  function audience230(b){const explicit=norm(b?.audience270||b?.audience||'');if(['retail','wholesale','custom'].includes(explicit))return explicit;const t=norm([b?.name,b?.category].filter(Boolean).join(' '));if(/wholesale|whole\s*sale|distributor|dealer|stockist|trade|bulk/.test(t))return'wholesale';if(/retail|consumer|counter|mrp/.test(t))return'retail';return'custom'}
  function audienceLabel230(b){const a=audience230(b);return a==='wholesale'?'Wholesale / Trade':a==='retail'?'Retail':'Custom'}
  function brandFor(cfg){const id=cfg?.brandingTemplateId230||'default',b=(S.pdfBrandTemplates230||[]).find(x=>x.id===id)||(S.pdfBrandTemplates230||[])[0];return b?{name:b.name||'',firm:b.firm||'',subtitle:b.subtitle||'',contact:b.contact||'',footer:b.footer||'',showEffective:b.showEffective!==false}:null}
  function bookPayload(pb){const currentCfg=pb.config||{},items=structuredBook(pb,currentCfg),prevItems=pb.previousConfig230?structuredBook(pb,pb.previousConfig230):[],base={id:pb.id,name:pb.name,category:pb.category||'Other',audience:audience230(pb),version:+pb.version230||1,effectiveFrom:pb.effectiveFrom230||'',cfg:cfgForBook(currentCfg),branding:brandFor(currentCfg),items,changes:changeSet(prevItems,items)};if(pb.scheduled230){const sc=pb.scheduled230.config||{},si=structuredBook(pb,sc);base.scheduled={effectiveDate:pb.scheduled230.effectiveDate,note:pb.scheduled230.note||'',cfg:cfgForBook(sc),branding:brandFor(sc),items:si,changes:changeSet(items,si)}}return base}
  function expiryMs(u){if(!u?.accessExpiresOn)return 0;const x=new Date(u.accessExpiresOn+'T23:59:59.999').getTime();return Number.isFinite(x)?x:0}
  function payloadFor(u){
    const now=Date.now(),accessVersion=String(now)+'_'+Math.random().toString(36).slice(2,7),expires=expiryMs(u);
    const books=(u.allowedPriceBookIds||[]).map(id=>S.priceBooks.find(x=>x.id===id)).filter(Boolean).map(bookPayload);
    const catalogs=(u.allowedCatalogFileIds||[]).map(id=>S.catalogFiles.find(x=>x.id===id)).filter(Boolean).map(c=>({id:c.id,title:c.title,name:c.title,category:c.category||'Other',filename:c.filename||'catalog.pdf',storagePath:c.storagePath||'',size:c.size||0,uploadedAt:c.uploadedAt||0}));
    const rn=u.rateNotice||{},an=u.announcement||{};const notice={enabled:rn.enabled===true,effectiveDate:safe(rn.effectiveDate||''),text:safe(rn.text||'')},announcement={enabled:an.enabled===true,title:safe(an.title||''),text:safe(an.text||''),from:safe(an.from||''),until:safe(an.until||'')};
    return {schema:PAYLOAD_SCHEMA,version:6,firm:S.settings.firm||'Price & Stock Manager',currency:S.settings.currency||'₹',user:{name:u.name,role:u.role||'customer'},priceBooks:books,catalogs,notice,announcement,accessExpiresAt:expires,updatedAt:now,offlineValidUntil:Math.min(now+OFFLINE_TTL,expires||Infinity),accessVersion};
  }

  async function establishRestrictedAccount(cfg,u){
    const email=await loginEmailV2(u.name,u.pin,cfg.projectId),legacyEmail=await loginEmail(u.name,cfg.projectId),pw=await loginPassword(u.name,u.pin,cfg.projectId);let sec=null,uid='';
    try{
      sec=await secondary(cfg,u.id||'user');
      const candidates=[],seen=new Set(),add=(em,pass)=>{if(!em||!pass||seen.has(em+'|'+pass))return;seen.add(em+'|'+pass);candidates.push([em,pass])};
      // First try the exact credentials previously stored for this local user.
      if(u.cloudEmail&&u.cloudNameSnapshot&&u.cloudPinSnapshot)add(u.cloudEmail,await loginPassword(u.cloudNameSnapshot,u.cloudPinSnapshot,cfg.projectId));
      if(u.cloudNameSnapshot&&u.cloudPinSnapshot){
        add(await loginEmailV2(u.cloudNameSnapshot,u.cloudPinSnapshot,cfg.projectId),await loginPassword(u.cloudNameSnapshot,u.cloudPinSnapshot,cfg.projectId));
        add(await loginEmail(u.cloudNameSnapshot,cfg.projectId),await loginPassword(u.cloudNameSnapshot,u.cloudPinSnapshot,cfg.projectId));
      }
      // Then current v2 + legacy identities.
      add(email,pw);add(legacyEmail,pw);
      let cred=null,lastAuthErr=null;
      for(const [em,pass] of candidates){try{cred=await sec.auth.signInWithEmailAndPassword(em,pass);break}catch(e){lastAuthErr=e}}
      if(cred){
        uid=cred.user.uid;
        // Migrate a successfully recovered legacy/stale account to the v2 pin-bound address.
        if(cred.user.email!==email){try{await cred.user.updateEmail(email)}catch(e){if(e.code!=='auth/email-already-in-use')throw e}}
        try{await cred.user.updatePassword(pw)}catch(e){if(e.code==='auth/requires-recent-login')throw e}
      }else{
        try{cred=await sec.auth.createUserWithEmailAndPassword(email,pw);uid=cred.user.uid}
        catch(e){
          if(e.code==='auth/email-already-in-use'){
            try{cred=await sec.auth.signInWithEmailAndPassword(email,pw);uid=cred.user.uid}
            catch(signErr){throw signErr}
          }else throw e
        }
      }
      return {uid,email:(cred&&cred.user&&cred.user.email)||email,sec};
    }catch(e){if(sec){try{await sec.auth.signOut()}catch(_){ }try{await sec.app.delete()}catch(_){ }}throw e}
  }
  function stablePayloadForHash265(payload){const x=clone(payload)||{};delete x.updatedAt;delete x.offlineValidUntil;delete x.accessVersion;return x}
  function fastHash265(raw){let h1=0x811c9dc5,h2=0x9e3779b9;for(let i=0;i<raw.length;i++){const c=raw.charCodeAt(i);h1=Math.imul(h1^c,0x01000193);h2=Math.imul(h2+c,0x85ebca6b)^(h2>>>13)}return raw.length+':'+(h1>>>0).toString(36)+':'+(h2>>>0).toString(36)}
  function payloadHash265(u,payload){return PUBLISH_REV+':'+fastHash265(JSON.stringify(stablePayloadForHash265(payload||payloadFor(u))))}
  function credentialsNeedProvision265(u){
    if(!u.cloudUid)return true;
    if(u.credentialPending265)return true;
    if(u.cloudNameSnapshot&&norm(u.cloudNameSnapshot)!==norm(u.name))return true;
    if(u.cloudPinSnapshot&&u.pin&&String(u.cloudPinSnapshot)!==String(u.pin))return true;
    return false;
  }
  async function syncOneNow(id){
    const u=S.viewerUsers.find(x=>x.id===id);if(!u)throw Error('User not found');
    const {cfg,auth,db}=await ready();if(!auth.currentUser)throw Error('Owner must sign in to Firebase first in Settings.');const owner=auth.currentUser.uid;await ensureOwner(db,owner);
    const oldUid=u.cloudUid||'';let uid=oldUid,email=u.cloudEmail||'',sec=null;
    const needsCred=credentialsNeedProvision265(u);
    if(needsCred){
      if(String(u.pin||'').length<6)throw Error('Enter a new 6+ character PIN for this user, then retry cloud provisioning. Existing cloud PINs are not stored in plaintext anymore.');
      const acct=await establishRestrictedAccount(cfg,u);uid=acct.uid;email=acct.email;sec=acct.sec;
    }
    try{
      if(oldUid&&oldUid!==uid){const oldProfile=db.collection('accessProfiles').doc(oldUid);await oldProfile.set({active:false,revokedAt:firebase.firestore.FieldValue.serverTimestamp()},{merge:true});await deletePayload(db,oldUid);await oldProfile.delete()}
      const payload=payloadFor(u),active=u.active!==false,profile={ownerUid:owner,username:u.name,usernameKey:norm(u.name),role:u.role||'customer',active,accessVersion:payload.accessVersion,offlineValidUntil:payload.offlineValidUntil,expiresAt:payload.accessExpiresAt?firebase.firestore.Timestamp.fromMillis(payload.accessExpiresAt):null,allowedPriceBookIds:u.allowedPriceBookIds||[],allowedCatalogFileIds:u.allowedCatalogFileIds||[],updatedAt:firebase.firestore.FieldValue.serverTimestamp()};
      if(active){await writePayload(db,uid,payload);await db.collection('accessProfiles').doc(uid).set(profile,{merge:true})}
      else{await db.collection('accessProfiles').doc(uid).set(profile,{merge:true});await deletePayload(db,uid)}
      Object.assign(u,{cloudUid:uid,cloudEmail:email,cloudNameSnapshot:u.name,cloudSyncedAt:Date.now(),cloudAccessVersion:payload.accessVersion,cloudPayloadHash265:payloadHash265(u,payload),cloudSyncState:'ready',cloudSyncError:'',cloudSyncAttemptAt:Date.now(),cloudNextRetryAt:0,credentialPending265:false,pin:'',cloudPinSnapshot:''});
      publishSuppress=true;try{save()}finally{publishSuppress=false}return u;
    }finally{if(sec){try{await sec.auth.signOut()}catch(e){}try{await sec.app.delete()}catch(e){}}}
  }
  function persistCloudStatus(){publishSuppress=true;try{saveBeforeSecure()}finally{publishSuppress=false}}
  function syncOne(id,{force=false}={}){
    const existing=S.viewerUsers.find(x=>x.id===id);
    if(!force&&existing?.cloudSyncState==='error'&&(+existing.cloudNextRetryAt||0)>Date.now()){
      const er=Error(existing.cloudSyncError||'Cloud retry is waiting for its retry window.');er.code='pm/retry-backoff';return Promise.reject(er)
    }
    const run=async()=>{
      const u=S.viewerUsers.find(x=>x.id===id);if(u){u.cloudSyncState='syncing';u.cloudSyncError='';u.cloudSyncAttemptAt=Date.now();persistCloudStatus()}
      try{return await syncOneNow(id)}catch(e){
        const row=S.viewerUsers.find(x=>x.id===id);if(row){const code=safe(e&&e.code);const delay=code==='auth/too-many-requests'?15*60*1000:code==='auth/network-request-failed'?60*1000:5*60*1000;row.cloudSyncState='error';row.cloudSyncError=cloudErrorMessage(e);row.cloudSyncAttemptAt=Date.now();row.cloudNextRetryAt=Date.now()+delay;persistCloudStatus()}
        throw e
      }
    };
    restrictedSyncQueue=restrictedSyncQueue.then(run,run);return restrictedSyncQueue
  }
  async function revokeUser(u,{deleteAuth=true}={}){
    if(!u)return true;const oldName=u.cloudNameSnapshot||u.name;
    try{
      if(u.cloudUid){
        const {cfg,auth,db}=await ready();
        if(!auth.currentUser)throw Error('Owner must be signed in to Firebase before this cloud login can be removed safely.');
        await ensureOwner(db,auth.currentUser.uid);
        const pref=db.collection('accessProfiles').doc(u.cloudUid);
        await pref.set({active:false,revokedAt:firebase.firestore.FieldValue.serverTimestamp()},{merge:true});
        await deletePayload(db,u.cloudUid);
        await pref.delete();
        if(deleteAuth){let sec=null;try{sec=await secondary(cfg,'revoke');const names=[[u.cloudNameSnapshot||u.name,u.cloudPinSnapshot||u.pin],[u.name,u.pin]],creds=[],seen=new Set(),add=(em,pw)=>{if(em&&!seen.has(em+'|'+pw)){seen.add(em+'|'+pw);creds.push([em,pw])}};for(const [nm,pn] of names){if(!nm||String(pn||'').length<6)continue;const pw=await loginPassword(nm,pn,cfg.projectId);if(u.cloudEmail&&nm===(u.cloudNameSnapshot||u.name))add(u.cloudEmail,pw);add(await loginEmailV2(nm,pn,cfg.projectId),pw);add(await loginEmail(nm,cfg.projectId),pw)}let cred=null;for(const [em,pw] of creds){try{cred=await sec.auth.signInWithEmailAndPassword(em,pw);break}catch(e){}}if(cred)await cred.user.delete()}catch(e){}finally{if(sec){try{await sec.auth.signOut()}catch(_){}try{await sec.app.delete()}catch(_){}}}}
      }
      try{localStorage.removeItem(CACHE_PREFIX+norm(u.name));localStorage.removeItem(CACHE_PREFIX+norm(oldName))}catch(e){}
      return true;
    }catch(e){throw Error('Cloud access could not be revoked, so the local user was kept. '+(e.message||''))}
  }
  window.revokeViewerUser46=async id=>{const u=S.viewerUsers.find(x=>x.id===id);if(!u)return false;await revokeUser(u);return true};
  window.syncOneUser46=async(id,opts={})=>{
    try{const u=await syncOne(id,{force:true});if(!opts.silentSuccess)toast('Firebase access updated for '+u.name);render();return true}
    catch(e){const msg=cloudErrorMessage(e);toast('Cloud login failed: '+msg);render();if(opts.throwOnError)throw e;return false}
  };
  function updateProvisionProgress265(){
    const st=window.cloudProvisionStatus265,el=document.getElementById('cloudProgress265');if(!el||!st)return;
    el.innerHTML=st.running?`<div class="a265-progress"><div><b>Cloud provisioning ${st.done+st.failed} / ${st.total}</b><span>${esc(st.current||'Preparing…')}</span></div><progress max="${Math.max(1,st.total)}" value="${st.done+st.failed}"></progress></div>`:`<div class="note">Last cloud run: ${st.done} updated${st.failed?` · <span class="bad">${st.failed} failed</span>`:''}</div>`;
  }
  window.syncAllUsers46=async(opts={})=>{
    if(!(S.viewerUsers||[]).length){toast('Create a restricted user first');return false}
    const onlyPending=!!opts.onlyPending;
    const candidates=(S.viewerUsers||[]).filter(u=>u.active!==false||u.cloudUid).filter(u=>!onlyPending||!u.cloudUid||u.cloudSyncState==='pending'||u.cloudSyncState==='error'||u.credentialPending265);
    if(!candidates.length){toast(onlyPending?'No pending/failed cloud logins':'No cloud users to publish');return true}
    const failures=[],done=[];window.cloudProvisionStatus265={running:true,total:candidates.length,done:0,failed:0,current:'Starting…',results:[],startedAt:Date.now()};updateProvisionProgress265();
    for(const u of candidates){window.cloudProvisionStatus265.current=u.name;updateProvisionProgress265();try{await syncOne(u.id,{force:true});done.push(u.name);window.cloudProvisionStatus265.done++}catch(e){const er=cloudErrorMessage(e);failures.push({name:u.name,error:er});window.cloudProvisionStatus265.failed++;window.cloudProvisionStatus265.results.push({name:u.name,error:er})}updateProvisionProgress265()}
    window.cloudProvisionStatus265.running=false;window.cloudProvisionStatus265.current='';updateProvisionProgress265();render();
    if(failures.length){toast(`${done.length} cloud login(s) updated; ${failures.length} failed. Failed users can be retried individually.`);if(opts.throwOnError)throw Error(failures.map(x=>x.name+': '+x.error).join(' | '));return false}
    toast('Published '+done.length+' restricted cloud login(s) securely');return true
  };
  window.initSecureAccess46=async()=>{try{const {auth,db}=await ready();if(!auth.currentUser)return toast('Sign in as owner in Firebase Settings first');await ensureOwner(db,auth.currentUser.uid);toast('Secure access initialized for this owner');render()}catch(e){toast(e.message)}};

  function cache(name,p){try{localStorage.setItem(CACHE_PREFIX+norm(name),JSON.stringify(p))}catch(e){}}
  function cached(name){try{return JSON.parse(localStorage.getItem(CACHE_PREFIX+norm(name))||'null')}catch(e){return null}}
  function bookPdf(b){try{buildPDF(b.cfg).save((b.name||'price-list').replace(/[^\w\- ]+/g,'')+'.pdf')}catch(e){toast('Could not create PDF')}}
  async function bookShare(b){try{const d=buildPDF(b.cfg),blob=d.output('blob'),file=new File([blob],(b.name||'price-list')+'.pdf',{type:'application/pdf'});if(navigator.share&&(!navigator.canShare||navigator.canShare({files:[file]})))return navigator.share({title:b.name,text:b.name,files:[file]});bookPdf(b)}catch(e){if(e&&e.name==='AbortError')return;bookPdf(b)}}
  function catalogCacheKey(c){return new Request(location.origin+location.pathname+'?pmCatalog='+encodeURIComponent(c.id))}
  async function catalogDownloadUrl(c){
    if(!cloudSession||!cloudSession.storage)throw Error('Catalog is not cached on this device. Connect to internet once and open it.');
    return await cloudSession.storage.ref(c.storagePath).getDownloadURL();
  }
  async function catalogBlob(c){
    const cc=typeof caches!=='undefined'?await caches.open('pm-viewer-catalogs-v228'):null,key=catalogCacheKey(c);if(cc){const hit=await cc.match(key);if(hit)return hit.blob()}
    const url=await catalogDownloadUrl(c),r=await fetch(url);if(!r.ok)throw Error('Catalog download failed');const blob=await r.blob();if(cc)await cc.put(key,new Response(blob,{headers:{'Content-Type':'application/pdf'}}));return blob;
  }
  async function viewCatalog(c){
    let w=window.open('about:blank','_blank');
    try{
      const blob=await catalogBlob(c),url=URL.createObjectURL(blob);
      if(w)w.location=url;else window.location.href=url;
      setTimeout(()=>URL.revokeObjectURL(url),60000)
    }catch(e){
      // Caching fetch can fail (e.g. the Storage bucket's default CORS setup blocks browser fetch() of the
      // file, even though the app itself is authorised). A plain top-level navigation to the same signed URL
      // is not subject to that restriction, so fall back to it -- this always works if the file exists.
      try{
        const url=await catalogDownloadUrl(c);
        if(w)w.location=url;else window.location.href=url;
      }catch(e2){
        if(w)w.close();
        toast(e2.message||e.message||'Could not open catalog')
      }
    }
  }
  async function downloadCatalog(c){
    try{
      const blob=await catalogBlob(c),url=URL.createObjectURL(blob),a=document.createElement('a');
      a.href=url;a.download=c.filename||((c.title||'catalog')+'.pdf');
      document.body.appendChild(a);a.click();a.remove();
      setTimeout(()=>URL.revokeObjectURL(url),3000)
    }catch(e){
      try{
        const url=await catalogDownloadUrl(c),a=document.createElement('a');
        a.href=url;a.download=c.filename||((c.title||'catalog')+'.pdf');a.target='_blank';a.rel='noopener';
        document.body.appendChild(a);a.click();a.remove();
        toast("Opening the catalog — use your browser's save/download option if it does not save automatically.")
      }catch(e2){
        toast(e2.message||e.message||'Could not download catalog')
      }
    }
  }

  function activeBook230(b){if(!b)return b;const sc=b.scheduled,at=sc?.effectiveDate?new Date(sc.effectiveDate+'T00:00:00').getTime():0;if(sc&&at&&at<=Date.now())return {...b,cfg:sc.cfg,branding:sc.branding||b.branding,items:sc.items||[],changes:sc.changes||{},effectiveFrom:sc.effectiveDate,scheduledActivated:true};return b}
  function activeBooks230(p){return (p.priceBooks||[]).map(activeBook230)}
  function viewerCss(){if(document.getElementById('cv47css'))return;const st=document.createElement('style');st.id='cv47css';st.textContent=`#cloudViewer46 .cv47-wrap{max-width:960px;margin:auto;padding:20px 14px 40px}.cv47-head{display:flex;justify-content:space-between;gap:12px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:15px}.cv47-search{position:sticky;top:0;z-index:2;background:#f6f2e9;padding:8px 0 12px}.cv47-searchbox{display:grid;grid-template-columns:minmax(0,1fr) 190px 170px;gap:8px}.cv47-results{display:grid;gap:8px;margin-top:10px}.cv47-rate{font-size:18px;font-weight:800;white-space:nowrap}.cv47-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center}.cv47-uom{min-width:105px}.cv47-booktag{font-size:10px;text-transform:uppercase;color:var(--muted);font-weight:700}.cv47-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.cv47-catgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}.cv47-notice{border:1px solid #d9b65c;background:#fff8dc;border-radius:14px;padding:13px 14px;margin:0 0 14px}.cv47-announce{border:1px solid #b9c7df;background:#f3f7ff;border-radius:14px;padding:13px 14px;margin:0 0 14px}.cv47-notice b,.cv47-announce b{display:block;font-size:14px;margin-bottom:2px}.cv47-switch{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:0 0 14px}.cv47-switch .card{margin:0}.cv47-switch select{width:100%;margin-top:6px}.cv47-empty{padding:16px;text-align:center;color:var(--muted);font-size:12.5px}.cv47-star{border:0;background:transparent;font-size:19px;cursor:pointer;padding:2px 5px}.cv47-tools{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.cv47-change{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:8px;padding:8px;border-bottom:1px solid var(--line)}@media(max-width:700px){.cv47-switch{grid-template-columns:1fr}.cv47-searchbox{grid-template-columns:1fr}.cv47-row{grid-template-columns:1fr}.cv47-rate{font-size:17px}.cv47-head{align-items:flex-start}.cv47-change{grid-template-columns:1fr auto}}`;document.head.appendChild(st)}
  function prefsKey230(p){return 'pm-viewer-prefs-v230:'+norm(p.user?.name||'user')}
  function prefs230(p){try{return {...{favorites:[],recentProducts:[],recentQueries:[]},...JSON.parse(localStorage.getItem(prefsKey230(p))||'{}')}}catch(e){return{favorites:[],recentProducts:[],recentQueries:[]}}}
  function savePrefs230(p,x){try{localStorage.setItem(prefsKey230(p),JSON.stringify(x))}catch(e){}}
  function productKey230(b,it){return b.id+'|'+(it.id||it.code)}
  function activeAnnouncement230(a){if(!a?.enabled||!a.text)return false;const d=new Date(),now=`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;return(!a.from||a.from<=now)&&(!a.until||a.until>=now)}
  function searchRows(p,q,bookId,category,mode){const pr=prefs230(p),tokens=norm(q).replace(/[^a-z0-9]+/g,' ').split(/\s+/).filter(Boolean),out=[];activeBooks230(p).filter(b=>!bookId||b.id===bookId).forEach(b=>(b.items||[]).forEach(it=>{if(category&&norm(it.category)!==norm(category))return;const key=productKey230(b,it);if(mode==='favorites'&&!pr.favorites.includes(key))return;if(mode==='recent'&&!pr.recentProducts.includes(key))return;const hay=norm([it.code,it.name,it.size,it.category,it.barcode,it.packing,it.keywords,b.name,(it.uomRates||[]).map(x=>x.u).join(' ')].join(' ')).replace(/[^a-z0-9]+/g,' ');if(tokens.length&&tokens.some(t=>!hay.includes(t)))return;out.push({b,it,key})}));if(mode==='recent')out.sort((a,b)=>pr.recentProducts.indexOf(a.key)-pr.recentProducts.indexOf(b.key));return out.slice(0,100)}
  function selectedRate(it,u,payload){if(it.rateOnRequest)return 'Rate on request';const x=(it.uomRates||[]).find(r=>norm(r.u)===norm(u))||(it.uomRates||[])[0];const cur=payload?.currency||'₹';return x?(cur+Number(x.r).toLocaleString('en-IN',{maximumFractionDigits:2})+'/'+x.u):'—'}
  function rememberResults230(p,rows,q){if(!rows.length)return;const pr=prefs230(p);for(const r of rows.slice(0,8)){pr.recentProducts=[r.key,...pr.recentProducts.filter(x=>x!==r.key)].slice(0,30)}if(q.trim().length>1)pr.recentQueries=[q.trim(),...pr.recentQueries.filter(x=>norm(x)!==norm(q))].slice(0,12);savePrefs230(p,pr)}
  function renderResults(root,p,mode='search'){
    const q=root.querySelector('#cv47q')?.value||'',bookId=root.querySelector('#cv47book')?.value||'',category=root.querySelector('#cv47catfilter')?.value||'',box=root.querySelector('#cv47results');if(!box)return;
    const books=activeBooks230(p),sales=p.user?.role==='sales';
    if(sales&&books.length>1&&!bookId){box.innerHTML=`<div class="cv270-context-empty"><b>Select a rate context before showing any rate</b>Choose the correct Retail / Wholesale / customer price list above. Search results stay hidden until a price list is selected, preventing accidental quotation of the wrong rate.</div>`;return}
    if(mode==='search'&&!q.trim()){const pr=prefs230(p);const chips=pr.recentQueries.map(x=>`<button class="btn ghost sm" data-q230="${esc(x)}">${esc(x)}</button>`).join('');box.innerHTML=`<div class="cv47-empty"><div style="font-size:26px;margin-bottom:6px">🔍</div>${sales?'Search inside the selected rate context':'Search by product, code, barcode, category, size, packing or UOM.'}${chips?'<div class="cv47-tools" style="justify-content:center">'+chips+'</div>':''}</div>`;box.querySelectorAll('[data-q230]').forEach(b=>b.onclick=()=>{root.querySelector('#cv47q').value=b.dataset.q230;renderResults(root,p)});return}
    const rows=searchRows(p,q,bookId,category,mode);if(mode==='search')rememberResults230(p,rows,q);const pr=prefs230(p);
    box.innerHTML=rows.length?rows.map((r,i)=>{const aud=audience230(r.b),label=audienceLabel230(r.b),wh=sales&&aud==='wholesale';return `<div class="card"><div class="bd cv47-row"><div><div class="cv270-bookmeta"><span class="cv270-aud ${aud}">${esc(label)}</span><span class="cv47-booktag">${esc(r.b.name)} · ${esc(r.it.category||'')}</span></div><b>${esc(r.it.code)} · ${esc(r.it.name)}</b><button class="cv47-star" data-star230="${i}" title="Favorite">${pr.favorites.includes(r.key)?'★':'☆'}</button><div class="note">${esc(r.it.size||'')}${r.it.packing?' · '+esc(r.it.packing):''}${r.it.mrp!=null?' · MRP '+(p.currency||'₹')+Number(r.it.mrp).toLocaleString('en-IN',{maximumFractionDigits:2}):''}</div>${wh?'<div class="cv270-wholesale-note">Wholesale / trade rate — verify the buyer before quoting.</div>':''}${window.orderRowExtra233?window.orderRowExtra233(r,i):''}</div><div style="text-align:right"><div class="cv47-rate cv270-rate-${aud}" data-rate47="${i}">${selectedRate(r.it,r.it.defaultUom,p)}</div>${!r.it.rateOnRequest&&(r.it.uomRates||[]).length>1?`<select class="cv47-uom" data-uom47="${i}">${r.it.uomRates.map(x=>`<option value="${esc(x.u)}" ${norm(x.u)===norm(r.it.defaultUom)?'selected':''}>${esc(x.u)}</option>`).join('')}</select>`:`<div class="metric-sub">${r.it.rateOnRequest?'Contact owner / sales team':esc(r.it.defaultUom||'')}</div>`}</div></div></div>`}).join(''):'<div class="cv47-empty"><div style="font-size:26px;margin-bottom:6px">📭</div>No matching product in the selected price list.<div class="note" style="margin-top:4px">Try a shorter search term, or check the category filter above.</div></div>';
    box.querySelectorAll('[data-uom47]').forEach(sel=>sel.onchange=()=>{const i=+sel.dataset.uom47,row=rows[i],rate=box.querySelector(`[data-rate47="${i}"]`);if(row&&rate)rate.textContent=selectedRate(row.it,sel.value,p)});
    box.querySelectorAll('[data-star230]').forEach(st=>st.onclick=()=>{const r=rows[+st.dataset.star230],x=prefs230(p);x.favorites=x.favorites.includes(r.key)?x.favorites.filter(k=>k!==r.key):[r.key,...x.favorites];savePrefs230(p,x);renderResults(root,p,mode)});if(window.wireOrderRows233)window.wireOrderRows233(box,rows,p)
  }
  function noticeDate47(v){if(!v)return'';try{const d=new Date(v+'T00:00:00');if(!isNaN(d))return d.toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'})}catch(e){}return safe(v)}
  function viewerBookCfg230(book,p){const b=activeBook230(book),cur=p?.currency||'₹',groups=[],gm=new Map();for(const it of b.items||[]){const cat=it.category||'Other';if(!gm.has(cat)){const g={name:cat,rows:[]};gm.set(cat,g);groups.push(g)}const rr=(it.uomRates||[]).find(x=>norm(x.u)===norm(it.defaultUom))||(it.uomRates||[])[0],rate=it.rateOnRequest?'Rate on request':rr?cur+Number(rr.r).toLocaleString('en-IN',{maximumFractionDigits:2})+'/'+rr.u:'—';gm.get(cat).rows.push([it.code||'',it.name||'',it.size||'',it.packing||'',it.mrp==null?'—':cur+Number(it.mrp).toLocaleString('en-IN',{maximumFractionDigits:2}),rate])}const br=b.branding||{},effective=b.effectiveFrom?`Effective ${noticeDate47(b.effectiveFrom)}`:'';return{columns:[{key:'code',label:'Code',w:1},{key:'name',label:'Product',w:3.4},{key:'size',label:'Size',w:1},{key:'packing',label:'Packing',w:1.5},{key:'mrp',label:'MRP',align:'right',w:1},{key:'final',label:'Rate',align:'right',w:1.4,bold:true}],groups,landscape:true,firm:br.firm||p.firm||'Price List',meta:[br.subtitle,br.contact].filter(Boolean).join('  ·  '),title:b.name,count:(b.items||[]).length,sub:[effective,b.category].filter(Boolean).join('  ·  '),footer:br.footer||''}}
  function bookPdf(b){try{const p=cloudSession?.payload||{},a=activeBook230(b),doc=buildPDF(viewerBookCfg230(a,p));doc.save((a.name||'price-list').replace(/[^\w\- ]+/g,'')+'.pdf')}catch(e){toast('Could not create PDF')}}
  async function bookShare(b){try{const p=cloudSession?.payload||{},a=activeBook230(b),d=buildPDF(viewerBookCfg230(a,p)),blob=d.output('blob'),file=new File([blob],(a.name||'price-list')+'.pdf',{type:'application/pdf'});if(navigator.share&&(!navigator.canShare||navigator.canShare({files:[file]})))return navigator.share({title:a.name,text:a.name,files:[file]});d.save(file.name)}catch(e){if(e&&e.name==='AbortError')return;bookPdf(b)}}
  function changesDialog230(b,p){const a=activeBook230(b),c=a.changes||{},m=document.createElement('div');m.className='modal';m.style.zIndex='220000';m.innerHTML=`<div class="box" style="max-width:760px"><div class="hd"><div><h2 style="margin:0">What changed? · ${esc(a.name)}</h2><div class="note">${c.changed||0} changed · ${c.increased||0} increased · ${c.decreased||0} decreased · ${c.added||0} new · ${c.removed||0} removed</div></div></div><div class="bd"><div class="tbl-wrap" style="max-height:480px"><table><thead><tr><th>Product</th><th>Change</th><th class="r">Old</th><th class="r">New</th></tr></thead><tbody>${(c.details||[]).map(x=>`<tr><td><b>${esc(x.code||'')}</b> · ${esc(x.name||'')}</td><td>${esc(x.type||'Changed')}</td><td class="r">${x.oldOnRequest?'On request':x.oldRate==null?'—':(p.currency||'₹')+Number(x.oldRate).toLocaleString('en-IN',{maximumFractionDigits:2})}</td><td class="r">${x.onRequest?'On request':x.newRate==null?'—':(p.currency||'₹')+Number(x.newRate).toLocaleString('en-IN',{maximumFractionDigits:2})}</td></tr>`).join('')||'<tr><td colspan="4" class="empty-mini">No recorded changes.</td></tr>'}</tbody></table></div></div><div class="ft"><button class="btn primary" data-x="close">Close</button></div></div>`;document.body.appendChild(m);m.onclick=e=>{if(e.target.closest('[data-x="close"]')||e.target===m)m.remove()}}
  function show(p,off=false){
    viewerCss();let e=document.getElementById('cloudViewer46');if(!e){e=document.createElement('div');e.id='cloudViewer46';e.style.cssText='position:fixed;inset:0;z-index:200000;background:#f6f2e9;overflow:auto';document.body.appendChild(e)}e.style.display='block';
    const books=activeBooks230(p),sales=p.user?.role==='sales',mustChoose=sales&&books.length>1,gs={};books.forEach(b=>(gs[b.category||'Other']=gs[b.category||'Other']||[]).push(b));
    const exp=p.offlineValidUntil?new Date(p.offlineValidUntil).toLocaleString('en-IN'):'',rn=p.notice||{},rd=noticeDate47(rn.effectiveDate),rtext=rn.text||('New rates implemented'+(rd?' from '+rd:'')),an=p.announcement||{},cats=[...new Set(books.flatMap(b=>(b.items||[]).map(x=>x.category).filter(Boolean)))].sort();
    const previousContext=(cloudSession&&cloudSession.rateContextBookId270&&books.some(b=>b.id===cloudSession.rateContextBookId270))?cloudSession.rateContextBookId270:(sales&&books.length===1?books[0].id:'');
    const bookOptions=books.map(b=>`<option value="${b.id}">${esc(b.name)} · ${esc(audienceLabel230(b))}</option>`).join('');
    e.innerHTML=`<div class="cv47-wrap"><div class="cv47-head"><div><b style="font-size:18px">${esc(p.firm||'Price List')}</b><div class="note">${sales?'Sales team':'Customer'} · ${esc(p.user?.name||'')} ${off?'· Offline cached rates'+(exp?' valid until '+esc(exp):''):''}</div></div><button class="btn ghost sm" id="cv46out">Log out</button></div>${rn.enabled?`<div class="cv47-notice"><b>Rate update</b><div>${esc(rtext)}</div>${rd&&rn.text?`<div class="note" style="margin-top:3px">Effective from ${esc(rd)}</div>`:''}</div>`:''}${activeAnnouncement230(an)?`<div class="cv47-announce"><b>${esc(an.title||'Announcement')}</b><div>${esc(an.text)}</div></div>`:''}${sales?`<div id="cv270context" class="cv270-context ${mustChoose&&!previousContext?'require':''}"><div><b id="cv270contextTitle">${mustChoose&&!previousContext?'Choose a price list before quoting':'Rate context'}</b><small id="cv270contextSub">${mustChoose&&!previousContext?'Rates are intentionally hidden until you select the correct Retail / Wholesale / customer list.':'Confirm the price list before telling a buyer the rate.'}</small></div><span id="cv270contextBadge" class="cv270-context-badge">${mustChoose&&!previousContext?'SELECT REQUIRED':'RATE CONTEXT'}</span></div>`:''}<div class="cv47-switch"><div class="card"><div class="bd"><b>${sales?'Rate context':'Change price list'}</b><select id="cv47switchbook"><option value="">${mustChoose?'Select price list before searching':'Show all assigned price lists'}</option>${bookOptions}</select>${sales?'<div class="metric-sub" style="margin-top:5px">The selected context is shown beside every searched rate.</div>':''}</div></div><div class="card"><div class="bd"><b>Change / open catalog</b><select id="cv47switchcat"><option value="">Show all assigned catalogs</option>${(p.catalogs||[]).map(c=>`<option value="${c.id}">${esc(c.title||c.name||'Catalog')}</option>`).join('')}</select></div></div></div><div class="cv47-search"><div class="section-title">${sales?'Safe product rate search':'Quick product rate search'}</div><div class="cv47-searchbox"><input id="cv47q" type="search" autocomplete="off" placeholder="${sales?'Search after selecting the correct rate context...':'Search name, code, barcode, category, size, packing...'}"><select id="cv47book"><option value="">${mustChoose?'Select price list — rates hidden':'All assigned price lists'}</option>${bookOptions}</select><select id="cv47catfilter"><option value="">All categories</option>${cats.map(c=>`<option>${esc(c)}</option>`).join('')}</select></div><div class="cv47-tools"><button class="btn ghost sm" id="cv47fav">★ Favorites</button><button class="btn ghost sm" id="cv47recent">Recent products</button></div><div id="cv47results" class="cv47-results"></div></div><div id="cv47priceSection"><div class="section-title" style="margin-top:14px">Assigned price lists</div>${Object.keys(gs).sort().map(c=>`<div class="metric-sub" style="font-weight:700;text-transform:uppercase;margin:14px 0 6px">${esc(c)}</div>${gs[c].map(b=>{const aud=audience230(b);return `<div class="card" data-book-card="${b.id}" style="margin-bottom:10px"><div class="bd"><div class="cv270-bookmeta"><span class="cv270-aud ${aud}">${esc(audienceLabel230(b))}</span><b>${esc(b.name)}</b></div><div class="note">${(b.items||[]).length} searchable products${b.effectiveFrom?' · effective '+esc(noticeDate47(b.effectiveFrom)):''} · PDF download only</div>${sales&&aud==='wholesale'?'<div class="cv270-wholesale-note">Trade rates — do not use for a retail buyer.</div>':''}<div class="cv47-actions"><button class="btn ghost sm" data-pdf="${b.id}">Download PDF</button><button class="btn primary sm" data-share="${b.id}">Share PDF / WhatsApp</button>${sales&&((b.changes?.details||[]).length)?`<button class="btn ghost sm" data-changes230="${b.id}">What changed?</button>`:''}</div></div></div>`}).join('')}`).join('')||'<div class="cv47-empty">No price list assigned.</div>'}</div><div id="cv47catalogSection">${(p.catalogs||[]).length?`<div class="section-title" style="margin-top:22px">Product catalogs</div><div class="cv47-catgrid">${p.catalogs.map(c=>`<div class="card" data-cat-card="${c.id}"><div class="bd"><div class="cv47-booktag">${esc(c.category||'Other')}</div><b>${esc(c.title||c.name||'Catalog')}</b><div class="note">PDF catalog · cached after first online open</div><div class="cv47-actions"><button class="btn ghost sm" data-cat-view="${c.id}">View</button><button class="btn primary sm" data-cat-down="${c.id}">Download PDF</button></div></div></div>`).join('')}</div>`:''}</div></div>`;
    e.querySelector('#cv46out').onclick=window.cloudViewerLogout46;let mode='search';
    const contextEls={wrap:e.querySelector('#cv270context'),title:e.querySelector('#cv270contextTitle'),sub:e.querySelector('#cv270contextSub'),badge:e.querySelector('#cv270contextBadge')};
    const updateContext=()=>{if(!sales||!contextEls.wrap)return;const id=e.querySelector('#cv47book')?.value||'',b=books.find(x=>x.id===id),aud=b?audience230(b):'';contextEls.wrap.classList.remove('require','wholesale','retail');if(!b){if(mustChoose)contextEls.wrap.classList.add('require');contextEls.title.textContent=mustChoose?'Choose a price list before quoting':'Rate context';contextEls.sub.textContent=mustChoose?'Rates are hidden until the correct list is selected.':'Confirm the list before quoting.';contextEls.badge.textContent=mustChoose?'SELECT REQUIRED':'RATE CONTEXT';return}if(aud==='wholesale')contextEls.wrap.classList.add('wholesale');if(aud==='retail')contextEls.wrap.classList.add('retail');contextEls.title.textContent=(aud==='wholesale'?'Wholesale / Trade':aud==='retail'?'Retail':'Custom')+' rates · '+b.name;contextEls.sub.textContent=aud==='wholesale'?'Do not quote these rates to a retail customer.':aud==='retail'?'Retail context selected — still verify the customer before sharing.':'Custom price list selected — verify the intended customer/list.';contextEls.badge.textContent=aud==='wholesale'?'WHOLESALE MODE':aud==='retail'?'RETAIL MODE':'CUSTOM MODE'};
    const rr=()=>{updateContext();renderResults(e,p,mode)};
    const setBook=(id,source)=>{const b=books.find(x=>x.id===id);if(sales&&b&&audience230(b)==='wholesale'){const confirmations=(cloudSession&&(cloudSession.wholesaleConfirmed270=cloudSession.wholesaleConfirmed270||{}))||{};if(!confirmations[id]){if(!window.confirm('Wholesale / Trade rate mode\n\nThese rates should not be quoted to a retail customer. Continue with this price list?')){if(source)source.value=(cloudSession?.rateContextBookId270||'');return false}confirmations[id]=true}}if(cloudSession)cloudSession.rateContextBookId270=id||'';const a=e.querySelector('#cv47book'),bsel=e.querySelector('#cv47switchbook');if(a)a.value=id||'';if(bsel)bsel.value=id||'';e.querySelectorAll('[data-book-card]').forEach(c=>c.style.display=!id||c.dataset.bookCard===id?'':'none');rr();return true};
    e.querySelector('#cv47q').oninput=()=>{mode='search';rr()};
    e.querySelector('#cv47book').onchange=ev=>setBook(ev.target.value,ev.target);
    e.querySelector('#cv47catfilter').onchange=rr;
    e.querySelector('#cv47fav').onclick=()=>{mode='favorites';e.querySelector('#cv47q').value='';rr()};
    e.querySelector('#cv47recent').onclick=()=>{mode='recent';e.querySelector('#cv47q').value='';rr()};
    const sb=e.querySelector('#cv47switchbook');if(sb)sb.onchange=ev=>setBook(ev.target.value,ev.target);
    const sc=e.querySelector('#cv47switchcat');if(sc)sc.onchange=()=>{const id=sc.value;e.querySelectorAll('[data-cat-card]').forEach(c=>c.style.display=!id||c.dataset.catCard===id?'':'none')};
    const safeBookAction=(b,fn)=>{if(!b)return;if(sales&&audience230(b)==='wholesale'&&!window.confirm('Wholesale / Trade price list\n\nConfirm this is intended for a trade/wholesale buyer before continuing.'))return;fn(b)};
    e.querySelectorAll('[data-pdf]').forEach(x=>x.onclick=()=>safeBookAction((p.priceBooks||[]).find(b=>b.id===x.dataset.pdf),bookPdf));
    e.querySelectorAll('[data-share]').forEach(x=>x.onclick=()=>safeBookAction((p.priceBooks||[]).find(b=>b.id===x.dataset.share),bookShare));
    e.querySelectorAll('[data-changes230]').forEach(x=>x.onclick=()=>changesDialog230((p.priceBooks||[]).find(b=>b.id===x.dataset.changes230),p));
    e.querySelectorAll('[data-cat-view]').forEach(x=>x.onclick=async()=>{const orig=x.textContent;x.disabled=true;x.textContent='Loading…';try{await viewCatalog(p.catalogs.find(c=>c.id===x.dataset.catView))}finally{x.disabled=false;x.textContent=orig}});
    e.querySelectorAll('[data-cat-down]').forEach(x=>x.onclick=async()=>{const orig=x.textContent;x.disabled=true;x.textContent='Downloading…';try{await downloadCatalog(p.catalogs.find(c=>c.id===x.dataset.catDown))}finally{x.disabled=false;x.textContent=orig}});
    if(previousContext)setBook(previousContext,null);else rr()
  }

  const authoritative=e=>!!(e&&e.__authoritative);
  async function clearViewerDeviceData268(cs){
    const names=[cs?.loginName,cs?.payload?.user?.name].filter(Boolean).map(norm),uniq=[...new Set(names)];
    try{for(const n of uniq){localStorage.removeItem(CACHE_PREFIX+n);localStorage.removeItem('pm-viewer-prefs-v230:'+n);localStorage.removeItem('pm-order-cart-233:'+n)}}catch(e){}
    try{await caches.delete('pm-viewer-catalogs-v228')}catch(e){}
  }
  async function closeViewerSession46({reason='',clearCache=false}={}){const cs=cloudSession;cloudSession=null;window.__restrictedFirebaseSession46=false;clearTimeout(viewerSessionTimer271);viewerSessionTimer271=null;clearViewerSessionMarker271();try{if(cs?.unsubProfile)cs.unsubProfile()}catch(e){}try{if(cs?.auth)await cs.auth.signOut()}catch(e){}try{if(cs?.app)await cs.app.delete()}catch(e){}if(clearCache)await clearViewerDeviceData268(cs);const el=document.getElementById('cloudViewer46');if(el)el.remove();if(reason)toast(reason)}
  window.cloudViewerLogout46=()=>{const login=cloudSession?.loginName||'';if(!login)return closeViewerSession46();const m=document.createElement('div');m.className='modal';m.style.zIndex='200020';m.innerHTML=`<div class="box" style="max-width:430px"><div class="hd"><h2 style="margin:0">Log out</h2></div><div class="bd"><div class="note">Choose whether this device should retain the encrypted/verifier-protected offline price cache.</div></div><div class="ft"><button class="btn ghost" data-x="cancel">Cancel</button><button class="btn ghost" data-x="keep">Log out</button><button class="btn danger" data-x="clear">Log out & clear offline data</button></div></div>`;document.body.appendChild(m);m.onclick=async e=>{const b=e.target.closest('[data-x]');if(!b){if(e.target===m)m.remove();return}if(b.dataset.x==='cancel')return m.remove();const clear=b.dataset.x==='clear';m.remove();await closeViewerSession46({clearCache:clear})}};
  function profileExpired230(d){try{return d?.expiresAt&&typeof d.expiresAt.toMillis==='function'&&d.expiresAt.toMillis()<=Date.now()}catch(e){return false}}
  async function logActivity230(sec,uid,profile){try{const ua=safe(navigator.userAgent).slice(0,300),device=/Mobi|Android/i.test(ua)?'Mobile':'Desktop';await sec.db.collection('loginActivity').doc(uid).set({ownerUid:profile.ownerUid||'',username:profile.username||'',role:profile.role||'',lastLoginAt:firebase.firestore.FieldValue.serverTimestamp(),loginCount:firebase.firestore.FieldValue.increment(1),device,userAgent:ua,lastAccessVersion:profile.accessVersion||''},{merge:true})}catch(e){}}
  function watchProfile46(cs){if(!cs||cs.uid==='offline'||!cs.db)return;try{cs.unsubProfile=cs.db.collection('accessProfiles').doc(cs.uid).onSnapshot(async snap=>{if(cloudSession!==cs)return;const d=snap.exists?snap.data():null;if(!d||d.active!==true||profileExpired230(d)){await closeViewerSession46({reason:profileExpired230(d)?'This login has expired.':'This login was disabled or removed.',clearCache:true});return}try{const pe=d.expiresAt&&typeof d.expiresAt.toMillis==='function'?d.expiresAt.toMillis():0;if(pe&&(!cs.sessionExpiresAt271||pe<cs.sessionExpiresAt271)){cs.sessionExpiresAt271=pe;const mk=readViewerSession271();if(mk&&mk.uid===cs.uid){mk.expiresAt=pe;localStorage.setItem(VIEWER_SESSION_KEY,JSON.stringify(mk))}scheduleViewerSessionExpiry271(cs)}}catch(e){}if(d.accessVersion&&d.accessVersion!==cs.payload.accessVersion){try{const np=await readPayload(cs.db,cs.uid);if(!np||!np.accessVersion||np.accessVersion!==d.accessVersion)return;np.__offlineVerifier=cs.payload.__offlineVerifier;cs.payload=np;if(np.__offlineVerifier)cache(cs.loginName,np);show(np,false)}catch(e){}}},()=>{})}catch(e){}}
  window.secureViewerLogin46=async(name,pin)=>{let sec=null,cfg=null;try{const r=await ready();cfg=r.cfg;const emailV2=await loginEmailV2(name,pin,cfg.projectId),emailLegacy=await loginEmail(name,cfg.projectId),pw=await loginPassword(name,pin,cfg.projectId);sec=await viewerSecondary271(cfg);let cred=null,lastAuthErr=null;for(const em of [emailV2,emailLegacy]){try{cred=await sec.auth.signInWithEmailAndPassword(em,pw);break}catch(e){lastAuthErr=e}}if(!cred){const authErr=lastAuthErr||Error('Login failed'),code=(authErr&&authErr.code)||'';if(['auth/wrong-password','auth/user-not-found','auth/invalid-credential','auth/invalid-login-credentials','auth/invalid-email'].includes(code)){const er=Error('Incorrect username or PIN.');er.__authoritative=true;throw er}throw authErr}window.__restrictedFirebaseSession46=true;const pr=await sec.db.collection('accessProfiles').doc(cred.user.uid).get(),pd=pr.exists?pr.data():null;if(!pd||pd.active!==true||profileExpired230(pd)){const er=Error(profileExpired230(pd)?'This login has expired.':'This login has been disabled or removed.');er.__authoritative=true;throw er}const p=await readPayload(sec.db,cred.user.uid);if(!p){const er=Error('No price data has been published for this login.');er.__authoritative=true;throw er}if(pd.accessVersion&&p.accessVersion&&pd.accessVersion!==p.accessVersion){const er=Error('Published access is being updated. Try again.');er.__authoritative=true;throw er}if(p.accessExpiresAt&&p.accessExpiresAt<=Date.now()){const er=Error('This login has expired.');er.__authoritative=true;throw er}if(String(pin||'').length>=6){p.__offlineVerifier=await offlineVerifier(name,pin,cfg.projectId);cache(name,p)}else{delete p.__offlineVerifier;try{localStorage.removeItem(CACHE_PREFIX+norm(name))}catch(_){}}cloudSession={uid:cred.user.uid,loginName:pd.username||name,payload:p,app:sec.app,auth:sec.auth,db:sec.db,storage:sec.storage,unsubProfile:null};persistViewerSession271(cloudSession);show(p);watchProfile46(cloudSession);logActivity230(sec,cred.user.uid,pd);return true}catch(e){if(sec){try{await sec.auth.signOut()}catch(_){}try{await sec.app.delete()}catch(_){}}cloudSession=null;window.__restrictedFirebaseSession46=false;if(authoritative(e))throw e;try{const a=cfg||await ready().then(x=>x.cfg),c=cached(name),v=await offlineVerifier(name,pin,a.projectId),valid=String(pin||'').length>=6&&c&&norm(c.user?.name)===norm(name)&&c.__offlineVerifier===v&&(+c.offlineValidUntil||0)>Date.now()&&(!c.accessExpiresAt||+c.accessExpiresAt>Date.now());if(valid){cloudSession={uid:'offline',loginName:name,payload:c,storage:null};window.__restrictedFirebaseSession46=true;show(c,true);return true}}catch(_){}throw Error('Could not reach Firebase and no valid offline cache is available for this login.')}};
  function promptLogin(){const m=document.createElement('div');m.className='modal';m.innerHTML=`<div class="box" style="max-width:370px"><div class="hd"><h2 style="margin:0">Sales / customer login</h2></div><div class="bd"><div class="field"><label>Username</label><input id="sv46n"></div><div class="field"><label>PIN</label><input id="sv46p" type="password" inputmode="numeric"></div><div class="note">Search rates on screen, switch available UOMs, and download/share price lists only as PDF. After a successful login, this device stays signed in for up to 6 hours (or until you log out / access expires). Offline rate cache still expires automatically and is enabled only for PINs with at least 6 characters.</div><div class="pm-lock-msg" id="sv46m"></div></div><div class="ft"><button class="btn ghost" data-x="close">Cancel</button><button class="btn primary" data-x="go">Log in</button></div></div>`;document.body.appendChild(m);const go=async()=>{const b=m.querySelector('[data-x="go"]'),msg=m.querySelector('#sv46m');b.disabled=true;msg.textContent='Signing in…';try{await window.secureViewerLogin46(m.querySelector('#sv46n').value,m.querySelector('#sv46p').value);m.remove()}catch(e){msg.textContent=e.message||'Login failed';b.disabled=false}};m.onclick=e=>{const b=e.target.closest('[data-x]');if(!b){if(e.target===m)m.remove();return}b.dataset.x==='close'?m.remove():go()};m.querySelector('#sv46p').onkeydown=e=>{if(e.key==='Enter')go()}}
  window.viewerLoginPrompt44=promptLogin;

  // Disable the old browser-local viewer authentication path. All entry points, including
  // the encrypted lock-screen link and Users & access button, must use this secure portal.
  window.secureViewerPrompt46=promptLogin;
  window.viewerLoginPrompt44=promptLogin;
  window.viewerLogin44=(name,pin)=>window.secureViewerLogin46(name,pin).catch(e=>toast(e.message||'Login failed'));

  async function compressPdf233(file, onProgress){
    const J = (window.jspdf||{}).jsPDF;
    if(!J || typeof pdfjsLib === 'undefined') throw new Error('PDF tools are not available in this browser session.');
    const buf = await file.arrayBuffer();
    const doc = await pdfjsLib.getDocument({data: buf}).promise;
    const numPages = doc.numPages;
    const TARGET_DPI = 130, JPEG_QUALITY = 0.72;
    let out = null;
    for(let i = 1; i <= numPages; i++){
      if(onProgress) onProgress(i, numPages);
      const page = await doc.getPage(i);
      const viewport = page.getViewport({scale: TARGET_DPI / 72});
      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, Math.round(viewport.width));
      canvas.height = Math.max(1, Math.round(viewport.height));
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, canvas.width, canvas.height); // avoid black background behind transparent content
      await page.render({canvasContext: ctx, viewport}).promise;
      const imgData = canvas.toDataURL('image/jpeg', JPEG_QUALITY);
      const orientation = canvas.width > canvas.height ? 'l' : 'p';
      const sizePt = [canvas.width * 72 / TARGET_DPI, canvas.height * 72 / TARGET_DPI];
      if(!out) out = new J({orientation, unit: 'pt', format: sizePt});
      else out.addPage(sizePt, orientation);
      out.addImage(imgData, 'JPEG', 0, 0, sizePt[0], sizePt[1]);
      canvas.width = 0; canvas.height = 0; // release memory before the next page
      await new Promise(r => setTimeout(r, 0)); // yield to keep the UI responsive
    }
    if(!out) throw new Error('This PDF has no pages to compress.');
    return out.output('blob');
  }

  function catalogUploadDialog(){const m=document.createElement('div');m.className='modal';m.innerHTML=`<div class="box" style="max-width:500px"><div class="hd"><h2 style="margin:0">Upload product catalog</h2></div><div class="bd"><div class="cols2"><div class="field"><label>Catalog title</label><input id="C47title" placeholder="e.g. Rangoli Catalog 2026"></div><div class="field"><label>Product category</label><input id="C47cat" placeholder="e.g. Rangoli"></div></div><div class="field"><label>PDF catalog</label><input id="C47file" type="file" accept="application/pdf,.pdf"><div class="note">PDF only · up to 150 MB · secured in Firebase Storage. Large files can take a few minutes on a slow connection.</div></div><label style="display:flex;align-items:center;gap:8px;margin-top:8px;font-size:12.5px"><input type="checkbox" id="C47compress" checked> Compress before uploading <span class="mut">(recompresses images — smaller, faster upload; text may not stay searchable)</span></label><div id="C47prog" style="display:none;margin-top:8px"><div style="height:6px;border-radius:3px;background:var(--line-2,#eee);overflow:hidden"><div id="C47bar" style="height:100%;width:0%;background:var(--kumkum,#C42A1C);transition:width .2s"></div></div><div id="C47pct" class="note" style="margin-top:4px"></div></div><div id="C47msg" class="note"></div></div><div class="ft"><button class="btn ghost" data-x="close">Cancel</button><button class="btn primary" data-x="upload">Upload</button></div></div>`;document.body.appendChild(m);m.onclick=async e=>{const b=e.target.closest('[data-x]');if(!b){if(e.target===m)m.remove();return}if(b.dataset.x==='close')return m.remove();let file=m.querySelector('#C47file').files[0];const title=m.querySelector('#C47title').value.trim(),category=m.querySelector('#C47cat').value.trim()||'Other',msg=m.querySelector('#C47msg'),progWrap=m.querySelector('#C47prog'),bar=m.querySelector('#C47bar'),pct=m.querySelector('#C47pct'),wantCompress=m.querySelector('#C47compress').checked;if(!file)return toast('Choose a PDF catalog');if(file.type&&file.type!=='application/pdf'&&!/\.pdf$/i.test(file.name))return toast('Catalog must be PDF');if(file.size>150*1024*1024)return toast('Catalog must be 150 MB or smaller');b.disabled=true;msg.textContent='';const originalSize=file.size,originalName=file.name;if(wantCompress){progWrap.style.display='';bar.style.width='0%';try{pct.textContent='Compressing page 1…';const blob=await compressPdf233(file,(i,n)=>{pct.textContent='Compressing page '+i+' of '+n+'…';bar.style.width=Math.round(i/n*100)+'%'});if(blob.size<originalSize){file=new File([blob],originalName,{type:'application/pdf'});pct.textContent='Compressed: '+(originalSize/1024/1024).toFixed(1)+' MB → '+(file.size/1024/1024).toFixed(1)+' MB';}else{pct.textContent='Compression did not reduce the size — uploading the original file.';}}catch(err){pct.textContent='Could not compress ('+(err.message||'error')+') — uploading the original file instead.';}await new Promise(r=>setTimeout(r,600));}progWrap.style.display='';pct.textContent='Starting upload… (0 MB of '+(file.size/1024/1024).toFixed(1)+' MB)';bar.style.width='0%';try{const {auth,db,storage}=await ready();if(!auth.currentUser)throw Error('Sign in as owner in Firebase Settings first.');if(!storage)throw Error('Firebase Storage is unavailable.');await ensureOwner(db,auth.currentUser.uid);const id=uid(),filename=originalName.replace(/[^\w.\- ]+/g,'_'),path=`catalogs/${auth.currentUser.uid}/${id}/${filename}`;const task=storage.ref(path).put(file,{contentType:'application/pdf'});await new Promise((resolve,reject)=>{task.on('state_changed',snap=>{const donePct=snap.totalBytes?Math.round(snap.bytesTransferred/snap.totalBytes*100):0;bar.style.width=donePct+'%';pct.textContent=donePct+'% — '+(snap.bytesTransferred/1024/1024).toFixed(1)+' MB of '+(snap.totalBytes/1024/1024).toFixed(1)+' MB';},reject,resolve)});S.catalogFiles.push({id,title:title||originalName.replace(/\.pdf$/i,''),category,filename,storagePath:path,size:file.size,uploadedAt:Date.now()});save();m.remove();render();toast('Catalog uploaded — assign it to users.')}catch(err){progWrap.style.display='none';msg.textContent=err.message||'Upload failed';b.disabled=false}}}
  function catalogAssignDialog(id){const c=S.catalogFiles.find(x=>x.id===id);if(!c)return;const m=document.createElement('div');m.className='modal';m.innerHTML=`<div class="box" style="max-width:480px"><div class="hd"><h2 style="margin:0">Assign catalog · ${esc(c.title)}</h2></div><div class="bd">${S.viewerUsers.length?S.viewerUsers.map(u=>`<label style="display:block;margin:8px 0"><input type="checkbox" data-c47-user="${u.id}" ${(u.allowedCatalogFileIds||[]).includes(id)?'checked':''}> <b>${esc(u.name)}</b> · ${u.role==='sales'?'Sales team':'Customer'}</label>`).join(''):'<div class="note">Create a restricted user first.</div>'}</div><div class="ft"><button class="btn ghost" data-x="close">Cancel</button><button class="btn primary" data-x="save">Save</button></div></div>`;document.body.appendChild(m);m.onclick=e=>{const b=e.target.closest('[data-x]');if(!b){if(e.target===m)m.remove();return}if(b.dataset.x==='close')return m.remove();const selected=new Set([...m.querySelectorAll('[data-c47-user]:checked')].map(x=>x.dataset.c47User));S.viewerUsers.forEach(u=>{const set=new Set(u.allowedCatalogFileIds||[]);selected.has(u.id)?set.add(id):set.delete(id);u.allowedCatalogFileIds=[...set]});save();m.remove();render();toast('Catalog assignment saved; cloud users will auto-refresh.')}}
  async function deleteCatalog47(id){const c=S.catalogFiles.find(x=>x.id===id);if(!c||!confirm('Delete catalog "'+c.title+'"?'))return;try{if(c.storagePath){const {auth,db,storage}=await ready();if(!auth.currentUser)throw Error('Owner must be signed in before a cloud catalog can be deleted safely.');if(!storage)throw Error('Firebase Storage is unavailable.');await ensureOwner(db,auth.currentUser.uid);try{await storage.ref(c.storagePath).delete()}catch(e){if(e&&e.code!=='storage/object-not-found')throw e}}}catch(e){toast((e&&e.message)||'Catalog was not deleted because cloud removal could not be confirmed.');return}S.catalogFiles=S.catalogFiles.filter(x=>x.id!==id);S.viewerUsers.forEach(u=>u.allowedCatalogFileIds=(u.allowedCatalogFileIds||[]).filter(x=>x!==id));try{if(typeof caches!=='undefined'){const cc=await caches.open('pm-viewer-catalogs-v228');await cc.delete(catalogCacheKey(c))}}catch(e){}save();render();toast('Catalog deleted securely; assigned access will auto-refresh.')}
  function catalogLibraryHtml(){return `<div class="card" id="catalogLibrary47" style="margin-top:14px"><div class="hd"><h2>Product catalog library</h2><div class="spacer"></div><button class="btn ghost sm" data-act="catalog-upload47">Upload PDF catalog</button></div><div class="bd"><div class="note" style="margin-bottom:8px">Upload category-wise PDF catalogs. Restricted users can only open assigned catalogs.</div>${S.catalogFiles.length?`<div class="tbl-wrap"><table><thead><tr><th>Catalog</th><th>Category</th><th>Assigned users</th><th class="r">Actions</th></tr></thead><tbody>${S.catalogFiles.map(c=>`<tr><td><b>${esc(c.title)}</b><div class="metric-sub">${esc(c.filename)}</div></td><td>${esc(c.category||'Other')}</td><td>${S.viewerUsers.filter(u=>(u.allowedCatalogFileIds||[]).includes(c.id)).map(u=>esc(u.name)).join(', ')||'—'}</td><td class="r"><button class="link" data-cat-assign47="${c.id}">assign</button> · <button class="link" data-cat-delete47="${c.id}">delete</button></td></tr>`).join('')}</tbody></table></div>`:'<div class="empty-mini">No uploaded PDF catalogs yet.</div>'}</div></div>`}
  async function activityCard230(v){if(!v||v.querySelector('#loginActivity230'))return;const a=api();if(!a?.auth?.currentUser||!a.db)return;const card=document.createElement('div');card.className='card';card.id='loginActivity230';card.style.marginTop='14px';card.innerHTML='<div class="hd"><h2>Device / login activity</h2></div><div class="bd"><div class="note">Loading recent restricted-user activity… This is client-reported operational activity, not an immutable security audit log.</div></div>';v.appendChild(card);try{const snap=await a.db.collection('loginActivity').where('ownerUid','==',a.auth.currentUser.uid).get(),rows=[];snap.forEach(d=>rows.push({uid:d.id,...d.data()}));rows.sort((x,y)=>(y.lastLoginAt?.toMillis?.()||0)-(x.lastLoginAt?.toMillis?.()||0));card.querySelector('.bd').innerHTML=`<div class="note" style="margin-bottom:8px">Client-reported operational activity; use Firebase/Auth logs for authoritative security auditing.</div><div class="tbl-wrap"><table><thead><tr><th>User</th><th>Device</th><th>Last login</th><th class="r">Logins</th></tr></thead><tbody>${rows.map(r=>{const u=(S.viewerUsers||[]).find(x=>x.cloudUid===r.uid),at=r.lastLoginAt?.toDate?.();return `<tr><td><b>${esc(u?.name||r.username||'Unknown')}</b><div class="metric-sub">${esc(r.role||u?.role||'')}</div></td><td>${esc(r.device||'—')}</td><td>${at?esc(at.toLocaleString('en-IN')):'—'}</td><td class="r">${+r.loginCount||0}</td></tr>`}).join('')||'<tr><td colspan="4" class="empty-mini">No cloud login activity yet.</td></tr>'}</tbody></table></div>`}catch(e){card.querySelector('.bd').innerHTML='<div class="note">Login activity will appear after the updated Firestore rules are published and a restricted user logs in.</div>'}}
  function enhance(){if(page!=='access45')return;const v=document.getElementById('view');if(!v)return;let card=v.querySelector('#secureAccess46');if(!card){const a=api();card=document.createElement('div');card.className='card';card.id='secureAccess46';card.style.marginTop='14px';card.innerHTML=`<div class="hd"><h2>Secure Firebase access</h2></div><div class="bd"><div class="private-note"><b>Security:</b> restricted users receive final rates and UOM alternatives only. Owner costing, discount formulas, inventory and settings are excluded. Offline viewer access expires after 24 hours or the user access-expiry date, whichever comes first.</div><div class="note" style="margin:10px 0">${a?.db?(a.auth?.currentUser?'Owner Firebase account is signed in. Pending logins will retry automatically.':'Firebase connected, owner not signed in. New cloud logins stay pending until the Owner signs in.'):'Firebase is not configured on this device.'}</div><button class="btn ghost sm" data-act="init-secure46">Initialize security</button> <button class="btn ghost sm" data-act="publish-all46">Publish / update cloud users</button> <button class="btn ghost sm" data-act="repair-cloud46">Repair pending only</button><div id="cloudProgress265" style="margin-top:10px"></div></div>`;v.appendChild(card)}if(!v.querySelector('#catalogLibrary47'))v.insertAdjacentHTML('beforeend',catalogLibraryHtml());v.querySelectorAll('[data-a45-edit]').forEach(btn=>{if(btn.parentElement.querySelector(`[data-cloud46="${btn.dataset.a45Edit}"]`))return;const id=btn.dataset.a45Edit,u=S.viewerUsers.find(x=>x.id===id),b=document.createElement('button');b.className='link';b.dataset.cloud46=id;const failed=u?.cloudSyncState==='error',syncing=u?.cloudSyncState==='syncing';b.textContent=syncing?'syncing…':failed?'retry cloud':u?.cloudUid?'sync cloud':'create cloud login';if(failed){b.title=u.cloudSyncError||'Cloud sync failed';const er=document.createElement('div');er.className='metric-sub';er.style.cssText='max-width:260px;color:var(--danger,#a23a32);margin-top:3px;white-space:normal';er.textContent='Cloud error: '+(u.cloudSyncError||'sync failed');btn.parentElement.appendChild(er)}else if(!u?.cloudUid){const st=document.createElement('div');st.className='metric-sub';st.style.cssText='margin-top:3px';st.textContent='Cloud: pending';btn.parentElement.appendChild(st)}btn.insertAdjacentText('afterend',' · ');btn.after(b)});updateProvisionProgress265();activityCard230(v)}

  const saveBeforeSecure=save;
  function cloudRelevantStamp266(){
    // Correctness-first domain stamp. Only cloud-visible pricing/catalog/access dependencies
    // are included, but every dependency that can change a restricted user's rate/PDF is covered.
    const ph=fastHash265(JSON.stringify((S.products||[]).map(p=>[p.id,p.updatedAt||0,p.code,p.name,p.size,p.category,p.packing,p.barcode,p.mrp,p.price,p.stock,p.status,p.priceUnit,p.priceListUnit,p.keywords,p.tags])));
    const rh=fastHash265(JSON.stringify(S.rules||[]));
    const pbh=fastHash265(JSON.stringify((S.priceBooks||[]).map(pb=>[pb.id,pb.name,pb.category,pb.version230||0,pb.effectiveFrom230||'',pb.config||{},pb.scheduled230||null,pb.previousConfig230||null])));
    const uh=fastHash265(JSON.stringify((S.viewerUsers||[]).map(u=>[u.id,u.name,u.role,u.active!==false,u.accessExpiresOn||'',u.allowedPriceBookIds||[],u.allowedCatalogFileIds||[],u.rateNotice||{},u.announcement||{},u.credentialPending265||false])));
    const ch=fastHash265(JSON.stringify((S.catalogFiles||[]).map(c=>[c.id,c.storagePath,c.title,c.category,c.filename,c.size,c.uploadedAt||0])));
    const policy=fastHash265(JSON.stringify([S.uomMaster||[],S.quantityPriceSlabs||[],S.customerRateLocks||[],S.customerRateTemplates230||[],S.scheduledRates||[]]));
    const branding=fastHash265(JSON.stringify(S.pdfBrandTemplates230||[]));
    const settings=fastHash265(JSON.stringify({firm:S.settings?.firm||'',tagline:S.settings?.tagline||'',address:S.settings?.address||'',phone:S.settings?.phone||'',email:S.settings?.email||'',gstin:S.settings?.gstin||'',wef:S.settings?.wef||'',footer:S.settings?.footer||'',rounding:S.settings?.rounding||'',currency:S.settings?.currency||'',gstDefault:S.settings?.gstDefault??null}));
    return [ph,rh,pbh,uh,ch,policy,branding,settings].join('|');
  }
  let lastCloudRelevantStamp266='';try{lastCloudRelevantStamp266=cloudRelevantStamp266()}catch(e){}
  function userNeedsPublish265(u){
    if(!u)return false;if(!u.cloudUid||u.cloudSyncState==='pending'||u.cloudSyncState==='error'||u.credentialPending265)return true;
    try{return payloadHash265(u)!==u.cloudPayloadHash265}catch(e){return true}
  }
  async function publishPending(){
    if(!cloudPublishDirty265)return true;
    const a=api();if(!navigator.onLine||!a?.auth?.currentUser)return false;
    const users=(S.viewerUsers||[]).filter(x=>x.active!==false||x.cloudUid).filter(userNeedsPublish265);
    if(!users.length){cloudPublishDirty265=false;return true}
    const failures=[];
    for(const u of users){try{await syncOne(u.id)}catch(e){failures.push({name:u.name,error:cloudErrorMessage(e)})}}
    cloudPublishDirty265=failures.length>0;
    if(page==='access45')setTimeout(()=>render(),0);
    if(failures.length)throw Error(failures.map(x=>x.name+': '+x.error).join(' | '));
    return true;
  }
  function schedulePublish(delay=1400){if(publishSuppress||window.__restrictedFirebaseSession46)return;cloudPublishDirty265=true;clearTimeout(publishTimer);publishTimer=setTimeout(()=>publishPending().catch(()=>{}),delay)}
  function flushPublishNow233(){if(publishSuppress||window.__restrictedFirebaseSession46||!cloudPublishDirty265)return;clearTimeout(publishTimer);return publishPending().catch(()=>{})}
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='hidden')flushPublishNow233()});
  window.addEventListener('pagehide',()=>{flushPublishNow233()});
  save=function(){
    const out=saveBeforeSecure();
    let stamp='';try{stamp=cloudRelevantStamp266()}catch(e){}
    if(stamp&&stamp!==lastCloudRelevantStamp266){lastCloudRelevantStamp266=stamp;schedulePublish()}
    return out
  };
  window.addEventListener('online',()=>schedulePublish(120));
  window.markRestrictedPublish265=()=>{try{lastCloudRelevantStamp266=cloudRelevantStamp266()}catch(e){}schedulePublish(120)};


  const oldRender=render;render=function(){const out=oldRender();setTimeout(()=>{const legacy=document.getElementById('L_viewerBox44');if(legacy)legacy.remove();enhance();if(cloudSession)show(cloudSession.payload,cloudSession.uid==='offline');const l=document.getElementById('viewerLoginLink44');if(l)l.onclick=promptLogin},0);return out};
  document.addEventListener('click',async e=>{
    const c=e.target.closest('[data-cloud46]');if(c){e.preventDefault();window.syncOneUser46(c.dataset.cloud46)}
    const a=e.target.closest('[data-act]');if(a?.dataset.act==='init-secure46'){e.preventDefault();window.initSecureAccess46()}if(a?.dataset.act==='publish-all46'){e.preventDefault();window.syncAllUsers46()}if(a?.dataset.act==='repair-cloud46'){e.preventDefault();window.syncAllUsers46({onlyPending:true})}if(a?.dataset.act==='catalog-upload47'){e.preventDefault();catalogUploadDialog()}
    const as=e.target.closest('[data-cat-assign47]');if(as){e.preventDefault();catalogAssignDialog(as.dataset.catAssign47)}const del=e.target.closest('[data-cat-delete47]');if(del){e.preventDefault();deleteCatalog47(del.dataset.catDelete47)}
    const oldDel=e.target.closest('[data-viewer-del]');if(oldDel){e.preventDefault();e.stopImmediatePropagation();const u=S.viewerUsers.find(x=>x.id===oldDel.dataset.viewerDel);if(u&&confirm('Remove this user and revoke app/Firebase data access? The Firebase Auth identity may remain until an Admin cleanup is run.')){try{await revokeUser(u);S.viewerUsers=S.viewerUsers.filter(x=>x.id!==u.id);publishSuppress=true;try{save()}finally{publishSuppress=false}render();toast('User removed and cloud access revoked')}catch(err){toast(err.message||'User was not removed because cloud revoke failed')}}return}
    const modalDel=e.target.closest('[data-x="delete"], [data-x="del"]');if(modalDel){const m=modalDel.closest('.modal'),nameInput=m&&(m.querySelector('#A45_name')||m.querySelector('#V44_name'));if(nameInput){const u=S.viewerUsers.find(x=>norm(x.name)===norm(nameInput.value));if(u){e.preventDefault();e.stopImmediatePropagation();if(confirm('Delete '+u.name+' and revoke Firebase/offline access?')){try{await revokeUser(u);S.viewerUsers=S.viewerUsers.filter(x=>x.id!==u.id);publishSuppress=true;try{save()}finally{publishSuppress=false}m.remove();render();toast('User removed and cloud access revoked')}catch(err){toast(err.message||'User was not removed because cloud revoke failed')}}return}}}
  },true);
  window.clearRestrictedOfflineCaches265=async()=>{clearTimeout(viewerSessionTimer271);viewerSessionTimer271=null;clearViewerSessionMarker271();if(cloudSession){try{await closeViewerSession46({clearCache:true})}catch(e){}}else{try{const a=firebase.app(VIEWER_SESSION_APP);try{await a.auth().signOut()}catch(e){}try{await a.delete()}catch(e){}}catch(e){}}try{Object.keys(localStorage).filter(k=>k.startsWith(CACHE_PREFIX)||k.startsWith('pm-viewer-prefs-v230:')||k.startsWith('pm-order-cart-233:')).forEach(k=>localStorage.removeItem(k))}catch(e){}try{await caches.delete('pm-viewer-catalogs-v228')}catch(e){}};
  window.cloudWipeAccess265=async()=>{
    const {auth,db,storage}=await ready();if(!auth.currentUser)throw Error('Sign in as Owner in Firebase Settings before deleting cloud data.');const owner=auth.currentUser.uid;await ensureOwner(db,owner);const errors=[];
    for(const u of [...(S.viewerUsers||[])]){try{await revokeUser(u,{deleteAuth:true})}catch(e){errors.push(`${u.name}: ${e.message||e}`)}}
    // Remove access profiles left behind by older/local user records too. Viewer payloads are keyed by UID.
    try{const ps=await db.collection('accessProfiles').where('ownerUid','==',owner).get();for(const d of ps.docs){try{await deletePayload(db,d.id)}catch(e){}try{await d.ref.delete()}catch(e){errors.push(`Access ${d.id}: ${e.message||e}`)}}}catch(e){errors.push(`Access profile cleanup: ${e.message||e}`)}
    for(const c of [...(S.catalogFiles||[])]){if(c.storagePath&&storage)try{await storage.ref(c.storagePath).delete()}catch(e){if(!/object-not-found/i.test(String(e?.code||e)))errors.push(`Catalog ${c.title||c.filename}: ${e.message||e}`)}}
    // Also sweep orphaned catalog objects that are no longer present in local state.
    if(storage)try{const top=await storage.ref(`catalogs/${owner}`).listAll();for(const pref of top.prefixes||[]){const sub=await pref.listAll();for(const item of sub.items||[])try{await item.delete()}catch(e){errors.push(`Catalog object ${item.fullPath||item.name}: ${e.message||e}`)}}for(const item of top.items||[])try{await item.delete()}catch(e){errors.push(`Catalog object ${item.fullPath||item.name}: ${e.message||e}`)}}catch(e){if(!/object-not-found/i.test(String(e?.code||e)))errors.push(`Catalog sweep: ${e.message||e}`)}
    const deleteDocs=async q=>{try{const snap=await q.get();for(const d of snap.docs)await d.ref.delete()}catch(e){errors.push(e.message||String(e))}};
    await deleteDocs(db.collection('orderRequests').doc(owner).collection('items'));
    await deleteDocs(db.collection('loginActivity').where('ownerUid','==',owner));
    try{await deleteDocs(db.collection('users').doc(owner).collection('appData'))}catch(e){}
    await window.clearRestrictedOfflineCaches265();
    if(errors.length)throw Error('Some cloud records could not be removed: '+errors.slice(0,5).join(' | '));return true;
  };
  setTimeout(()=>render(),0);setTimeout(()=>restoreViewerSession271(),180);setTimeout(()=>schedulePublish(500),900);window.payloadFor46=payloadFor;window.showViewerPreview46=(p)=>show(p,false);window.getCloudSession233=()=>cloudSession;window.PriceManagerAPI={...(window.PriceManagerAPI||{}),version:'2.71 persistent-viewer-session'};
})();

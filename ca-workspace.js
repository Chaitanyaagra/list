/* CA 2.81 workspace. Uses existing pricing/export/auth paths. */
(()=>{
  'use strict';
  const date=x=>{if(!x)return 'Not set';const d=new Date(typeof x==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(x)?x+'T00:00:00':x);return Number.isNaN(d.getTime())?'Not set':d.toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'})};
  const audience=b=>{if(['retail','wholesale','custom'].includes(b?.audience270))return b.audience270;const n=(b?.name+' '+b?.category).toLowerCase();return /wholesale|distributor|dealer|stockist|trade|bulk/.test(n)?'wholesale':/retail|consumer|counter|mrp/.test(n)?'retail':'custom'};
  const modeLabel=x=>({retail:'Retail',wholesale:'Wholesale / Trade',custom:'Custom'}[x]||'Custom');
  function publication(pb){
    if(!pb)return {key:'draft',label:'Draft',detail:'Unsaved working list'};
    const users=(S.viewerUsers||[]).filter(u=>u.active!==false&&(u.allowedPriceBookIds||[]).includes(pb.id));
    if(!users.length)return {key:'draft',label:'Saved · not assigned',detail:'Assign this list in Users & Access'};
    const ready=users.filter(u=>u.cloudUid&&u.cloudSyncState==='ready'&&typeof window.userNeedsPublish281==='function'&&!window.userNeedsPublish281(u)).length;
    if(ready===users.length)return {key:'published',label:'Published',detail:`Current for ${ready} assigned login${ready===1?'':'s'}`};
    return {key:users.some(u=>u.cloudSyncState==='error')?'error':'pending',label:ready?'Partly published':'Publish pending',detail:`${ready} of ${users.length} assigned logins current`};
  }
  const badges=pb=>{const st=publication(pb);return `<span class="ca281-status ${st.key}" title="${esc(st.detail)}">${esc(st.label)}</span>${pb?.scheduled230?`<span class="ca281-status scheduled">Scheduled ${esc(date(pb.scheduled230.effectiveDate))}</span>`:''}`};
  const safeName=x=>(String(x||'price-list').replace(/\.pdf$/i,'').replace(/[<>:"/\\|?*\x00-\x1f]/g,'_').trim()||'price-list')+'.pdf';
  function config(pb){
    if(!pb)return listConfig();
    const own=Object.prototype.hasOwnProperty.call(ui.list,'effectiveDate230'),old=ui.list.effectiveDate230;
    try{const sc=pb.scheduled230;ui.list.effectiveDate230=sc&&new Date(sc.effectiveDate+'T00:00:00').getTime()<=Date.now()?sc.effectiveDate:(pb.effectiveFrom230||'');const cfg=window.priceBookListConfig44(pb);cfg.title=pb.name||cfg.title;return cfg}
    finally{if(own)ui.list.effectiveDate230=old;else delete ui.list.effectiveDate230}
  }
  function view(cfg){
    const m=document.createElement('div');m.className='modal';m.setAttribute('role','dialog');m.setAttribute('aria-modal','true');m.setAttribute('aria-label','Price list preview');
    m.innerHTML=`<div class="box" style="max-width:1000px"><div class="hd"><h2>${esc(cfg.title||'Price list')}</h2><div class="spacer"></div><button class="btn ghost" data-ca-close>Close</button></div><div class="bd"><p>${esc(cfg.firm||'')} ${esc(cfg.sub||'')}</p><div class="tbl-wrap"><table><thead><tr>${cfg.columns.map(c=>`<th>${esc(c.label)}</th>`).join('')}</tr></thead><tbody>${cfg.groups.map(g=>`<tr><th colspan="${cfg.columns.length}">${esc(g.name||'Products')}</th></tr>${g.rows.map(r=>`<tr>${r.map(c=>`<td>${esc(c==null?'—':String(c))}</td>`).join('')}</tr>`).join('')}`).join('')}</tbody></table></div></div></div>`;
    const origin=document.activeElement;const close=()=>{m.remove();origin?.focus?.()};m.onclick=e=>{if(e.target===m||e.target.closest('[data-ca-close]'))close()};m.addEventListener('keydown',e=>{if(e.key==='Escape'){e.preventDefault();close()}});document.body.append(m);m.querySelector('button').focus();
  }
  async function exportList(pb,action){
    try{const cfg=config(pb);if(action==='view')return view(cfg);const doc=buildPDF(cfg),name=safeName(pb?.name||ui.list.filename||cfg.title);
      if(action==='share'){const file=new File([doc.output('blob')],name,{type:'application/pdf'});if(navigator.share&&navigator.canShare?.({files:[file]})){await navigator.share({title:cfg.title||'Price list',files:[file]});return}toast('File sharing is unavailable here. Downloading the PDF.')}doc.save(name);
    }catch(e){if(e?.name!=='AbortError')toast(e?.message||'Could not prepare price list')}
  }
  function actions(pb){return `<div class="ca281-actions"><button class="btn ghost" data-ca-export="view" data-book="${esc(pb.id)}">View</button><button class="btn ghost" data-ca-export="share" data-book="${esc(pb.id)}">Share</button><button class="btn primary" data-ca-export="download" data-book="${esc(pb.id)}">Download</button></div>`}
  const filters={q:'',party:'',mode:''};
  const initialList=JSON.parse(JSON.stringify(ui.list||{}));
  function drawBooks(target){
    const q=filters.q.trim().toLowerCase(),books=(S.priceBooks||[]).filter(b=>(!q||[b.name,b.category,(S.parties||[]).find(p=>p.id===b.config?.party)?.name].join(' ').toLowerCase().includes(q))&&(!filters.party||b.config?.party===filters.party)&&(!filters.mode||audience(b)===filters.mode));
    target.innerHTML=books.length?books.map(b=>{const party=(S.parties||[]).find(p=>p.id===b.config?.party);return `<article class="card ca281-book"><div class="ca281-meta">${badges(b)}</div><h2>${esc(b.name)}</h2><p>${esc(party?.name||'General price list')} · ${esc(modeLabel(audience(b)))}</p><p class="note">Effective ${esc(date(b.effectiveFrom230))} · Updated ${esc(date(b.updatedAt||b.createdAt))}</p><p class="note">${esc(publication(b).detail)}</p>${actions(b)}<div class="ca281-actions"><button class="btn ghost" data-ca-edit="${esc(b.id)}">Edit rates</button><button class="btn ghost" data-nav="access45">Assign / publish</button></div></article>`}).join(''):`<div class="ca281-empty"><b>${S.priceBooks?.length?'No matching price lists':'Create your first price list'}</b><p>${S.priceBooks?.length?'Try another name, customer or rate type.':'Choose products and customer rates, then save your Price Book.'}</p><button class="btn primary" data-ca-new>New price list</button></div>`;
  }
  function hub(v,t,sub,act){
    t.textContent='Price lists';sub.textContent='Customer rates, effective dates and publishing';
    // Keep the existing templates and branding buttons with their event handlers.
    const oldTemplates=document.getElementById('RT230manage'),oldBrand=document.getElementById('BR230manage');
    act.innerHTML='<button class="btn primary" data-ca-new>New price list</button><button class="btn ghost" data-nav="access45">Users & Access</button><button class="btn ghost" data-nav="pricing230">Refresh status</button>';
    for(const b of [oldTemplates,oldBrand])if(b)act.append(b);
    v.innerHTML=`<div class="ca281-toolbar"><div><label for="ca281-find">Search price lists</label><input type="search" id="ca281-find" placeholder="Name, category or customer" value="${esc(filters.q)}"></div><div><label for="ca281-customer">Customer</label><select id="ca281-customer"><option value="">All customers</option>${(S.parties||[]).filter(p=>!p.archived).map(p=>`<option value="${esc(p.id)}" ${p.id===filters.party?'selected':''}>${esc(p.name)}</option>`).join('')}</select></div><div><label for="ca281-mode">Rate type</label><select id="ca281-mode"><option value="">All rate types</option>${['retail','wholesale','custom'].map(x=>`<option value="${x}" ${filters.mode===x?'selected':''}>${modeLabel(x)}</option>`).join('')}</select></div></div><div class="ca281-books" id="ca281-books"></div>`;
    const target=v.querySelector('#ca281-books');drawBooks(target);
    for(const [id,key,event] of [['ca281-find','q','input'],['ca281-customer','party','change'],['ca281-mode','mode','change']])v.querySelector('#'+id).addEventListener(event,e=>{filters[key]=e.target.value;drawBooks(target)});
  }
  const originalList=viewList;
  viewList=function(v,t,sub,act){
    originalList(v,t,sub,act);t.textContent='Price list workspace';
    const pb=(S.priceBooks||[]).find(b=>b.id===ui.editingPriceBook230);
    const bar=document.createElement('section');bar.className='card ca281-context';bar.setAttribute('aria-label','Price list context');
    // Move the original controls so their pricing handlers stay attached.
    for(const id of ['L_party','L_catalog']){const el=v.querySelector('#'+id),field=el?.closest('.field');if(field){const label=field.querySelector('label');if(label){label.htmlFor=id;if(id==='L_party')label.textContent='Customer'}bar.append(field)}}
    const context=document.createElement('div');context.innerHTML=`<label>Rate type</label><b>${esc(modeLabel(audience(pb)))}</b><div class="note">Effective ${esc(date(pb?.effectiveFrom230||ui.list.effectiveDate230))}</div>`;bar.append(context);
    const state=document.createElement('div');state.className='ca281-meta';state.innerHTML=`<span class="ca281-status">Draft workspace</span>${pb?badges(pb):''}<span class="note">${pb?'Saved list: '+esc(pb.name)+' · Updated '+esc(date(pb.updatedAt||pb.createdAt)):'Save as Price Book to retain and assign this list.'}</span>`;bar.append(state);v.prepend(bar);
    const exports=document.createElement('div');exports.className='ca281-actions';exports.style.marginTop='0';exports.innerHTML='<button class="btn ghost" data-ca-export="view">View</button><button class="btn ghost" data-ca-export="share">Share</button>';
    const pdf=act.querySelector('[data-act="make-pdf"]');if(pdf){pdf.textContent='Download';exports.append(pdf)}act.prepend(exports);
    const more=document.createElement('details');more.className='ca281-more';const summary=document.createElement('summary');summary.textContent='More tools';const menu=document.createElement('div');menu.className='ca281-menu';more.append(summary,menu);
    for(const b of [...act.children])if(b.tagName==='BUTTON'&&!['save-pricebook-44','schedule-book-230'].includes(b.dataset.act))menu.append(b);
    if(menu.children.length)act.append(more);
    const rates=[...v.querySelectorAll('[data-list-rate]')];
    if(rates.length){const card=rates[0].closest('.card');card?.classList.add('ca281-preview');const body=card?.querySelector('.bd');if(body){const search=document.createElement('input');search.type='search';search.className='ca281-preview-search';search.placeholder='Find product in preview';search.setAttribute('aria-label','Filter preview rows');body.prepend(search);search.oninput=()=>{const q=search.value.trim().toLowerCase();rates.forEach(input=>{const row=input.closest('tr');row.hidden=!row.textContent.toLowerCase().includes(q)});};}
      for(const input of rates){const row=input.closest('tr');[...row.children].forEach((td,i)=>td.dataset.label=['Code','Product','Final rate','Actions'][i]||'');for(const el of row.querySelectorAll('.uom-matrix230,.pc26-source')){const details=document.createElement('details');details.className='ca281-details';const summary=document.createElement('summary');summary.textContent=el.classList.contains('uom-matrix230')?'Other units':'Rate calculation';el.before(details);details.append(summary,el)}}
    }
  };
  const originalNav=renderNav;
  renderNav=function(...args){const out=originalNav.apply(this,args);if(page==='list')document.querySelector('#nav [data-nav="pricing230"]')?.classList.add('on');return out};
  const originalRender=render;
  render=function(...args){const out=originalRender.apply(this,args);if(page==='pricing230'&&!window.__restrictedFirebaseSession46)hub(document.getElementById('view'),document.getElementById('pgTitle'),document.getElementById('pgSub'),document.getElementById('topActions'));return out};
  document.addEventListener('click',e=>{
    const b=e.target.closest('[data-ca-export],[data-ca-edit],[data-ca-new]');if(!b||window.__restrictedFirebaseSession46)return;
    if(b.hasAttribute('data-ca-new')){delete ui.editingPriceBook230;ui.list=JSON.parse(JSON.stringify(initialList));delete ui.list.effectiveDate230;return go('list')}
    if(b.dataset.caEdit)return window.loadPriceBook44(b.dataset.caEdit);
    const pb=b.dataset.book?(S.priceBooks||[]).find(x=>x.id===b.dataset.book):null;if(b.dataset.book&&!pb)return toast('Price list no longer exists');exportList(pb,b.dataset.caExport);
  });
  window.CAWorkspace281={publication,audience,date};
  // Navigation-only agent action. It never grants access or publishes records.
  const context=document.modelContext;
  if(context?.registerTool){
    const lifecycle=new AbortController();
    const tool={name:'filter_price_lists',title:'Filter price lists',description:'Filter the owner price-list workspace by name and rate type.',inputSchema:{type:'object',properties:{query:{type:'string'},rateType:{type:'string',enum:['','retail','wholesale','custom']}},additionalProperties:false},annotations:{readOnlyHint:false,untrustedContentHint:true},execute(input){
      if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(k=>!['query','rateType'].includes(k))||(input.query!==undefined&&(typeof input.query!=='string'||input.query.length>200))||(input.rateType!==undefined&&!['','retail','wholesale','custom'].includes(input.rateType)))throw Error('Invalid price-list filter');
      if(window.__restrictedFirebaseSession46||(typeof SEC!=='undefined'&&SEC.role!=='owner')||document.getElementById('entryGate238')||document.querySelector('.pm-lock')||!window.__entryGate238Resolved)throw Error('Unlock the owner workspace first');
      filters.q=input.query||'';filters.mode=input.rateType||'';filters.party='';go('pricing230');return {query:filters.q,rateType:filters.mode};
    }};
    try{Promise.resolve(context.registerTool(tool,{signal:lifecycle.signal})).catch(()=>{})}catch(_){}
    window.addEventListener('pagehide',()=>lifecycle.abort(),{once:true});
  }
  if(page==='core45'||page==='dash')page='pricing230';
  render();
})();

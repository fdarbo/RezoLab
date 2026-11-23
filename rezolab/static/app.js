// SPDX-License-Identifier: GPL-2.0-only — Copyright (c) 2026 fdarbo — RézoLab
'use strict';
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let epoch=null;
const NS='http://www.w3.org/2000/svg';
let packets=[], seen=0, selIdx=null, playing=false, playIdx=0, playTimer=null;
let LOCAL_IP='', GATEWAY='';                    // valeurs EFFECTIVES utilisées par toutes les vues
let SRV_LOCAL='', SRV_GW='', localOverride=null;    // valeurs de cette machine / valeurs déduites du pcap ou saisies
let seqHistory=[];
let disp=[];                 // paquets AFFICHÉS (filtrés) — base du tableau, replay et diagramme
let lastAnimated=0;          // index du dernier paquet déjà propulsé vers les vues

/* ================= Filtres ================= */
function protoMatch(p,pr){
  switch(pr){
    case 'dns' : return p.proto==='DNS';
    case 'icmp': return p.proto==='ICMP';
    case 'dhcp': return p.proto==='DHCP';
    case 'arp' : return p.proto==='ARP';
    case 'udp' : return p.proto==='UDP';
    case 'tcp' : return p.proto==='TCP';
    case 'telnet': return p.proto==='TCP' && (p.sport===23||p.dport===23);
    case 'ftp' : return p.proto==='TCP' && [20,21].some(x=>p.sport===x||p.dport===x);
    case 'ssh' : return p.proto==='TCP' && (p.sport===22||p.dport===22);
    case 'http': return p.proto==='TCP' &&
      (p.sport===80||p.dport===80||p.sport===443||p.dport===443);
  }
  return true;
}
function matchFilter(p){
  if(isOwnPtr(p)) return false;                 // bruit généré par la résolution inverse de RézoLab
  if(p.v6 && !$('bV6').classList.contains('on')) return false;
  const protos=[...document.querySelectorAll('.chip.on[data-p]')].map(c=>c.dataset.p);
  if(protos.length && !protos.some(pr=>protoMatch(p,pr))) return false;
  const ip=$('ipf').value.trim();
  if(ip && p.src!==ip && p.dst!==ip) return false;
  return true;
}
function applyFilter(){
  disp=packets.filter(matchFilter);
  const tb=$('tbody'); tb.innerHTML='';
  disp.forEach((p,n)=>tb.appendChild(row(p,n+1)));
  $('prog').max=disp.length;
  $('pos').textContent=`${playIdx} / ${disp.length}`;
}
function refilterAll(){
  pause();
  applyFilter();
  seqHistory=disp.slice(0,playIdx);
  flushSeq(); flushPath();
  drawSeqBase();
}

/* ================= IP du poste : machine locale, ou déduite d'un pcap réalisé ailleurs ================= */
const isPriv=ip=>/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(ip||'');
function applyLocal(quiet){
  LOCAL_IP=localOverride?localOverride.ip:SRV_LOCAL; GATEWAY=localOverride?localOverride.gw:SRV_GW;
  mapLocal=LOCAL_IP; mapGw=GATEWAY;
  const tag=localOverride?(localOverride.auto?' (déduit du pcap)':' (saisi)'):'';
  const n=$('netinfo'); n.textContent=`IP: ${LOCAL_IP||'?'} · GW: ${GATEWAY||'?'}${tag}`;
  n.style.cursor='pointer'; n.title='Cliquer pour modifier l\'IP du poste (client) et la passerelle : utile pour un pcap capturé sur une autre machine';
  if(!quiet){ updatePathLabels(); drawSeqHead(); }
}
function inferNet(pk){                                  // poste = IP privée la plus présente, pondérée par les SYN émis ; GW = cible ARP/DNS privée du poste
  const cnt={}, syn={}, arpT={}, dnsT={};
  pk.forEach(p=>{
    [p.src,p.dst].forEach(ip=>{ if(isPriv(ip)) cnt[ip]=(cnt[ip]||0)+1; });
    if(p.fl==='S' && isPriv(p.src)) syn[p.src]=(syn[p.src]||0)+1;
  });
  let ip='', best=-1;
  for(const [k,v] of Object.entries(cnt)){ const sc=v+(syn[k]||0)*2; if(sc>best){ best=sc; ip=k; } }
  if(!ip){ const s=pk.find(p=>p.fl==='S'); ip=s?s.src:(pk[0]?pk[0].src:''); }       // aucune IP privée : premier client TCP
  pk.forEach(p=>{
    if(p.proto==='ARP' && p.src===ip && isPriv(p.dst)) arpT[p.dst]=(arpT[p.dst]||0)+1;
    if(p.proto==='DNS' && p.src===ip && isPriv(p.dst) && p.dst!==ip) dnsT[p.dst]=(dnsT[p.dst]||0)+1;
  });
  const top=o=>Object.entries(o).sort((a,b)=>b[1]-a[1])[0], g=top(arpT)||top(dnsT);
  return {ip, gw:g?g[0]:''};
}
function autoLocalForPcap(){
  localOverride=null; applyLocal(true);
  const present=packets.some(p=>p.src===SRV_LOCAL||p.dst===SRV_LOCAL);
  if(!SRV_LOCAL || !present){                           // capture faite sur une autre machine : on déduit le poste
    const g=inferNet(packets); if(g.ip) localOverride={ip:g.ip,gw:g.gw,auto:true};
  }
  applyLocal(true);
}
function refreshLocalViews(){ updatePathLabels(); drawSeqHead(); drawSeqBase(); drawPathBase(); if(mapHosts.length) mapDraw(); }
$('netinfo').onclick=()=>{
  const ip=prompt('IP du poste (le « client » des diagrammes). Laisser vide pour revenir au réglage automatique :',LOCAL_IP||'');
  if(ip===null) return;
  if(!ip.trim()){ localOverride=null; applyLocal(true); refreshLocalViews(); return; }
  const gw=prompt('IP de la passerelle (routeur) — facultatif :',GATEWAY||''); if(gw===null) return;
  localOverride={ip:ip.trim(),gw:(gw||'').trim()}; applyLocal(true); refreshLocalViews();
};

/* ================= Statut & polling ================= */
async function status(){
  try{
    const s=await (await fetch('/api/status?iface='+encodeURIComponent($('ifsel').value))).json();
    SRV_LOCAL=s.local_ip||''; SRV_GW=s.gateway||''; applyLocal(true);
    $('dot').classList.toggle('on',s.running);
    if(s.version) $('hver').textContent='v'+s.version;
    $('status').textContent=s.scapy?(s.running?'Capture en cours':'Prêt'):'⚠ scapy absent';
    $('bStart').disabled=s.running; $('bStop').disabled=!s.running; $('bV6').disabled=s.running; $('ifsel').disabled=s.running;
    updatePathLabels(); drawSeqHead();
    if(s.running) setTimeout(poll,600);
    else if(s.count>0 && seen===0) poll();                     // pcap déjà chargé au démarrage (rezolab.py fichier.pcap)
  }catch(e){ $('status').textContent='Serveur injoignable'; }
}
function row(p,n){
  const tr=document.createElement('tr');
  const dt=new Date(p.t*1000).toLocaleTimeString('fr',{hour12:false})+'.'+String(Math.floor((p.t%1)*1000)).padStart(3,'0');
  tr.innerHTML=`<td><span class="no ${esc(p.proto)}">${n}</span></td><td>${dt}</td><td>${esc(p.src)}${p.sport?':'+p.sport:''}</td><td>${esc(p.dst)}${p.dport?':'+p.dport:''}</td><td class="p-${esc(p.proto)}">${esc(p.proto)}</td><td>${p.len}</td><td>${esc(p.info)}</td>`;
  tr.title=`index capture : ${p.i+1}`;
  tr.onclick=()=>select(p,tr); return tr;
}
async function poll(){
  try{
    const r=await (await fetch('/api/packets?after='+seen)).json();
    if(epoch!==null && r.epoch!==epoch){ epoch=r.epoch; resetViews(); drawPathBase(); return poll(); }
    epoch=r.epoch;
    r.packets.forEach(p=>packets.push(p));
    seen=r.total;
    applyFilter();
    animateIncremental();
    const s=await (await fetch('/api/status?iface='+encodeURIComponent($('ifsel').value))).json();
    if(s.running) setTimeout(poll,600); else status();
  }catch(e){}
}

/* ================= Table : sélection & flux ================= */
function select(p,tr){
  document.querySelectorAll('#tbody tr').forEach(x=>x.classList.remove('sel')); if(tr)tr.classList.add('sel');
  selIdx=p.i; const d=$('detail'); d.style.display='block';
  d.innerHTML=`<h3>Paquet #${p.i} — ${esc(p.proto)}</h3>
  ${[['Heure',new Date(p.t*1000).toISOString()],['Source',p.src+(p.sport?':'+p.sport:'')],
     ['Destination',p.dst+(p.dport?':'+p.dport:'')],['Protocole',p.proto],['Longueur',p.len+' o'],['Info',p.info]]
    .map(([k,v])=>`<div class="kv"><span>${k}</span><span>${esc(v)}</span></div>`).join('')}
  ${p.proto==='TCP'?`<button class="act" style="margin-top:12px;width:100%" onclick="followStream()">Suivre le flux TCP</button>`:''}`;
}
let streamData=null, streamMode='asc';
async function followStream(){
  if(selIdx===null) return;
  let r;
  try{ r=await (await fetch('/api/stream/'+selIdx)).json(); }catch(e){ alert('Serveur injoignable'); return; }
  if(r.error){ alert(r.error); return; }
  streamData=r;
  streamMode = r.decoded ? 'dec' : (r.flow.clear ? 'asc' : (r.chunks.length ? 'hex' : 'pkt'));
  showTab('stream'); renderStream();
}
function hexdump(b64,off){
  const bin=atob(b64); let out='';
  for(let i=0;i<bin.length;i+=16){
    let hx='', as='';
    for(let k=0;k<16;k++){
      if(i+k<bin.length){ const c=bin.charCodeAt(i+k); hx+=c.toString(16).padStart(2,'0')+' '; as+=(c>=32&&c<127)?bin[i+k]:'.'; }
      else hx+='   ';
      if(k===7) hx+=' ';
    }
    out+=(off+i).toString(16).padStart(8,'0')+'  '+hx+' '+as+'\n';
  }
  return out;
}
function renderStream(){
  const r=streamData; if(!r) return;
  const f=r.flow, pre=$('pre'), info=$('stinfo'), mb=$('stmodes');
  info.textContent='';
  const l1=document.createElement('div');
  l1.textContent=`${f.client} → ${f.server} · ${f.label} · ${f.bytes_c2s} o envoyés / ${f.bytes_s2c} o reçus`;
  info.appendChild(l1);
  if(f.note){ const n=document.createElement('div'); n.className='stnote'+(f.clear?' warn':''); n.textContent=f.note; info.appendChild(n); }
  mb.textContent='';
  [...(r.decoded?[['dec','Décodé']]:[]),['asc','ASCII'],['hex','Hex'],['pkt','Paquets']].forEach(([k,l])=>{
    const b=document.createElement('button'); b.className='chip'+(k===streamMode?' on':''); b.textContent=l;
    b.onclick=()=>{ streamMode=k; renderStream(); }; mb.appendChild(b);
  });
  pre.textContent='';
  const secs=r.secrets||[];
  if(secs.length){                                   // encadré des secrets détectés
    const bx=document.createElement('div'); bx.className='secrets';
    const t=document.createElement('h4'); t.textContent='🔑 Identifiants / secrets détectés ('+secs.length+')'; bx.appendChild(t);
    secs.forEach(x=>{ const row=document.createElement('div'); row.className='sec-row';
      const k=document.createElement('span'); k.className='sec-k'; k.textContent=(x.d===1?'← ':'→ ')+x.kind;
      const v=document.createElement('span'); v.className='sec-v'; v.textContent=x.value; row.append(k,v); bx.appendChild(row); });
    pre.appendChild(bx);
  }
  const raws=[...new Set(secs.map(x=>x.raw).filter(x=>x&&x.length>1))];
  const reEsc=x=>x.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const rx=raws.length?new RegExp('('+raws.map(reEsc).join('|')+')'):null;
  const add=(d,t)=>{ const el=document.createElement('div'); el.className='sblk sd'+d;
    if(rx && streamMode!=='hex' && streamMode!=='pkt') t.split(rx).forEach((part,i)=>{
      if(i%2){ const m=document.createElement('mark'); m.textContent=part; el.appendChild(m); } else el.appendChild(document.createTextNode(part)); });
    else el.textContent=t;
    pre.appendChild(el); };
  if(streamMode==='dec') r.decoded.forEach(x=>add(x.d,x.t));
  else if(streamMode==='asc') r.chunks.forEach(c=>add(c.d,c.t));
  else if(streamMode==='hex'){
    const off=[0,0]; let budget=65536;
    for(const c of r.chunks){
      if(budget<=0){ add(0,'… (affichage hexadécimal limité à 64 Ko)'); break; }
      add(c.d,hexdump(c.b,off[c.d])); off[c.d]+=c.n; budget-=c.n;
    }
  } else {
    r.frames.forEach(fr=>{ const c=(fr.src+':'+fr.sport)===f.client; add(c?0:1,`#${fr.i} ${c?'→':'←'} ${fr.proto} ${fr.info}`); });
  }
  if(!pre.querySelector('.sblk')) add(0,'(aucune donnée applicative dans ce flux)');
}

/* ================= Onglets ================= */
function showTab(v){
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on',t.dataset.v===v));
  document.querySelectorAll('.view').forEach(x=>x.classList.toggle('on',x.id==='v-'+v));
  if(v==='path'){ drawPathBase(); }
  if(v==='seq') drawSeqBase();
  if(v==='map'){ mapV=-1; mapPoll(); }
}
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>showTab(t.dataset.v));

/* ================= Icônes isométriques (suivent le thème via CSS) ================= */
const slab=y=>`<path class="iso" d="M-22,${y+2}L0,${y+12}V${y+20}L-22,${y+10}Z"/><path class="iso" d="M22,${y+2}L0,${y+12}V${y+20}L22,${y+10}Z"/><path class="iso top" d="M0,${y-8}L22,${y+2}L0,${y+12}L-22,${y+2}Z"/><path class="iso fl" d="M4,${y+14}L16,${y+8}"/>`;
const ISO={
  laptop:'<path class="iso" d="M-30,12L0,26V31L-30,17Z"/><path class="iso" d="M30,12L0,26V31L30,17Z"/><path class="iso top" d="M0,-2L30,12L0,26L-30,12Z"/><path class="iso top" d="M-30,12L0,-2V-34L-30,-20Z"/><path class="iso fl" d="M-24,6L-6,-2V-27L-24,-17Z"/>',
  router:'<path class="iso" d="M-32,10L0,24V36L-32,22Z"/><path class="iso" d="M32,10L0,24V36L32,22Z"/><path class="iso top" d="M0,-4L32,10L0,24L-32,10Z"/><path class="iso fl" d="M20,3V-28"/><circle cx="20" cy="-30" r="2.5" class="iso"/><path class="iso fl" d="M6,31L14,27M18,25L26,21"/>',
  server:'<path class="iso" d="M-24,-24L0,-12V30L-24,18Z"/><path class="iso" d="M24,-24L0,-12V30L24,18Z"/><path class="iso top" d="M0,-36L24,-24L0,-12L-24,-24Z"/><path class="iso fl" d="M5,-2L19,-9M5,8L19,1M5,18L19,11"/>',
  rack:slab(14)+slab(-8)+slab(-30),
  cloud:'<path class="iso top" d="M-34,16 C-52,16 -52,-6 -32,-6 C-32,-28 -2,-34 8,-16 C28,-24 46,-6 36,10 C46,14 42,16 34,16 Z"/><circle class="iso fl" cx="2" cy="0" r="12"/><ellipse class="iso fl" cx="2" cy="0" rx="5" ry="12"/><path class="iso fl" d="M-10,0H14"/>',
  switch:'<path class="iso" d="M-34,8L0,24V32L-34,16Z"/><path class="iso" d="M34,8L0,24V32L34,16Z"/><path class="iso top" d="M0,-8L34,8L0,24L-34,8Z"/><path class="iso fl" d="M-18,14L-12,17M-8,19L-2,22M2,23L8,20"/>',
  nas:slab(6)+slab(-16),
  phone:'<path class="iso" d="M10,-14L15,-17V25L10,28Z"/><path class="iso top" d="M-16,-26L10,-14V28L-16,16Z"/><path class="iso fl" d="M-12,-21L6,-12.5V22L-12,13.5Z"/>',
  printer:'<path class="iso" d="M-30,6L0,20V34L-30,20Z"/><path class="iso" d="M30,6L0,20V34L30,20Z"/><path class="iso top" d="M0,-8L30,6L0,20L-30,6Z"/><path class="iso top" d="M-12,0L8,-10L18,-5L-2,5Z"/><path class="iso fl" d="M6,28L12,25"/>',
  camera:'<path class="iso" d="M-22,-3L0,8V24L-22,13Z"/><path class="iso" d="M22,-3L0,8V24L22,13Z"/><path class="iso top" d="M0,-14L22,-3L0,8L-22,-3Z"/><circle class="iso fl" cx="9" cy="14" r="6"/>',
  tv:'<path class="iso top" d="M-34,-3L34,31V-9L-34,-43Z"/><path class="iso fl" d="M-26,-9L26,17V-5L-26,-31Z"/><path class="iso fl" d="M0,34V40M-12,40L12,46"/>',
  iot:'<path class="iso" d="M-16,0L0,8V22L-16,14Z"/><path class="iso" d="M16,0L0,8V22L16,14Z"/><path class="iso top" d="M0,-8L16,0L0,8L-16,0Z"/><path class="iso fl" d="M-12,-18Q0,-28 12,-18M-6,-12Q0,-18 6,-12"/>',
  unknown:'<path class="iso" d="M-20,-8L0,2V30L-20,20Z"/><path class="iso" d="M20,-8L0,2V30L20,20Z"/><path class="iso top" d="M0,-18L20,-8L0,2L-20,-8Z"/><text x="10" y="18" style="font:700 16px monospace;fill:var(--acc)" text-anchor="middle">?</text>'
};
function isoIcon(k,x,y,sc){ return `<g transform="translate(${x},${y}) scale(${sc||.9})">${ISO[k]}</g>`; }

/* ================= Vue Chemin : couloirs aller/retour + DNS ================= */
const XP={pc:160,rt:420,srv:760,dns:1050};
const NODE_Y=215, YTOP=140, YBOT=290, DNS_OFF=24;      // DNS : couloirs « intérieurs » (branche distincte)
let dnsServers=new Set(), domainByIp={}, lastRemote='', lastDns='', dnsUsed=false;
let pathQ=[], pathBusy=false, pathGen=0;

function isRemote(h){ return !!h && h!==LOCAL_IP && h!==GATEWAY; }
function nodeOfPath(h){
  if(h===LOCAL_IP) return 'pc';
  if(h===GATEWAY)  return 'rt';
  if(dnsServers.has(h)) return 'dns';
  return 'srv';
}
/* Un échange DNS va toujours jusqu'au nœud DNS, même si le résolveur est le routeur lui-même */
function isOwnPtr(p){ return p.proto==='DNS' && /\.arpa\b/i.test(p.info||'') && $('bRdns').classList.contains('on'); }
function isDnsExchange(p){ return p.proto==='DNS' && p.sport!==5353 && p.dport!==5353; }
function dnsIsQuery(p){ return p.src===LOCAL_IP ? true : p.dst===LOCAL_IP ? false : p.sport!==53; }
function learnDns(p){
  if(p.proto!=='DNS') return;
  if(isDnsExchange(p) && !isOwnPtr(p)){
    dnsUsed=true; setPathViewBox(); document.querySelectorAll('.dnsg').forEach(e=>e.style.opacity=1);   // le résolveur apparaît à la 1re requête
    [p.src,p.dst].forEach(h=>{ if(isRemote(h)) dnsServers.add(h); });
  }
  (p.domains||[]).forEach(([n,ip])=>{ domainByIp[ip]=n; });
}
function pathNodes(p){
  if(isDnsExchange(p)) return dnsIsQuery(p) ? ['pc','dns'] : ['dns','pc'];
  return [nodeOfPath(p.src), nodeOfPath(p.dst)];
}
function noteRemote(p){
  if(isDnsExchange(p)) lastDns = dnsIsQuery(p) ? p.dst : p.src;
  else [p.src,p.dst].forEach(h=>{ if(nodeOfPath(h)==='srv') lastRemote=h; });
}
function updatePathLabels(){
  const set=(id,v)=>{const e=document.getElementById(id); if(e) e.textContent=v||'';};
  set('ip-pc',LOCAL_IP); set('ip-rt',GATEWAY);
  set('ip-srv',lastRemote); set('dom-srv',domainByIp[lastRemote]||'');
  set('ip-dns',lastDns);    set('dom-dns',domainByIp[lastDns]||'');
}
/* Disposition 2D : client — routeur — Internet — serveur / DNS ; deux voies par liaison (aller / retour) */
const NODES={pc:{x:170,y:390,t:'b'},rt:{x:450,y:285,t:'b'},net:{x:790,y:400,t:'b'},srv:{x:810,y:150,t:'t'},dns:{x:560,y:140,t:'t'}};
const UP={pc:null,rt:'pc',net:'rt',srv:'net',dns:'net'}, RANK={pc:0,rt:1,net:2,srv:3,dns:3}, LANE=7;
function rootPath(n){ const r=[]; for(; n; n=UP[n]) r.unshift(n); return r; }
function route(a,b){                                   // remonte à l'ancêtre commun puis redescend
  const ra=rootPath(a), rb=rootPath(b); let k=0;
  while(k<ra.length&&k<rb.length&&ra[k]===rb[k]) k++;
  return ra.slice(k-1).reverse().concat(rb.slice(k));
}
function pathChain(p){
  const [a,b]=pathNodes(p);
  if(a===b) return null;
  const chain=route(a,b), pts=[];
  for(let i=0;i<chain.length-1;i++){
    const f=NODES[chain[i]], t=NODES[chain[i+1]], dx=t.x-f.x, dy=t.y-f.y, L=Math.hypot(dx,dy)||1;
    const ox=-dy/L*LANE, oy=dx/L*LANE;                  // voie à droite du sens de marche
    pts.push([f.x+ox,f.y+oy],[t.x+ox,t.y+oy]);
  }
  return {d:'M '+pts.map(q=>q.map(Math.round).join(',')).join(' L '),
          col:RANK[a]<RANK[b]?'#2c4bd6':'#0b8f63', start:pts[0]};
}
function setPathViewBox(){ $('svpath').setAttribute('viewBox','0 0 1000 540'); }
function arrowLabel(p){
  const t=(p.info||p.proto||'').replace(/\s+\d+\s*>\s*\d+$/,'');       // retire « 5000 > 443 »
  return t.length>38?t.slice(0,37)+'…':t;
}
function drawPathBase(){
  const sv=$('svpath'); setPathViewBox();
  const lane=(f,t)=>{ const A=NODES[f], B=NODES[t], dx=B.x-A.x, dy=B.y-A.y, L=Math.hypot(dx,dy), ux=dx/L, uy=dy/L, ox=-uy*LANE, oy=ux*LANE, s=56, e=L-56;
    return `<line class="link" marker-end="url(#pah)" x1="${A.x+ux*s+ox}" y1="${A.y+uy*s+oy}" x2="${A.x+ux*e+ox}" y2="${A.y+uy*e+oy}"/>`; };
  const both=(f,t)=>lane(f,t)+lane(t,f);
  const lab=(k,name,dom)=>{ const n=NODES[k], y0=n.t==='t'?n.y-96:n.y+68;
    return `<text class="nodelabel" x="${n.x}" y="${y0}">${name}</text><text class="nodedim" x="${n.x}" y="${y0+16}" id="ip-${k}"></text>`
      +(dom?`<text class="domlab" x="${n.x}" y="${y0+32}" id="dom-${k}"></text>`:''); };
  const ic=(k,n,s)=>isoIcon(k,NODES[n].x,NODES[n].y,s||1.25);
  const dop=dnsUsed?1:0;
  sv.innerHTML=`<defs><marker id="pah" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto" markerUnits="userSpaceOnUse"><path d="M0,0L10,5L0,10Z" style="fill:var(--dim)"/></marker></defs>
  ${both('pc','rt')}${both('rt','net')}${both('net','srv')}
  <g class="dnsg" style="opacity:${dop}">${both('net','dns')}</g><g id="arrowsG"></g>
  ${ic('laptop','pc')}${ic('router','rt')}${ic('cloud','net',1.4)}${ic('server','srv')}
  <g class="dnsg" style="opacity:${dop}">${ic('rack','dns')}${lab('dns','Résolveur DNS',true)}</g>
  ${lab('pc','Client')}${lab('rt','Routeur')}${lab('net','Internet')}${lab('srv','Serveur',true)}`;
  updatePathLabels();
}
function flushPath(){
  pathGen++; pathQ.length=0; pathBusy=false;
  const g=$('arrowsG'); if(g) g.textContent='';      // plus aucune flèche résiduelle
}
function animPath(p,live){
  pathQ.push({p,live});
  if(pathQ.length>40) pathQ.splice(0,pathQ.length-40);   // évite un retard cumulatif en capture live
  pumpPath();
}
function fadeOut(grp){
  const t0=performance.now()+260;                    // la flèche reste lisible un instant, puis s'efface
  (function f(ts){
    const k=(ts-t0)/350;
    if(k<=0){ requestAnimationFrame(f); return; }
    if(k>=1){ grp.remove(); return; }
    grp.setAttribute('opacity',String(1-k));
    requestAnimationFrame(f);
  })(performance.now());
  setTimeout(()=>grp.remove(),1500);                 // garde-fou (onglet en arrière-plan)
}
function pumpPath(){
  if(pathBusy||!pathQ.length) return;
  const g=$('arrowsG');
  if(!g){ pathQ.length=0; return; }
  const {p,live}=pathQ.shift();
  const pc=pathChain(p);
  if(!pc){ pumpPath(); return; }
  noteRemote(p); updatePathLabels();
  const gen=pathGen;
  const grp=document.createElementNS(NS,'g');
  grp.setAttribute('opacity','0');                   // invisible tant que la tête n'est pas positionnée
  const trail=document.createElementNS(NS,'path');
  trail.setAttribute('d',pc.d); trail.setAttribute('fill','none');
  trail.setAttribute('stroke',pc.col); trail.setAttribute('stroke-width','2.5');
  trail.setAttribute('stroke-linejoin','round');
  const head=document.createElementNS(NS,'path');
  head.setAttribute('d','M0,-5 L11,0 L0,5 Z'); head.setAttribute('fill',pc.col);
  const dot=document.createElementNS(NS,'circle'); dot.setAttribute('cx',pc.start[0]); dot.setAttribute('cy',pc.start[1]); dot.setAttribute('r','4'); dot.setAttribute('fill',pc.col);
  const lbl=document.createElementNS(NS,'text'); lbl.setAttribute('class','arrlab'); lbl.setAttribute('fill',pc.col); lbl.textContent=arrowLabel(p);
  grp.appendChild(trail); grp.appendChild(dot); grp.appendChild(head); grp.appendChild(lbl); g.appendChild(grp);
  let L=0; try{ L=trail.getTotalLength(); }catch(e){}
  if(!L){ grp.remove(); pumpPath(); return; }       // vue non affichée : on n'anime pas
  trail.setAttribute('stroke-dasharray',L+' '+L);
  const place=cur=>{
    trail.setAttribute('stroke-dashoffset',L-cur);
    const p1=trail.getPointAtLength(Math.max(cur-3,0)), p2=trail.getPointAtLength(Math.min(cur+3,L));
    const pt=trail.getPointAtLength(cur);
    lbl.setAttribute('x',pt.x); lbl.setAttribute('y',pt.y-14);
    head.setAttribute('transform',`translate(${pt.x},${pt.y}) rotate(${Math.atan2(p2.y-p1.y,p2.x-p1.x)*180/Math.PI})`);
  };
  place(0); grp.setAttribute('opacity','1');
  pathBusy=true;
  const sp=parseFloat($('speed').value)||1;
  let dur=live?Math.max(L*0.9,300):Math.min(Math.max(L*0.9/sp,150),8000);
  if(pathQ.length>5) dur=Math.max(dur/(1+pathQ.length/5),120);    // rattrape le retard
  const t0=performance.now();
  (function fr(ts){
    if(gen!==pathGen){ grp.remove(); return; }
    const k=Math.max(0,Math.min((ts-t0)/dur,1)), e=1-Math.pow(1-k,2);
    place(L*e);
    if(k<1){ requestAnimationFrame(fr); return; }
    pathBusy=false; pumpPath();                      // la suivante démarre sans attendre l'effacement
    fadeOut(grp);
  })(t0);
}

/* ===== Noms des serveurs distants : DNS appris + DNS inverse (PTR) ===== */
const rdnsAsked=new Set(), rdnsQ=new Set(); let rdnsTimer=null;
function wantName(ip){
  if(!ip||domainByIp[ip]||rdnsAsked.has(ip)||!isRemote(ip)||!$('bRdns').classList.contains('on')) return;
  rdnsAsked.add(ip); rdnsQ.add(ip);
  if(!rdnsTimer) rdnsTimer=setTimeout(flushRdns,300);
}
async function flushRdns(){
  rdnsTimer=null; const ips=[...rdnsQ]; rdnsQ.clear();
  try{
    const r=await (await fetch('/api/rdns?ips='+encodeURIComponent(ips.join(',')))).json();
    Object.entries(r).forEach(([ip,n])=>{ if(n&&!domainByIp[ip]){ domainByIp[ip]=n; applyName(ip,n); } });
  }catch(e){}
}
function applyName(ip,n){
  updatePathLabels();
  (seqLabels.get(ip)||[]).forEach(({lb,port,tt})=>{
    let t=n+(port?':'+port:''); if(t.length>LABMAX) t=t.slice(0,LABMAX-1)+'…';
    lb.firstChild.nodeValue=t; lb.setAttribute('class','srvlab dom'); tt.textContent=ip+' ('+n+')';
  });
}
$('bRdns').onclick=()=>{ $('bRdns').classList.toggle('on'); refilterAll(); };
let rzT=null; window.addEventListener('resize',()=>{ clearTimeout(rzT); rzT=setTimeout(()=>{ drawSeqHead(); if($('v-seq').classList.contains('on')) drawSeqBase(); if($('v-map').classList.contains('on')) mapDraw(); },200); });

/* ================= Vue Séquence (en-tête fixe + défilement) ================= */
let SEQW=1100, XSEQ={pc:143,rt:396,srv:649}, XLAB=745, LABMAX=46; const ROW0=28, ROWH=28, MAXROWS=4000;
const seqLabels=new Map();
function layoutSeq(){                                   // occupe toute la largeur, texte ~1,3× plus grand
  const px=Math.max(document.querySelector('main').clientWidth-30,720);
  SEQW=Math.max(Math.round(px/1.3),820);                 // jamais plus étroit que 820 unités : les bulles ne se chevauchent pas
  XSEQ={pc:Math.round(SEQW*.15),rt:Math.round(SEQW*.40),srv:Math.round(SEQW*.65)};
  XLAB=XSEQ.srv+112; LABMAX=Math.max(18,Math.floor((SEQW-XLAB-6)/7.9));
}
let seqBusy=false, seqGen=0, seqRow=0, seqH=ROW0+ROWH, seqStick=true, lifeEls=[];
const seqQ=[];
function epOf(h,isDst,peer){
  if(h===LOCAL_IP) return 'pc';
  if(h===GATEWAY) return 'rt';
  if(isDst && /^255(\.255)*$/.test(h)) return peer==='pc'?'srv':'pc';
  if(!isDst && (/^0(\.0)*$/.test(h)||h==='::')) return 'pc';
  return 'srv';
}
function endpoints(p){
  let a=epOf(p.src,false,null), b=epOf(p.dst,true,a);
  if(a===b) b=(a==='pc')?'rt':(a==='rt')?'srv':'pc';
  return [a,b];
}
function peerOf(p){                                   // l'extrémité « distante » de la ligne
  if(p.src===LOCAL_IP||p.src===GATEWAY) return {ip:p.dst,port:p.dport};
  return {ip:p.src,port:p.sport};
}
function drawSeqHead(){
  const sv=$('svseqh'); if(!sv) return;
  layoutSeq(); sv.setAttribute('viewBox',`0 0 ${SEQW} 70`);
  const cols=[['pc','laptop','Client',LOCAL_IP],['rt','router','Routeur',GATEWAY],['srv','server','Serveur','']];
  sv.innerHTML=cols.map(([k,ic,n,ip])=>`<rect class="bubble" x="${XSEQ[k]-92}" y="8" width="184" height="54" rx="2"/>
    ${isoIcon(ic,XSEQ[k]-66,35,.38)}
    <text class="nodelabel" x="${XSEQ[k]+12}" y="29">${n}</text>
    <text class="nodedim" x="${XSEQ[k]+12}" y="49">${esc(ip||'')}</text>`).join('')
    +`<text class="srvhd" x="${XLAB}" y="39">Adresse / domaine distant</text>`;
}
function drawSeqBase(){
  const sv=$('svseq'), sc=$('v-seq');
  flushSeq(); layoutSeq(); seqLabels.clear();
  const keep=sc.scrollTop;
  seqRow=0; seqH=ROW0+ROWH;
  sv.setAttribute('viewBox',`0 0 ${SEQW} ${seqH}`);
  sv.innerHTML=`<defs>
    <marker id="ah" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0L6,3L0,6Z" fill="#2c4bd6"/></marker>
    <marker id="ah2" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0L6,3L0,6Z" fill="#0b8f63"/></marker>
  </defs>`+['pc','rt','srv'].map(k=>`<line class="blife" id="life-${k}" x1="${XSEQ[k]}" y1="0" x2="${XSEQ[k]}" y2="${seqH}"/>`).join('');
  lifeEls=['pc','rt','srv'].map(k=>document.getElementById('life-'+k));
  seqHistory.slice(-MAXROWS).forEach(p=>seqFinish(seqAddRow(p)));
  sc.scrollTop = seqStick ? sc.scrollHeight : keep;
}
function ensureSeqH(need){
  if(need<=seqH) return;
  seqH=need;
  $('svseq').setAttribute('viewBox',`0 0 ${SEQW} ${seqH}`);
  lifeEls.forEach(l=>l&&l.setAttribute('y2',seqH));
}
function seqAddRow(p){
  const sv=$('svseq'); if(!sv) return null;
  const [a,b]=endpoints(p);
  const y=ROW0+seqRow*ROWH; seqRow++;
  ensureSeqH(y+ROWH);
  const x1=XSEQ[a], x2=XSEQ[b], local=(a==='pc'||a==='rt');
  const ln=document.createElementNS(NS,'line');
  ln.setAttribute('x1',x1); ln.setAttribute('y1',y); ln.setAttribute('x2',x1); ln.setAttribute('y2',y);
  ln.setAttribute('class','msg'+(local?'':' rt'));
  const tx=document.createElementNS(NS,'text');
  tx.setAttribute('class','msgtxt'+(local?'':' rt')); tx.setAttribute('y',y-5); tx.setAttribute('opacity',0);
  tx.setAttribute('x',Math.min(x1,x2)+8); tx.setAttribute('text-anchor','start');      // toujours lisible, jamais coupé à gauche
  tx.textContent=(p.info||p.proto||'').slice(0,50);
  const peer=peerOf(p), name=domainByIp[peer.ip];       // domaine si connu (réponses DNS), sinon IP
  let label=(name||peer.ip||'?')+(peer.port?':'+peer.port:'');
  if(label.length>LABMAX) label=label.slice(0,LABMAX-1)+'…';
  const lb=document.createElementNS(NS,'text');
  lb.setAttribute('class','srvlab'+(name?' dom':'')); lb.setAttribute('x',XLAB); lb.setAttribute('y',y+4);
  lb.setAttribute('opacity',0);
  lb.textContent=label;
  const tt=document.createElementNS(NS,'title'); tt.textContent=peer.ip+(name?` (${name})`:''); lb.appendChild(tt);
  (seqLabels.get(peer.ip)||seqLabels.set(peer.ip,[]).get(peer.ip)).push({lb,port:peer.port,tt});
  const dt=document.createElementNS(NS,'circle'); dt.setAttribute('cx',x1); dt.setAttribute('cy',y); dt.setAttribute('r','3'); dt.setAttribute('fill',local?'#2c4bd6':'#0b8f63');
  sv.appendChild(ln); sv.appendChild(dt); sv.appendChild(tx); sv.appendChild(lb);
  return {ln,tx,lb,x1,x2};
}
function seqFinish(r){
  if(!r) return;
  r.ln.setAttribute('x2',r.x2); r.tx.setAttribute('opacity',1); r.lb.setAttribute('opacity',1);
}
function addSeqMsg(p,animate){ seqQ.push({p,animate}); pumpSeq(); }
function pumpSeq(){
  if(seqBusy||!seqQ.length) return;
  const {p,animate}=seqQ.shift();
  const gen=seqGen, r=seqAddRow(p);
  if(!r){ pumpSeq(); return; }
  const sc=$('v-seq');
  if(seqStick) sc.scrollTop=sc.scrollHeight;            // suit le flux tant qu'on est en bas
  if(!animate || seqQ.length>6){ seqFinish(r); pumpSeq(); return; }   // gros volume : sans animation
  seqBusy=true;
  const sp=parseFloat($('speed').value)||1;
  const dur=Math.min(Math.max(420/sp,150),5000);
  const t0=performance.now();
  (function fr(ts){
    if(gen!==seqGen) return;
    const k=Math.max(0,Math.min((ts-t0)/dur,1)), e=1-Math.pow(1-k,2);
    r.ln.setAttribute('x2',r.x1+(r.x2-r.x1)*e);
    r.tx.setAttribute('opacity',Math.min(k*5,1)); r.lb.setAttribute('opacity',Math.min(k*5,1));
    if(k>=1){ seqBusy=false; pumpSeq(); }
    else requestAnimationFrame(fr);
  })(t0);
}
function flushSeq(){ seqGen++; seqQ.length=0; seqBusy=false; }
$('v-seq').addEventListener('scroll',()=>{
  const s=$('v-seq'); seqStick=(s.scrollTop+s.clientHeight>=s.scrollHeight-30);
});

/* Répartit chaque paquet vers les vues concernées */
function animatePacket(p,live){
  learnDns(p); wantName(p.src); wantName(p.dst); updatePathLabels();
  if(!matchFilter(p)) return;
  seqHistory.push(p);
  if($('v-seq').classList.contains('on')) addSeqMsg(p,true);
  if($('v-path').classList.contains('on')) animPath(p,live);
}
function animateIncremental(){
  for(; lastAnimated<packets.length; lastAnimated++) animatePacket(packets[lastAnimated],true);
}

/* ================= Replay ================= */
function pause(){ playing=false; clearTimeout(playTimer); $('bPlay').textContent='▶ Lire'; }
$('bPlay').onclick=()=>{
  if(playing){ pause(); return; }
  if(disp.length===0){ $('pos').textContent='0 / 0 — rien à lire'; return; }
  if(playIdx>=disp.length) playIdx=0;
  if(seqHistory.length>playIdx) seqHistory=disp.slice(0,playIdx);
  playing=true; $('bPlay').textContent='⏸ Pause';
  drawSeqBase(); tick();
};
$('bRestart').onclick=()=>{
  pause(); playIdx=0; seqHistory=[];
  flushSeq(); flushPath();
  $('prog').value=0;
  $('pos').textContent='0 / '+disp.length;
  drawSeqBase();
  if(disp.length>0){ playing=true; $('bPlay').textContent='⏸ Pause'; tick(); }
};
function tick(){
  if(!playing) return;
  if(playIdx>=disp.length){ pause(); return; }
  const p=disp[playIdx];
  const sp=parseFloat($('speed').value)||1;
  const prev=playIdx>0?disp[playIdx-1]:null;
  const delay=Math.min(prev?Math.max((p.t-prev.t)/sp*1000,60):0,60000);
  playTimer=setTimeout(()=>{
    animatePacket(p,false);
    playIdx++;
    $('prog').value=playIdx;
    $('pos').textContent=playIdx+' / '+disp.length;
    tick();
  },delay);
}
$('prog').oninput=e=>{
  pause(); playIdx=+e.target.value;
  seqHistory=disp.slice(0,playIdx);
  flushSeq(); flushPath();
  $('pos').textContent=playIdx+' / '+disp.length;
  drawSeqBase();
};

/* ================= Contrôles ================= */
document.querySelectorAll('.chip[data-p]').forEach(c=>c.onclick=()=>{ c.classList.toggle('on'); refilterAll(); });
$('bV6').onclick=()=>{ $('bV6').classList.toggle('on'); refilterAll(); };
$('ipf').addEventListener('keydown',e=>{ if(e.key==='Enter') refilterAll(); });

function resetViews(){
  pause(); playIdx=0; lastAnimated=0;
  packets=[]; disp=[]; seen=0; seqHistory=[];
  dnsServers=new Set(); domainByIp={}; lastRemote=''; lastDns=''; dnsUsed=false; rdnsAsked.clear(); dnsUsed=false;
  flushSeq(); flushPath();
  $('tbody').innerHTML='';
  $('detail').innerHTML='<h3>Vue d\'ensemble</h3><p class="dim">Cliquez sur un paquet pour voir son détail.</p>';
  $('prog').value=0; $('prog').max=0; $('pos').textContent='0 / 0';
  drawSeqBase();
}
$('bStart').onclick=async()=>{
  const protos=[...document.querySelectorAll('.chip.on[data-p]')].map(c=>c.dataset.p);
  resetViews();
  drawPathBase();
  localOverride=null; applyLocal(true);
  const r=await (await fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({protocols:protos,host:$('ipf').value,iface:$('ifsel').value,ipv6:$('bV6').classList.contains('on')})})).json();
  if(r.error) alert(r.error);
  status();
};
$('bStop').onclick=async()=>{ await fetch('/api/stop',{method:'POST'}); status(); };
$('bClear').onclick=async()=>{
  await fetch('/api/clear',{method:'POST'});
  resetViews(); drawPathBase();
  localOverride=null; applyLocal();
};
const PCAP_MAGIC=['d4c3b2a1','a1b2c3d4','4d3cb2a1','a1b23c4d','0a0d0d0a'];          // pcap (4 variantes) et pcapng
async function pcapLoaded(r,name){
  resetViews(); drawPathBase();
  await poll();
  await status();
  autoLocalForPcap(); refreshLocalViews();               // le poste peut ne pas être cette machine
  $('pos').textContent='0 / '+disp.length;
  $('status').textContent='Pcap chargé : '+name+' — '+r.count+' paquets'+(r.warning?' — ⚠ '+r.warning:'');
  if(disp.length) $('bRestart').click();                                            // lecture animée automatique
  else alert('Pcap chargé ('+r.count+' paquets) mais tous masqués par les filtres : décochez des protocoles à gauche.');
}
/* Chargement par chemin : le fichier est lu par RézoLab lui-même (utile si le navigateur ne peut pas le lire : Firefox Snap/Flatpak...) */
async function pcapByPath(name){
  let last=''; try{ last=localStorage.getItem('rz_pcap_path')||''; }catch(e){}
  const path=prompt('Chemin complet du fichier pcap / pcapng sur cette machine\n(ex. /home/vous/Téléchargements/'+(name||'capture.pcap')+') :',last||(name?'':'')); 
  if(!path||!path.trim()) return;
  try{ localStorage.setItem('rz_pcap_path',path.trim()); }catch(e){}
  $('status').textContent='Import de '+path.trim()+'…';
  try{
    const r=await (await fetch('/api/pcap_path',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path.trim()})})).json();
    if(r.error){ alert('Erreur pcap : '+r.error); status(); } else await pcapLoaded(r,r.name||path);
  }catch(err){ alert('Import impossible : '+err.name+' — '+err.message); status(); }
}
$('bPcapPath').onclick=()=>pcapByPath();
$('pcapf').onchange=async e=>{
  const f=e.target.files[0]; if(!f) return;
  try{
    // 1) le navigateur peut-il lire le fichier ? (droits, dossier inaccessible Snap/Flatpak, particularité de Firefox...)
    let head;
    try{ head=new Uint8Array(await f.slice(0,4).arrayBuffer()); }
    catch(err){
      if(confirm('Le navigateur n\'a pas pu lire « '+f.name+' » ('+err.name+').\n\nCauses fréquentes : navigateur Snap/Flatpak sans accès à ce dossier, ou fichier créé avec sudo.\n\n'
        +'Voulez-vous indiquer son chemin ? RézoLab, qui tourne sur cette machine, le lira directement.')) await pcapByPath(f.name);
      return;
    }
    const hex=[...head].map(b=>b.toString(16).padStart(2,'0')).join('');
    if(!PCAP_MAGIC.includes(hex) && !confirm('« '+f.name+' » ne ressemble pas à un fichier pcap/pcapng (signature '+hex+').\nEssayer quand même ?')) return;
    // 2) envoi en flux (le fichier n'est pas chargé en mémoire par la page)
    $('status').textContent='Import de '+f.name+' ('+(f.size/1048576).toFixed(1)+' Mo)…';
    const resp=await fetch('/api/pcap?name='+encodeURIComponent(f.name),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:f});
    let r; try{ r=await resp.json(); }catch(_){ r={error:'réponse invalide du serveur (HTTP '+resp.status+')'}; }
    if(r.error) alert('Erreur pcap : '+r.error); else await pcapLoaded(r,f.name);
  }catch(err){
    if(confirm('Envoi impossible : '+err.name+' — '+err.message+'\n\nVoulez-vous plutôt indiquer le chemin du fichier ? RézoLab le lira directement, sans passer par le navigateur.')) await pcapByPath(f.name);
  }
  finally{ e.target.value=''; }
};

/* ================= Init ================= */
drawPathBase(); drawSeqHead(); drawSeqBase();
(function(){ const r=document.documentElement; let t='dark';
  try{ t=localStorage.getItem('nl_theme')||t; }catch(e){}
  const apply=()=>{ r.dataset.theme=t; $('bTheme').textContent=t==='dark'?'☀':'☾'; };
  $('bTheme').onclick=()=>{ t=t==='dark'?'light':'dark'; try{localStorage.setItem('nl_theme',t);}catch(e){} apply(); };
  apply(); })();
async function loadIfaces(){
  try{
    const r=await (await fetch('/api/ifaces')).json(), sel=$('ifsel');
    sel.options[0].textContent='Interface : auto'+(r.auto?' ('+r.auto+')':'');
    r.ifaces.forEach(i=>{ const o=document.createElement('option'); o.value=i.name;
      o.textContent=(i.label||i.name)+(i.ip?' — '+i.ip:'')+(i.virtual?' (virtuelle)':''); sel.appendChild(o); });
    try{ const v=localStorage.getItem('nl_iface'); if(v&&[...sel.options].some(o=>o.value===v)) sel.value=v; }catch(e){}
  }catch(e){}
  status();
}
$('ifsel').onchange=()=>{ try{localStorage.setItem('nl_iface',$('ifsel').value);}catch(e){} lastRemote=''; lastDns=''; status(); };
loadIfaces();
(function(){ const b=document.body; let saved='';
  try{ saved=localStorage.getItem('nl_layout')||''; }catch(e){}
  document.querySelectorAll('[data-hide]').forEach(btn=>{
    const k=btn.dataset.hide; if(saved.split(' ').includes('hide-'+k)){ b.classList.add('hide-'+k); btn.classList.remove('on'); }
    btn.onclick=()=>{ b.classList.toggle('hide-'+k); btn.classList.toggle('on',!b.classList.contains('hide-'+k));
      try{ localStorage.setItem('nl_layout',[...b.classList].filter(c=>c.startsWith('hide-')).join(' ')); }catch(e){}
      setTimeout(()=>window.dispatchEvent(new Event('resize')),60);   // le centre se réajuste / se redessine
    };
  });
  setTimeout(()=>window.dispatchEvent(new Event('resize')),100);
})();
/* ================= Cartographie : passive (capture) + active (scan scapy) ================= */
let mapZoom=1, mapPan={x:0,y:0}, mapBase=300, mapDragged=false, mapAsp=1.6;
function applyView(){ const sy=2*mapBase/mapZoom, sx=sy*mapAsp; $('svmap').setAttribute('viewBox',`${mapPan.x-sx/2} ${mapPan.y-sy/2} ${sx} ${sy}`); }
let mapV=-1, mapHosts=[], mapSlots=new Map(), mapPopped=new Set(), mapSel=null, mapLocal='', mapGw='';
const TYPES={router:'Routeur / passerelle',switch:'Switch / borne Wi-Fi',server:'Serveur',nas:'NAS',laptop:'Ordinateur',phone:'Smartphone / tablette',printer:'Imprimante',camera:'Caméra',tv:'TV / média',iot:'Objet connecté',unknown:'Inconnu'};
const SVC={21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',111:'rpc',135:'msrpc',139:'netbios',143:'imap',443:'https',445:'smb',515:'lpd',554:'rtsp',631:'ipp',993:'imaps',995:'pop3s',1723:'pptp',3306:'mysql',3389:'rdp',5000:'upnp/nas',5432:'postgres',5900:'vnc',8008:'cast',8009:'cast',8080:'http-alt',8443:'https-alt',9100:'impression',62078:'iphone'};
let OV={}; try{ OV=JSON.parse(localStorage.getItem('nl_types')||'{}'); }catch(e){}
function guessType(h){                                  // déduction : nom, fabricant (OUI), ports ouverts
  const t=((h.name||'')+' '+(h.vendor||'')).toLowerCase(), P=new Set(h.ports||[]), has=(...k)=>k.some(x=>t.includes(x));
  if(has('iphone','ipad','android','galaxy','pixel','oneplus','xiaomi','redmi','oppo','huawei')) return 'phone';
  if(has('print','epson','canon','brother','laserjet','officejet','xerox','lexmark')||P.has(9100)||P.has(631)||P.has(515)) return 'printer';
  if(has('cam','hikvision','dahua','reolink','axis','wyze')||P.has(554)) return 'camera';
  if(has('synology','qnap','diskstation','nas','wdmycloud')) return 'nas';
  if(has('roku','chromecast','bravia','sonos','playstation','xbox','nintendo','apple tv','lg elec','samsung tv','tv')||P.has(8008)||P.has(8009)) return 'tv';
  if(has('cisco','ubiquiti','tp-link','tplink','netgear','zyxel','mikrotik','d-link','aruba','ruckus','sagemcom','freebox','livebox')) return 'switch';
  if(has('raspberry','espressif','tuya','shelly','philips','sonoff','nest','arduino')) return 'iot';
  if(has('dell','lenovo','hewlett','asus','acer','msi','intel','microsoft','macbook','imac','laptop','desktop','windows','apple')||P.has(3389)||P.has(135)) return 'laptop';
  if((h.vendor||'')==='MAC aléatoire') return 'phone';       // adresse aléatoire : typique d'un téléphone
  if(P.has(22)||P.has(80)||P.has(443)||P.has(3306)||P.has(445)) return 'server';
  return 'unknown';
}
const autoType=h=>h.ip===mapGw?'router':h.ip===mapLocal?'laptop':guessType(h);
const typeOf=h=>OV[h.mac||h.ip]||autoType(h);
const showUnc=()=>$('bShowUnc').classList.contains('on');
function slotPos(i,asp){                                   // anneaux concentriques, position stable par ordre d'apparition
  let r=0, k=i;
  for(;;r++){ const R=240+200*r, cap=Math.max(6,Math.floor(2*Math.PI*R*Math.sqrt((asp*asp+1)/2)/200));
    if(k<cap){ const a=-Math.PI/2+2*Math.PI*k/cap+r*0.35; return {x:R*asp*Math.cos(a), y:R*Math.sin(a), R}; }
    k-=cap; }
}
function mapNode(h,x,y,sc){
  const me=h.ip===mapLocal, type=typeOf(h), pop=mapPopped.has(h.ip)?'':' pop'; mapPopped.add(h.ip);
  const unc=(h.confirmed===false&&h.ip!==mapGw&&!me)?' unc':'', ps=h.ports||[];
  const ports=[...new Set(ps.slice(0,5).map(p=>SVC[p]||p))].join('·')+(ps.length>5?'…':''), nm=h.name||TYPES[type], b=Math.round(52*sc);
  return `<g class="mnode${pop}${unc}${mapSel===h.ip?' sel':''}" data-ip="${esc(h.ip)}" transform="translate(${x.toFixed(0)},${y.toFixed(0)})">
    ${me?'<circle class="selfring" r="54"/>':''}${mapSel===h.ip?'<circle class="selring" r="58"/>':''}
    ${isoIcon(type,0,0,sc)}<text class="mlab" y="${b+10}">${esc(h.ip)}${me?' (vous)':''}</text>
    <text class="mdim" y="${b+25}">${esc(nm.length>22?nm.slice(0,21)+'…':nm)}</text>
    ${ports?`<text class="mdim mport" y="${b+40}">${esc(ports)}</text>`:''}</g>`;
}
function mapDraw(){
  const sv=$('svmap'), hs=mapHosts.filter(h=>h.ip!==mapGw&&(h.confirmed!==false||showUnc()));
  hs.forEach(h=>{ if(!mapSlots.has(h.ip)) mapSlots.set(h.ip,mapSlots.size); });
  const rc=sv.getBoundingClientRect(); mapAsp=rc.height>20?Math.max(1,Math.min(2.4,rc.width/rc.height)):1.6;   // carte adaptée au format du panneau
  let maxR=240; const pos={};
  hs.forEach(h=>{ const p=slotPos(mapSlots.get(h.ip),mapAsp); pos[h.ip]=p; maxR=Math.max(maxR,p.R); });
  mapBase=maxR+110; applyView();
  let links='', nodes='';
  hs.forEach(h=>{ const p=pos[h.ip]; links+=`<line class="link" x1="0" y1="0" x2="${p.x.toFixed(0)}" y2="${p.y.toFixed(0)}"/>`; nodes+=mapNode(h,p.x,p.y,1,h.kind); });
  const gw=mapHosts.find(h=>h.ip===mapGw)||(mapGw?{ip:mapGw,ports:[]}:null);
  sv.innerHTML=links+nodes+(gw?mapNode(gw,0,0,1.2,'router'):'')
    +((!hs.length&&!gw)?'<text class="mdim" x="0" y="0" style="font-size:15px">Aucune machine : lancez une capture (passif) ou un scan.</text>':'');
  sv.querySelectorAll('.mnode').forEach(g=>g.onclick=()=>{ if(!mapDragged) mapSelect(g.dataset.ip); });
}
function mapSelect(ip){
  mapSel=ip; const h=mapHosts.find(x=>x.ip===ip)||{ip}, key=h.mac||h.ip;
  const ps=(h.ports||[]).map(p=>SVC[p]?`${p} (${SVC[p]})`:p).join(', ');
  $('detail').innerHTML=`<h3>${esc(h.ip)}</h3>`+[['Nom',h.name],['MAC',h.mac],['Fabricant',h.vendor],['Ports ouverts',ps],
    ['Découverte',(h.via||[]).join(' + ')],['État',h.confirmed===false?'non confirmée (cache ARP, peut être éteinte)':'active']]
    .map(([k,v])=>`<div class="kv"><span>${k}</span><span>${esc(v||'—')}</span></div>`).join('')
    +'<div class="kv"><span>Type</span><select id="typeSel"></select></div>';
  const sel=$('typeSel');
  sel.innerHTML=`<option value="">Auto (${esc(TYPES[autoType(h)])})</option>`+Object.entries(TYPES).map(([k,v])=>`<option value="${k}">${esc(v)}</option>`).join('');
  sel.value=OV[key]||'';
  sel.onchange=()=>{ if(sel.value) OV[key]=sel.value; else delete OV[key];
    try{ localStorage.setItem('nl_types',JSON.stringify(OV)); }catch(e){} mapDraw(); };
  mapDraw();
}
function mapStatus(s,n){
  $('bScan').disabled=s.running; $('bScanStop').disabled=!s.running;
  $('scanInfo').textContent=(s.error?'⚠ '+s.error:(s.running?`${s.phase} ${s.done}/${s.total}`:(s.phase||'Prêt')))+` — ${n} machine(s)`+(s.cidr?` · ${s.cidr}`:'')+(s.iface?` · ${s.iface}`:'')+(s.replies!==undefined&&s.iface?` · ${s.replies} réponse(s) ARP`:'')+(s.note?' — ⚠ '+s.note:'');
}
async function mapPoll(){
  if(!$('v-map').classList.contains('on')) return;
  try{
    const r=await (await fetch('/api/hosts?v='+mapV+'&iface='+encodeURIComponent($('ifsel').value))).json();
    mapGw=GATEWAY; mapLocal=LOCAL_IP;
    if(r.hosts){ mapHosts=r.hosts; mapV=r.v; mapDraw(); }
    mapStatus(r.scan,mapHosts.length);
  }catch(e){}
}
setInterval(mapPoll,1000);
$('bScan').onclick=async()=>{
  try{
    const r=await (await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({iface:$('ifsel').value,cidr:$('scanCidr').value.trim(),ports:$('scanPorts').value.trim()})})).json();
    if(r.error) $('scanInfo').textContent='⚠ '+r.error;
  }catch(e){ $('scanInfo').textContent='⚠ serveur injoignable'; }
  mapPoll();
};
$('bShowUnc').onclick=()=>{ $('bShowUnc').classList.toggle('on'); mapDraw(); };
$('bScanStop').onclick=()=>fetch('/api/scan/stop',{method:'POST'});
$('bMapClear').onclick=async()=>{ await fetch('/api/hosts/clear',{method:'POST'}); mapSlots.clear(); mapPopped.clear(); mapSel=null; mapV=-1; mapPoll(); };
(function(){ const sv=$('svmap'); let drag=null;
  sv.addEventListener('wheel',e=>{ e.preventDefault(); mapZoom=Math.min(6,Math.max(.5,mapZoom*(e.deltaY<0?1.15:1/1.15))); applyView(); },{passive:false});
  sv.addEventListener('mousedown',e=>{ drag={x:e.clientX,y:e.clientY,moved:false}; });
  window.addEventListener('mousemove',e=>{ if(!drag) return;
    const dx=e.clientX-drag.x, dy=e.clientY-drag.y;
    if(!drag.moved && Math.hypot(dx,dy)<4) return;
    drag.moved=true; mapDragged=true;
    const r=sv.getBoundingClientRect(), u=(2*mapBase/mapZoom)/r.height;
    mapPan.x-=dx*u; mapPan.y-=dy*u; drag.x=e.clientX; drag.y=e.clientY; applyView(); });
  window.addEventListener('mouseup',()=>{ if(drag&&drag.moved) setTimeout(()=>{ mapDragged=false; },0); drag=null; });
  sv.addEventListener('dblclick',()=>{ mapZoom=1; mapPan={x:0,y:0}; applyView(); });   // double-clic : recentrer
})();
(function(){ const o=$('help');
  const open=()=>{ o.classList.add('on'); o.setAttribute('aria-hidden','false'); $('hclose').focus(); };
  const close=()=>{ o.classList.remove('on'); o.setAttribute('aria-hidden','true'); $('bHelp').focus(); };
  $('bHelp').onclick=open; $('hclose').onclick=close;
  o.addEventListener('mousedown',e=>{ if(e.target===o) close(); });
  document.addEventListener('keydown',e=>{ if(e.key==='Escape'&&o.classList.contains('on')) close(); });
})();

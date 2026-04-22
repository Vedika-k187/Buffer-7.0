'use strict';

/* ─── WHITELIST — domains that should never be flagged suspicious ── */
const SAFE_DOMAINS = new Set([
  'google.com','www.google.com','mail.google.com','accounts.google.com',
  'fonts.googleapis.com','fonts.gstatic.com','ssl.gstatic.com','www.gstatic.com',
  'lh3.google.com','lh3.googleusercontent.com','play.google.com','ogs.google.com',
  'history.google.com','www.google-analytics.com','www.googleadservices.com',
  'www.googletagmanager.com','googleads.g.doubleclick.net','static.doubleclick.net',
  'beacons.gcp.gvt2.com','ogads-pa.clients6.google.com','securetoken.googleapis.com',
  'identitytoolkit.googleapis.com','google-ohttp-relay-safebrowsing.fastly-edge.com',
  'www.youtube.com','i.ytimg.com','youtube.com',
  'microsoft.com','edge.microsoft.com','graph.microsoft.com','login.live.com',
  'settings-win.data.microsoft.com','mobile.events.data.microsoft.com',
  'ic3.events.data.microsoft.com','msedge.b.tlu.dl.delivery.mp.microsoft.com',
  'prod.rewardsplatform.microsoft.com','substrate.office.com',
  'edge-consumer-static.azureedge.net','default.exp-tas.com','main.vscode-cdn.net',
  'aks-prod-southeastasia.access-point.cloudmessaging.edge.microsoft.com',
  'www.bing.com','th.bing.com','c.bing.com','ntp.msn.com','c.msn.com',
  'assets.msn.com','api.msn.com','img-s-msn-com.akamaized.net',
  'claude.ai','anthropic.com',
  'chatgpt.com','ws.chatgpt.com','openai.com',
  'web.whatsapp.com','whatsapp.com',
  'telemetry.individual.githubcopilot.com','github.com','api.github.com',
  'unleash.codeium.com','server.codeium.com',
  'unpkg.com','cdn.jsdelivr.net','cdn.socket.io','cdnjs.cloudflare.com',
  'sb.scorecardresearch.com','wokwi.com','thumbs.wokwi.com',
  'threat.api.mcafee.com','browser-intake-us5-datadoghq.com',
  'phishing-detection.api.cx.metamask.io','client-side-detection.api.cx.metamask.io',
  '196263-ipv4fdsmte.gr.global.aa-rt.sharepoint.com',
]);

/* Patterns that are ALWAYS suspicious */
const SUSPICIOUS_PATTERNS = [
  /evil/i, /malware/i, /c2/i, /botnet/i, /exploit/i,
  /attacker/i, /ransomware/i, /trojan/i, /backdoor/i, /\.tk$/i,
];

function isTrulySuspicious(domain, severity, score) {
  if (!domain) return false;
  if (SUSPICIOUS_PATTERNS.some(p => p.test(domain))) return true;
  const base = domain.split('.').slice(-2).join('.');
  if (SAFE_DOMAINS.has(domain) || SAFE_DOMAINS.has(base)) return false;
  return score >= 50 && (severity === 'HIGH' || severity === 'CRITICAL');
}

function displaySeverity(domain, severity, score) {
  return isTrulySuspicious(domain, severity, score) ? severity : 'LOW';
}

function displayScore(domain, score) {
  return SAFE_DOMAINS.has(domain) ? Math.min(score, 15) : score;
}

/* ─── SUSPICIOUS DOMAIN ALERT ────────────────────────────────── */
let _alertedDomains = new Set();

function checkAndAlert(domain, score, severity) {
  if (_alertedDomains.has(domain)) return;
  if (!isTrulySuspicious(domain, severity, score)) return;
  _alertedDomains.add(domain);

  const banner = document.getElementById('alert-banner');
  const text   = document.getElementById('alert-banner-text');
  if (banner && text) {
    text.textContent = `⚠ SUSPICIOUS DOMAIN: ${domain} — Score ${score} (${severity})`;
    banner.classList.remove('hidden');
  }

  if (window.Notification && Notification.permission === 'granted') {
    new Notification('DNSGuard — Suspicious Domain', {
      body: `${domain}\nScore: ${score} | ${severity}`,
    });
  }
  console.warn(`[ALERT] ${domain} score=${score} sev=${severity}`);
}

if (window.Notification && Notification.permission === 'default') {
  Notification.requestPermission();
}

/* ─── CLOCK ─────────────────────────────────────────────────── */
function updateClock() {
  const d = new Date(), pad = n => String(n).padStart(2,'0');
  const el = document.getElementById('clock');
  if (el) el.textContent = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}
setInterval(updateClock, 1000);
updateClock();

/* ─── SIDEBAR NAV ───────────────────────────────────────────── */
const SECTION_NAMES = {
  overview:'Dashboard', livefeed:'Live Feed', threats:'Threat Alerts',
  timeline:'Attack Timeline', activity:'Activity Chart',
  graph:'Domain Graph', map:'Geo Threat Map'
};
let currentSection = 'overview';

function switchSection(id) {
  document.querySelectorAll('.section-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const panel = document.getElementById('section-' + id);
  if (panel) panel.classList.add('active');
  const navItem = document.querySelector(`.nav-item[data-section="${id}"]`);
  if (navItem) navItem.classList.add('active');
  const bc = document.getElementById('topbar-section-name');
  if (bc) bc.textContent = SECTION_NAMES[id] || id;
  currentSection = id;
  if (id === 'graph')      setTimeout(loadGraph, 50);
  if (id === 'map')        setTimeout(loadProtonMap, 80);
  
  if (id === 'timeline')   loadTimeline();
  if (id === 'activity')   loadActivityChartFull();
  if (id === 'threats')    loadThreatsFull();
  if (id === 'livefeed')   loadLiveFeedFull();
}
document.querySelectorAll('.nav-item[data-section]').forEach(item => {
  item.addEventListener('click', () => switchSection(item.dataset.section));
});

/* ─── HELPERS ───────────────────────────────────────────────── */
function sevBadge(sev) { return `<span class="sev ${sev}">${sev}</span>`; }

function scoreBar(score) {
  const pct = Math.min(100, Math.round(+score||0));
  let color = '#34d399';
  if (pct >= 80) color = '#f87171';
  else if (pct >= 60) color = '#fb923c';
  else if (pct >= 40) color = '#fbbf24';
  return `<div class="score-bar-wrap">
    <div class="score-bar"><div class="score-bar-fill" style="width:${pct}%;background:${color};"></div></div>
    <span class="score-num" style="color:${color};">${pct}</span></div>`;
}

function emptyState(cols, msg='No data — run the pipeline first') {
  return `<tr><td colspan="${cols}"><div class="empty-state">◎ ${msg}</div></td></tr>`;
}

function setText(id, val) { const el=document.getElementById(id); if(el) el.textContent=val; }
function setHtml(id, html) { const el=document.getElementById(id); if(el) el.innerHTML=html; }

/* ─── TIMESTAMP HELPERS ─────────────────────────────────────── */
// Handles both "2026-04-19T11:25:35" AND "2026-04-19 11:25:35" (PostgreSQL format)
function parseHour(ts) {
  if (!ts) return 0;
  const d = new Date(String(ts).replace(' ','T'));
  if (!isNaN(d)) return d.getHours();
  const part = String(ts).split(/[T ]/)[1] || '';
  return parseInt(part.split(':')[0]) || 0;
}

function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(String(ts).replace(' ','T'));
  if (!isNaN(d)) return d.toLocaleTimeString('en-GB');
  const part = String(ts).split(/[T ]/)[1] || '';
  return part.split('.')[0] || String(ts);
}

/* ─── LIVE FEED ─────────────────────────────────────────────── */
let _feedData = [];

function feedRows(data, limit=30) {
  return data.slice(0,limit).map(r => {
    const domain = r.domain||r.name||'—';
    const ip     = r.src_ip||r.source_ip||'—';
    const qt     = r.query_type||r.type||'A';
    const sus    = SUSPICIOUS_PATTERNS.some(p=>p.test(domain));
    return `<tr${sus?' style="background:rgba(248,113,113,0.07);"':''}>
      <td class="domain-cell"${sus?' style="color:#f87171!important;"':''}>${domain}${sus?' ⚠':''}</td>
      <td class="ip-cell">${ip}</td>
      <td><span class="qtype">${qt}</span></td>
      <td style="color:var(--text-muted);font-size:10px;">${formatTime(r.timestamp)}</td>
    </tr>`;
  }).join('');
}

async function loadLiveFeed() {
  try {
    const res = await fetch('/api/live-feed');
    _feedData = await res.json()||[];
    const count = _feedData.length;
    setText('nav-live-count', count||'—');
    setText('nav-live-count2', count||'—');
    setHtml('live-feed-body-overview', count ? feedRows(_feedData,20) : emptyState(4));
  } catch(e) { setHtml('live-feed-body-overview', emptyState(4,'Error fetching feed')); }
}

async function loadLiveFeedFull() {
  if (!_feedData.length) await loadLiveFeed();
  setHtml('live-feed-body-full', _feedData.length ? feedRows(_feedData,200) : emptyState(4));
}

/* ─── THREAT SCORES ─────────────────────────────────────────── */
let _threatData = [];

function threatRows(data, limit=50) {
  return data.slice(0,limit).map(r => `<tr>
    <td class="domain-cell">${r.domain||'—'}</td>
    <td>${scoreBar(r._ds)}</td>
    <td>${sevBadge(r._dv)}</td>
  </tr>`).join('');
}

async function loadThreatScores() {
  try {
    const res  = await fetch('/api/threat-scores');
    const data = await res.json()||[];
    _threatData = data.map(r => ({
      ...r,
      _ds: displayScore(r.domain, r.score||0),
      _dv: displaySeverity(r.domain, r.severity, r.score||0),
    })).sort((a,b)=>b._ds-a._ds);

    const count = _threatData.length;
    setText('nav-threat-count', count||'—');
    setHtml('threat-count-tag-overview', `${count} scored`);
    _threatData.forEach(r => checkAndAlert(r.domain, r._ds, r._dv));
    setHtml('threat-body-overview', count ? threatRows(_threatData,15) : emptyState(3));
  } catch(e) { setHtml('threat-body-overview', emptyState(3,'Error fetching threats')); }
}

async function loadThreatsFull() {
  if (!_threatData.length) await loadThreatScores();
  setHtml('threat-count-tag-full', `${_threatData.length} scored`);
  setHtml('threat-body-full', _threatData.length ? threatRows(_threatData,500) : emptyState(3));
}

/* ─── TIMELINE ──────────────────────────────────────────────── */
let _timelineData = [];

async function loadTimeline() {
  try {
    const res = await fetch('/api/timeline');
    _timelineData = await res.json()||[];
    const count = _timelineData.length;
    setText('timeline-count-tag', `${count} events`);
    const container = document.getElementById('timeline-container');
    if (!container) return;
    if (!count) { container.innerHTML='<div class="empty-state">◎ No timeline events yet</div>'; return; }
    container.innerHTML = _timelineData.slice(0,200).map(e => `
      <div class="timeline-row">
        <div class="tl-time">${formatTime(e.occurred_at||e.timestamp)}</div>
        <div>${sevBadge(e.severity||'INFO')}</div>
        <div class="tl-desc"><strong>${e.domain||'—'}</strong> — ${e.description||e.event||'—'}</div>
      </div>`).join('');
  } catch(e) {
    const c=document.getElementById('timeline-container');
    if(c) c.innerHTML='<div class="empty-state">◎ Error loading timeline</div>';
  }
}

/* ─── ACTIVITY CHART — KEY FIX: parseHour handles space timestamps ── */
let _actChart=null, _actChartFull=null;

function buildChartData(data) {
  const buckets = {};
  for(let i=0;i<24;i++) buckets[i]={critical:0,high:0,medium:0};
  (data||[]).forEach(e => {
    const hour = parseHour(e.occurred_at||e.timestamp||'');  // ← fixed
    const sev  = (e.severity||'LOW').toUpperCase();
    if(buckets[hour]!==undefined){
      if(sev==='CRITICAL') buckets[hour].critical++;
      else if(sev==='HIGH') buckets[hour].high++;
      else if(sev==='MEDIUM') buckets[hour].medium++;
    }
  });
  const labels = Array.from({length:24},(_,i)=>`${String(i).padStart(2,'0')}h`);
  return { labels, datasets:[
    {label:'Critical',data:labels.map((_,i)=>buckets[i].critical),backgroundColor:'rgba(248,113,113,0.75)',borderWidth:0,borderRadius:2},
    {label:'High',    data:labels.map((_,i)=>buckets[i].high),    backgroundColor:'rgba(251,146,60,0.75)', borderWidth:0,borderRadius:2},
    {label:'Medium',  data:labels.map((_,i)=>buckets[i].medium),  backgroundColor:'rgba(251,191,36,0.75)', borderWidth:0,borderRadius:2},
  ]};
}

const chartOpts = () => ({
  responsive:true, maintainAspectRatio:false,
  plugins:{
    legend:{position:'top',align:'end',labels:{boxWidth:10,boxHeight:10,padding:12,
      font:{family:"'JetBrains Mono',monospace",size:10},color:'#7a90c0'}},
    tooltip:{backgroundColor:'#0f1628',borderColor:'rgba(255,255,255,0.1)',borderWidth:1,
      titleFont:{family:"'JetBrains Mono',monospace",size:11},
      bodyFont:{family:"'JetBrains Mono',monospace",size:11}}
  },
  scales:{
    x:{stacked:true,grid:{color:'rgba(255,255,255,0.03)'},
      ticks:{color:'#3d4f72',font:{family:"'JetBrains Mono',monospace",size:9},maxRotation:0,maxTicksLimit:12}},
    y:{stacked:true,grid:{color:'rgba(255,255,255,0.04)'},
      ticks:{color:'#3d4f72',font:{family:"'JetBrains Mono',monospace",size:9},precision:0}}
  }
});

Chart.defaults.color='#7a90c0';
Chart.defaults.borderColor='rgba(255,255,255,0.04)';

async function _fetchTimeline() {
  if (!_timelineData.length) { const r=await fetch('/api/timeline'); _timelineData=await r.json()||[]; }
}
async function loadActivityChart() {
  try { await _fetchTimeline(); const ctx=document.getElementById('activity-chart'); if(!ctx) return;
    if(_actChart) _actChart.destroy();
    _actChart=new Chart(ctx.getContext('2d'),{type:'bar',data:buildChartData(_timelineData),options:chartOpts()}); } catch(e){}
}
async function loadActivityChartFull() {
  try { await _fetchTimeline(); const ctx=document.getElementById('activity-chart-full'); if(!ctx) return;
    if(_actChartFull) _actChartFull.destroy();
    _actChartFull=new Chart(ctx.getContext('2d'),{type:'bar',data:buildChartData(_timelineData),options:chartOpts()}); } catch(e){}
}

/* ─── DOMAIN GRAPH ──────────────────────────────────────────── */
let _graphNet=null;
async function loadGraph() {
  try {
    const res=await fetch('/api/graph'), data=await res.json();
    const rawN=data.nodes||[], rawE=data.edges||[];
    setText('graph-stats-tag',`${rawN.length} nodes / ${rawE.length} edges`);
    const colorMap={CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#34d399'};
    const nodes=new vis.DataSet(rawN.slice(0,120).map(n=>{
      const c=colorMap[n.severity]||'#4f8ef7';
      return{id:n.id,label:(n.label||n.id||'').length>22?(n.label||n.id).slice(0,20)+'…':(n.label||n.id),
        color:{background:c+'22',border:c,highlight:{background:c+'44',border:c}},
        font:{color:'#7a90c0',size:11,face:'JetBrains Mono'},borderWidth:1.5,
        size:n.severity==='CRITICAL'?18:12};
    }));
    const edges=new vis.DataSet(rawE.slice(0,220).map((e,i)=>({
      id:i,from:e.from||e.source,to:e.to||e.target,label:e.label||'',
      color:{color:'rgba(79,142,247,0.2)',highlight:'rgba(79,142,247,0.55)'},
      font:{color:'#3d4f72',size:9,face:'JetBrains Mono'},width:1,
      arrows:{to:{enabled:true,scaleFactor:0.5}},
    })));
    const container=document.getElementById('graph-container');
    if(!container) return;
    if(_graphNet) _graphNet.destroy();
    _graphNet=new vis.Network(container,{nodes,edges},{
      physics:{enabled:true,barnesHut:{gravitationalConstant:-3000,springLength:80,damping:0.15},
        stabilization:{iterations:150}},
      interaction:{hover:true,zoomView:true,dragView:true},
      nodes:{shape:'dot',shadow:false},
      edges:{smooth:{type:'continuous',roundness:0.2}}
    });
  } catch(e){ setText('graph-stats-tag','No graph data'); }
}

/* ─── PROTON MAP ────────────────────────────────────────────── */
let _mapBuilt=false, _mapW=0, _mapH=0;

function projectMercator(lon,lat,W,H){
  const x=(lon+180)/360*W;
  const latRad=lat*Math.PI/180;
  const mercN=Math.log(Math.tan(Math.PI/4+latRad/2));
  const y=H/2-(mercN*W/(2*Math.PI));
  return[x,y];
}

async function loadProtonMap(){
  const shell=document.getElementById('map-shell'), svg=document.getElementById('proton-map');
  if(!shell||!svg) return;
  const W=shell.clientWidth>10?shell.clientWidth:1200;
  const H=shell.clientHeight>10?shell.clientHeight:440;
  if(_mapBuilt&&Math.abs(W-_mapW)<5){ await renderMapDots(svg,W,H); return; }
  _mapBuilt=false; _mapW=W; _mapH=H;
  while(svg.firstChild) svg.removeChild(svg.firstChild);
  svg.setAttribute('viewBox',`0 0 ${W} ${H}`);
  svg.setAttribute('preserveAspectRatio','xMidYMid meet');
  const project=(lon,lat)=>projectMercator(lon,lat,W,H);
  for(let lon=-180;lon<=180;lon+=30){
    const[x1]=project(lon,85);
    const l=document.createElementNS('http://www.w3.org/2000/svg','line');
    l.setAttribute('x1',x1);l.setAttribute('y1',0);l.setAttribute('x2',x1);l.setAttribute('y2',H);
    l.setAttribute('stroke','rgba(79,142,247,0.055)');l.setAttribute('stroke-width','0.5');svg.appendChild(l);
  }
  for(let lat=-60;lat<=75;lat+=30){
    const[,y1]=project(0,lat);
    const l=document.createElementNS('http://www.w3.org/2000/svg','line');
    l.setAttribute('x1',0);l.setAttribute('y1',y1);l.setAttribute('x2',W);l.setAttribute('y2',y1);
    l.setAttribute('stroke','rgba(79,142,247,0.055)');l.setAttribute('stroke-width','0.5');svg.appendChild(l);
  }
  try{
    const topoRes=await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json');
    const topology=await topoRes.json();
    const countries=topojson.feature(topology,topology.objects.countries);
    function mercatorPath(f){
      let d='';
      const geoms=f.geometry.type==='MultiPolygon'?f.geometry.coordinates:[f.geometry.coordinates];
      geoms.forEach(poly=>poly.forEach(ring=>{
        ring.forEach((coord,i)=>{
          const[lon,lat]=coord; if(lat<-85||lat>85) return;
          const[x,y]=project(lon,lat);
          d+=i===0?`M${x.toFixed(1)},${y.toFixed(1)}`:`L${x.toFixed(1)},${y.toFixed(1)}`;
        }); d+='Z';
      })); return d;
    }
    countries.features.forEach(f=>{
      if(!f.geometry) return;
      const path=document.createElementNS('http://www.w3.org/2000/svg','path');
      path.setAttribute('d',mercatorPath(f));
      path.setAttribute('fill','#0c1a35');path.setAttribute('stroke','#1a2d52');path.setAttribute('stroke-width','0.5');
      path.style.transition='fill 0.2s';
      path.addEventListener('mouseenter',()=>path.setAttribute('fill','#112244'));
      path.addEventListener('mouseleave',()=>path.setAttribute('fill','#0c1a35'));
      svg.appendChild(path);
    });
  }catch(e){console.warn('TopoJSON failed:',e.message);}
  _mapBuilt=true;
  await renderMapDots(svg,W,H);
}

async function renderMapDots(svg,W,H){
  ['map-dot-layer','map-line-layer'].forEach(id=>{const el=document.getElementById(id);if(el)el.remove();});
  const dotLayer=document.createElementNS('http://www.w3.org/2000/svg','g');
  dotLayer.setAttribute('id','map-dot-layer'); svg.appendChild(dotLayer);
  const project=(lon,lat)=>projectMercator(lon,lat,W,H);
  try{
    const res=await fetch('/api/geo'), data=await res.json()||[];
    setText('geo-count-tag',`${data.length} IPs located`);
    setText('map-counter-val',data.length);
    if(!data.length){ setText('geo-count-tag','No geo data — run pipeline'); return; }
    const tooltip=document.getElementById('map-tooltip');
    const mapShell=document.getElementById('map-shell');
    let plotted=0;
    data.forEach((point,idx)=>{
      const lat=parseFloat(point.lat??point.latitude??0);
      const lon=parseFloat(point.lon??point.longitude??0);
      if(!lat||!lon) return;
      const sus=point.suspicious||point.is_suspicious||false;
      const color=sus?'#f87171':'#34d399';
      const[cx,cy]=project(lon,lat);
      if(cx<-10||cx>W+10||cy<-10||cy>H+10) return;
      plotted++;
      const pulse=document.createElementNS('http://www.w3.org/2000/svg','circle');
      pulse.setAttribute('cx',cx);pulse.setAttribute('cy',cy);pulse.setAttribute('r','5');
      pulse.setAttribute('fill','none');pulse.setAttribute('stroke',color);pulse.setAttribute('stroke-width','1.5');pulse.setAttribute('opacity','0');
      const ar=document.createElementNS('http://www.w3.org/2000/svg','animate');
      ar.setAttribute('attributeName','r');ar.setAttribute('from','5');ar.setAttribute('to','16');
      ar.setAttribute('dur',sus?'1.6s':'2.4s');ar.setAttribute('begin',`${(idx*0.25)%2}s`);ar.setAttribute('repeatCount','indefinite');
      pulse.appendChild(ar);
      const ao=document.createElementNS('http://www.w3.org/2000/svg','animate');
      ao.setAttribute('attributeName','opacity');ao.setAttribute('from','0.8');ao.setAttribute('to','0');
      ao.setAttribute('dur',sus?'1.6s':'2.4s');ao.setAttribute('begin',`${(idx*0.25)%2}s`);ao.setAttribute('repeatCount','indefinite');
      pulse.appendChild(ao); dotLayer.appendChild(pulse);
      const dot=document.createElementNS('http://www.w3.org/2000/svg','circle');
      dot.setAttribute('cx',cx);dot.setAttribute('cy',cy);dot.setAttribute('r',sus?'6':'4');
      dot.setAttribute('fill',color);dot.setAttribute('opacity','0.95');
      dot.style.cursor='pointer';dot.style.filter=`drop-shadow(0 0 ${sus?'7':'4'}px ${color})`;
      dot.addEventListener('mouseenter',()=>{
        let tx=cx+16,ty=cy-16;
        if(tx+200>W) tx=cx-210; if(ty<10) ty=cy+16; if(ty+80>H) ty=H-90;
        tooltip.style.left=`${tx}px`; tooltip.style.top=`${ty}px`;
        document.getElementById('map-tt-sev').textContent=sus?'⚠ SUSPICIOUS':'✓ NORMAL';
        document.getElementById('map-tt-sev').className=`map-tt-sev ${sus?'sus':'ok'}`;
        document.getElementById('map-tt-ip').textContent=(point.ip||point.ip_address||'—').replace(/^dom:/,'');
        document.getElementById('map-tt-loc').textContent=[point.city,point.country].filter(Boolean).join(', ')||'Unknown';
        tooltip.classList.add('visible');
      });
      dot.addEventListener('mouseleave',()=>tooltip.classList.remove('visible'));
      dotLayer.appendChild(dot);
    });
    const susPoints=data.filter(p=>(p.suspicious||p.is_suspicious)&&parseFloat(p.lat??p.latitude??0)&&parseFloat(p.lon??p.longitude??0));
    if(susPoints.length>=2){
      const lineLayer=document.createElementNS('http://www.w3.org/2000/svg','g');
      lineLayer.setAttribute('id','map-line-layer'); svg.insertBefore(lineLayer,dotLayer);
      for(let i=0;i<Math.min(susPoints.length-1,10);i++){
        const[x1,y1]=project(parseFloat(susPoints[i].lon??susPoints[i].longitude??0),parseFloat(susPoints[i].lat??susPoints[i].latitude??0));
        const[x2,y2]=project(parseFloat(susPoints[i+1].lon??susPoints[i+1].longitude??0),parseFloat(susPoints[i+1].lat??susPoints[i+1].latitude??0));
        const line=document.createElementNS('http://www.w3.org/2000/svg','line');
        line.setAttribute('x1',x1);line.setAttribute('y1',y1);line.setAttribute('x2',x2);line.setAttribute('y2',y2);
        line.setAttribute('stroke','rgba(248,113,113,0.3)');line.setAttribute('stroke-width','1');line.setAttribute('stroke-dasharray','4 4');
        lineLayer.appendChild(line);
      }
    }
  }catch(e){ console.error('[MAP]',e); setText('geo-count-tag','Error loading geo data'); }
}



/* ─── KPI ───────────────────────────────────────────────────── */
async function loadKPI(){
  try{
    const res=await fetch('/api/stats'); if(!res.ok) return;
    const d=await res.json();
    setText('total-queries',d.total_queries??'—'); setText('critical-alerts',d.critical_alerts??'—');
    setText('high-alerts',d.high_alerts??'—'); setText('suspicious-domains',d.suspicious_domains??'—');
    setText('kpi-updated',`Updated ${new Date().toLocaleTimeString()}`);
    setText('footer-stats',`Queries: ${d.total_queries??0} · Threats: ${d.suspicious_domains??0} · Critical: ${d.critical_alerts??0}`);
  }catch(e){}
}

/* ─── PIPELINE ──────────────────────────────────────────────── */
async function triggerPipeline(){
  const btn=document.getElementById('run-btn');
  const label=document.getElementById('pipeline-label');
  const pill=document.getElementById('pipeline-status');
  btn.disabled=true; btn.textContent='⟳ Running…';
  label.textContent='Pipeline running…'; pill.classList.remove('warn');
  try{
    const res=await fetch('/api/run-pipeline',{method:'POST'});
    label.textContent=res.ok?'Pipeline complete':'Pipeline error';
    if(!res.ok) pill.classList.add('warn');
    setText('last-run-label',`Last run: ${new Date().toLocaleTimeString()}`);
    _timelineData=[];_threatData=[];_feedData=[];_mapBuilt=false;_alertedDomains=new Set();
    await initDashboard();
  }catch(e){ label.textContent='Run main.py first'; pill.classList.add('warn'); await initDashboard(); }
  btn.disabled=false; btn.textContent='▶ Run Pipeline';
}

/* ─── INIT ──────────────────────────────────────────────────── */
async function initDashboard(){
  await Promise.allSettled([loadKPI(),loadLiveFeed(),loadThreatScores(),loadTimeline().then(loadActivityChart)]);
}
initDashboard();
setInterval(loadThreatScores,30000);
setInterval(()=>loadTimeline().then(loadActivityChart),40000);
setInterval(loadKPI,60000);
setInterval(loadLiveFeed,15000);
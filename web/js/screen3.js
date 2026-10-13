/* ══════════════════════════════════════════════════════════════
   AI 智能洞察大屏（AI 能力规划 P1-3）
   主角：今日威胁族群气泡图（攻击基础设施聚类全景）
   数据：/api/ai/stats /threat-clusters /false-positive /dga-suspects /tunnel-suspects
   设计：全程旁路只读展示，AI 产出均为「建议」，加白等动作需人工在管理端确认
   ══════════════════════════════════════════════════════════════ */
(function(){
'use strict';

var STAGE_W = 1920, STAGE_H = 1080;
var S = {
  token: localStorage.getItem('dnsf_token') || '',
  clusters: [], fp: [], dga: [], tunnels: [],
  anim: [],          // 气泡动画状态
  stats: null, booted: false
};

function $(id){ return document.getElementById(id); }
function fmt(n){ return (n == null || isNaN(n)) ? '--' : Number(n).toLocaleString('en-US'); }
function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function pad2(n){ return n < 10 ? '0' + n : '' + n; }

/* ── 视口等比缩放 ── */
function fit(){
  var s = Math.min(window.innerWidth / STAGE_W, window.innerHeight / STAGE_H);
  var st = $('stage');
  st.style.transform = 'scale(' + s + ')';
  st.style.left = ((window.innerWidth - STAGE_W * s) / 2) + 'px';
  st.style.top = ((window.innerHeight - STAGE_H * s) / 2) + 'px';
}
window.addEventListener('resize', fit);

/* ── API ── */
var timers = [];
function api(path){
  var opt = {headers: {}};
  if (S.token) opt.headers.Authorization = 'Bearer ' + S.token;
  return fetch(path, opt).then(function(r){
    if (r.status === 401){ onUnauthorized(); throw new Error('401'); }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(j){
    if (j.code !== 0) throw new Error(j.message || 'api error');
    return j.data;
  });
}
function onUnauthorized(){
  timers.forEach(clearInterval); timers = [];
  S.booted = false;
  $('loginOverlay').style.display = 'flex';
}
$('loginForm').addEventListener('submit', function(ev){
  ev.preventDefault();
  $('loginErr').textContent = '';
  fetch('/api/auth/login', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: $('loginUser').value.trim(),
                          password: $('loginPass').value})
  }).then(function(r){ return r.json(); }).then(function(j){
    if (j.code !== 0){ $('loginErr').textContent = j.message || '登录失败'; return; }
    S.token = j.data.token;
    localStorage.setItem('dnsf_token', S.token);
    $('loginOverlay').style.display = 'none';
    bootData();
  }).catch(function(){ $('loginErr').textContent = '网络异常，请重试'; });
});

/* ── 时钟 / 全屏 ── */
var WEEK = ['日','一','二','三','四','五','六'];
function tickClock(){
  var d = new Date();
  $('scrClock').textContent = pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  $('scrDate').textContent = d.getFullYear() + ' 年 ' + pad2(d.getMonth() + 1) + ' 月 ' +
    pad2(d.getDate()) + ' 日 · 星期' + WEEK[d.getDay()];
}
setInterval(tickClock, 1000); tickClock();
function toggleFs(){
  if (document.fullscreenElement) document.exitFullscreen();
  else document.documentElement.requestFullscreen && document.documentElement.requestFullscreen();
}
$('btnFs').addEventListener('click', toggleFs);
document.addEventListener('keydown', function(e){
  if ((e.key === 'f' || e.key === 'F') && !e.target.matches('input')) toggleFs();
});

/* ── 背景星尘 ── */
var bg = {cv: null, cx: null, stars: []};
function initBg(){
  bg.cv = $('bgCanvas');
  bg.cv.width = STAGE_W; bg.cv.height = STAGE_H;
  bg.cx = bg.cv.getContext('2d');
  for (var i = 0; i < 120; i++){
    bg.stars.push({x: Math.random()*STAGE_W, y: Math.random()*STAGE_H*0.8,
      r: Math.random()*1.3+0.3, a: Math.random()*0.45+0.1, ph: Math.random()*6.28});
  }
}
function drawBg(t){
  var c = bg.cx;
  c.clearRect(0, 0, STAGE_W, STAGE_H);
  for (var i = 0; i < bg.stars.length; i++){
    var s = bg.stars[i];
    var tw = s.a * (0.6 + 0.4*Math.sin(t/900 + s.ph));
    c.fillStyle = 'rgba(160,220,255,' + tw.toFixed(3) + ')';
    c.fillRect(s.x, s.y, s.r, s.r);
  }
}

/* ══════════ 威胁族群气泡图 ══════════ */
var cl = {cv: null, cx: null, W: 1008, H: 640};
/* 命中源 → 色相（与双屏配色体系一致） */
var SRC_HUE = {
  silverfox: 275, hagezi_ti: 190, hagezi_ult: 200, stevenblack: 210,
  threatfox_hosts: 45, urlhaus: 20, c2intel_domains: 330,
  local_blacklist: 348, ip_filter: 42, rdap_nrd: 220
};
function srcHue(sources){
  var keys = Object.keys(sources || {});
  if (!keys.length) return 190;
  var top = keys.sort(function(a,b){ return sources[b] - sources[a]; })[0];
  if (SRC_HUE[top] != null) return SRC_HUE[top];
  if (top.indexOf('threat_list:') === 0) return SRC_HUE[top.slice(12)] || 190;
  return 240;
}

function initCluster(){
  cl.cv = $('clusterCanvas');
  cl.cv.width = cl.W * 2; cl.cv.height = cl.H * 2;
  cl.cx = cl.cv.getContext('2d');
  cl.cx.scale(2, 2);
}

/* 向日葵螺旋布局：大族群在内、小族群向外，紧凑不重叠 */
function layout(items){
  var out = [], golden = 2.399963, cx = cl.W/2, cy = cl.H/2 - 10;
  items.forEach(function(it, i){
    var r = 30 * Math.sqrt(i + 0.6) + 14;
    var a = i * golden;
    out.push({x: cx + r*Math.cos(a), y: cy + r*Math.sin(a), item: it,
              ph: Math.random()*6.28});
  });
  return out;
}

function drawCluster(t){
  if (!cl.cx) return;
  var c = cl.cx;
  c.clearRect(0, 0, cl.W, cl.H);
  var items = S.clusters;
  if (!items.length){
    c.fillStyle = 'rgba(148,197,255,.45)';
    c.font = '600 22px "Microsoft YaHei", sans-serif';
    c.textAlign = 'center';
    c.fillText('尚无威胁族群 · AI 分析运行中（每 30 分钟一轮）', cl.W/2, cl.H/2);
    c.textAlign = 'left';
    return;
  }
  var maxHits = items[0].evidence.hits || 1;
  var nodes = layout(items);
  /* 先画连线（族群→中心，体现"聚类"关系） */
  c.save();
  c.globalCompositeOperation = 'lighter';
  nodes.forEach(function(n){
    if (n.item === items[0]) { n._r = 0; return; }
    n._r = 5;
  });
  /* 气泡 */
  nodes.forEach(function(n){
    var ev = n.item.evidence || {};
    var hits = ev.hits || 1;
    var hue = srcHue(ev.sources);
    var base = 9 + 27 * Math.sqrt(hits / maxHits);
    var pulse = 1 + 0.05 * Math.sin(t/700 + n.ph);
    var r = base * pulse;
    /* 光晕 */
    var g = c.createRadialGradient(n.x, n.y, 0, n.x, n.y, r*1.9);
    g.addColorStop(0, 'hsla(' + hue + ',88%,62%,.55)');
    g.addColorStop(0.45, 'hsla(' + hue + ',88%,58%,.16)');
    g.addColorStop(1, 'hsla(' + hue + ',88%,58%,0)');
    c.fillStyle = g;
    c.beginPath(); c.arc(n.x, n.y, r*1.9, 0, Math.PI*2); c.fill();
    /* 实心球 */
    c.fillStyle = 'hsla(' + hue + ',85%,58%,.85)';
    c.beginPath(); c.arc(n.x, n.y, r, 0, Math.PI*2); c.fill();
    /* 外环（评分越高越亮） */
    c.strokeStyle = 'hsla(' + hue + ',92%,72%,' + (0.35 + 0.5*n.item.score).toFixed(2) + ')';
    c.lineWidth = 1.6;
    c.beginPath(); c.arc(n.x, n.y, r + 3, 0, Math.PI*2); c.stroke();
    /* 标签 */
    c.font = '700 ' + (11 + Math.min(4, hits/maxHits*4)).toFixed(0) + 'px Consolas, monospace';
    c.fillStyle = 'rgba(226,246,255,.92)';
    c.textAlign = 'center';
    c.shadowColor = 'rgba(6,18,36,.95)'; c.shadowBlur = 6;
    c.fillText(n.item.target, n.x, n.y + r + 14);
    c.font = '600 10px Consolas, monospace';
    c.fillStyle = 'rgba(148,197,255,.7)';
    c.fillText(fmt(hits) + ' 次 · ' + (ev.domain_count||0) + ' 域', n.x, n.y + r + 26);
    c.shadowBlur = 0;
  });
  c.restore();
  c.textAlign = 'left';
}

/* ══════════ 左翼渲染 ══════════ */
function renderStats(d){
  var f = d.findings || {};
  function pend(t){ return (f[t] && f[t].pending) || 0; }
  $('mDga').textContent = fmt(pend('dga_suspect'));
  $('mTunnel').textContent = fmt(pend('tunnel_suspect'));
  $('mFp').textContent = fmt(pend('false_positive'));
  $('mCluster').textContent = fmt(pend('threat_cluster'));

  $('dTotal').textContent = fmt(d.first_seen_total);
  $('d24h').textContent = fmt(d.first_seen_24h);
  var col = d.collector || {};
  $('dQueue').textContent = fmt(col.queue_size) + ' / ' + fmt(col.flushed);
  var b = d.batch || {};
  var hasRun = b.at > 0;
  $('dInterval').textContent = hasRun ? '已运行' : '等待首轮';

  $('hdCollector').className = 'hd-light ' + (col.enabled !== false ? 'ok' : 'bad');
  $('hdCollector').querySelector('b').textContent = col.enabled !== false ? 'ON' : 'OFF';
}

/* ══════════ 右翼：列表渲染 ══════════ */
function renderFp(items){
  S.fp = items || [];
  var box = $('fpList');
  if (!items.length){ box.innerHTML = '<div class="ai-empty">暂无待办</div>'; return; }
  box.innerHTML = items.slice(0, 6).map(function(it){
    var ev = it.evidence || {};
    var meta = (ev.clients || 0) + ' 客户端 · 人均 ' + (ev.hits_per_client || 0) + ' 次' +
               (it.already_whitelisted ? ' · 已加白' : '');
    return '<div class="ai-item fp" title="' + esc(JSON.stringify(ev)) + '">' +
      '<span class="nm">' + esc(it.target) + '</span>' +
      '<span class="sc">' + (it.score * 100).toFixed(0) + '</span>' +
      '<span class="mt">' + esc(meta) + '</span></div>';
  }).join('');
}

function renderSuspects(dga, tunnels){
  S.dga = dga || []; S.tunnels = tunnels || [];
  var box = $('suspectList');
  var rows = [];
  (dga || []).slice(0, 4).forEach(function(it){
    var ev = it.evidence || {};
    rows.push({cls: '', name: it.target, score: it.score,
      meta: 'DGA · 熵 ' + (ev.entropy || 0) + ' · 长 ' + (ev.len || 0)});
  });
  (tunnels || []).slice(0, 3).forEach(function(it){
    var ev = it.evidence || {};
    rows.push({cls: '', name: (it.target || '').split('|')[1] || it.target,
      score: it.score,
      meta: '隧道 · ' + (ev.queries || 0) + ' 查询 · 类型 ' +
            Object.keys(ev.type_counter || {}).join('/')});
  });
  if (!rows.length){ box.innerHTML = '<div class="ai-empty">暂无发现</div>'; return; }
  box.innerHTML = rows.map(function(r){
    return '<div class="ai-item' + r.cls + '">' +
      '<span class="nm">' + esc(r.name) + '</span>' +
      '<span class="sc">' + (r.score * 100).toFixed(0) + '</span>' +
      '<span class="mt">' + esc(r.meta) + '</span></div>';
  }).join('');
}

/* ══════════ 底部：隧道会话 ══════════ */
function renderTunnels(items){
  var box = $('tunnelList');
  if (!items || !items.length){
    box.innerHTML = '<div class="ai-empty">未发现隧道会话</div>'; return;
  }
  box.innerHTML = items.slice(0, 6).map(function(it){
    var parts = (it.target || '').split('|');
    var ev = it.evidence || {};
    return '<div class="tn-item" title="' + esc(JSON.stringify(ev)) + '">' +
      '<span class="sc">' + (it.score * 100).toFixed(0) + '</span>' +
      '<span class="cl">' + esc(parts[0] || '-') + '</span>' +
      '<span class="pa">' + esc(parts[1] || it.target) + '</span>' +
      '<span class="mt">' + (ev.queries || 0) + ' 查询 · 熵 ' +
        (ev.avg_entropy || 0) + '</span></div>';
  }).join('');
}

/* ══════════ 轮询 ══════════ */
function pollStats(){
  return api('/api/ai/stats').then(renderStats).catch(function(){});
}
function pollClusters(){
  return api('/api/ai/threat-clusters?limit=40').then(function(d){
    S.clusters = (d && d.items) || [];
  }).catch(function(){});
}
function pollFp(){
  return api('/api/ai/false-positive?limit=20').then(function(d){
    renderFp((d && d.items) || []);
  }).catch(function(){});
}
function pollSuspects(){
  Promise.all([
    api('/api/ai/dga-suspects?limit=10').catch(function(){ return {items: []}; }),
    api('/api/ai/tunnel-suspects?limit=10').catch(function(){ return {items: []}; })
  ]).then(function(rs){
    renderSuspects(rs[0].items, rs[1].items);
    renderTunnels(rs[1].items);
  });
}

/* ── P3：AI 研判面板（LLM 只做归纳翻译，不参与任何检测判定） ── */
function apiPost(path){
  var opt = {method: 'POST', headers: {}};
  if (S.token) opt.headers.Authorization = 'Bearer ' + S.token;
  return fetch(path, opt).then(function(r){
    if (r.status === 401){ onUnauthorized(); throw new Error('401'); }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(j){
    if (j.code !== 0) throw new Error(j.message || 'api error');
    return j.data;
  });
}
var aip = {open: false, busy: false};
var AIP_FOOT = '事实来源：AI 算法层结论（DGA / 隧道 / 误报 / 族群 / 行为基线）';
function aipShow(mode, text, foot){
  var m = $('aipMode');
  m.textContent = (mode === 'llm') ? 'LLM 生成' : '结构化降级';
  m.className = 'aip-mode' + (mode === 'llm' ? '' : ' structured');
  $('aipBody').textContent = text || '';
  $('aipFoot').textContent = foot || AIP_FOOT;
}
function aipBusy(on){
  aip.busy = on;
  $('aipRefresh').disabled = on;
  $('aipAsk').disabled = on;
}
function aipOpenPanel(){
  $('aiPanelMask').style.display = 'flex';
  aip.open = true;
  aipGenerate();
}
function aipClosePanel(){
  $('aiPanelMask').style.display = 'none';
  aip.open = false;
}
function aipGenerate(){
  if (aip.busy) return;
  aipBusy(true);
  $('aipBody').innerHTML = '<div class="aip-hint">正在生成研判报告…</div>';
  apiPost('/api/ai/llm/report').then(function(d){
    aipShow(d.source, d.content);
  }).catch(function(e){
    aipShow('structured', '生成失败：' + e.message + '\n\n请稍后重试。');
  }).then(function(){ aipBusy(false); });
}
function aipAsk(){
  var q = $('aipQuestion').value.trim();
  if (!q || aip.busy) return;
  aipBusy(true);
  $('aipBody').innerHTML = '<div class="aip-hint">正在研判…</div>';
  apiPost('/api/ai/llm/ask?question=' + encodeURIComponent(q))
    .then(function(d){ aipShow(d.source, d.content, '问题：' + q); })
    .catch(function(e){ aipShow('structured', '提问失败：' + e.message); })
    .then(function(){ aipBusy(false); });
}
$('btnAiReport').addEventListener('click', aipOpenPanel);
$('aipRefresh').addEventListener('click', aipGenerate);
$('aipClose').addEventListener('click', aipClosePanel);
$('aipAsk').addEventListener('click', aipAsk);
$('aipQuestion').addEventListener('keydown', function(e){
  if (e.key === 'Enter'){ e.preventDefault(); aipAsk(); }
});
$('aiPanelMask').addEventListener('click', function(e){
  if (e.target === $('aiPanelMask')) aipClosePanel();
});
document.addEventListener('keydown', function(e){
  var tag = (e.target && e.target.tagName) || '';
  if (tag === 'INPUT' || tag === 'TEXTAREA') return;   /* 输入中不触发快捷键 */
  if (e.key === 'Escape' && aip.open) aipClosePanel();
  else if ((e.key === 'l' || e.key === 'L') && !aip.open) aipOpenPanel();
});

function bootData(){
  if (S.booted) return;
  S.booted = true;
  pollStats(); pollClusters(); pollFp(); pollSuspects();
  timers.push(setInterval(pollStats, 10000));
  timers.push(setInterval(pollClusters, 30000));
  timers.push(setInterval(pollFp, 30000));
  timers.push(setInterval(pollSuspects, 30000));
}

function loop(t){
  try {
    drawBg(t || 0);
    drawCluster(t || 0);
  } catch (e){ /* 单帧异常不致命 */ }
  requestAnimationFrame(loop);
}

fit();
initBg();
initCluster();
requestAnimationFrame(loop);

if (S.token) bootData(); else $('loginOverlay').style.display = 'flex';

})();

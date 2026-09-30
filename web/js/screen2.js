/* ══════════════════════════════════════════════════════════════
   检测链路透视（视角 B · 迭代 47）
   主角：五层检测链路流水线——查询光流逐层穿透，拦截在层塔捕获
   数据：/api/status /api/status/layers /api/logs/stream
         /api/circuit-breaker/stats /api/threatlist/sources
   ══════════════════════════════════════════════════════════════ */
(function(){
'use strict';

var STAGE_W = 1920, STAGE_H = 1080;
var STREAM_SIZE = 10;
var EV_ROW_H = 29;

/* 五层定义（与 detectors.process_query 检测顺序一致） */
var LAYERS = [
  {key: 'local_blacklist', tag: 'L1', name: '本地名单',   en: 'LOCAL LIST',     color: '#fb4d6d', hue: 348},
  {key: 'threat_list',    tag: 'L2', name: '离线大名单', en: 'THREAT LIST',    color: '#22d3ee', hue: 190},
  {key: 'nrd',            tag: 'L3', name: 'NRD 检测',   en: 'NRD WATCH',      color: '#60a5fa', hue: 220},
  {key: 'threatintel',    tag: 'L4', name: '在线情报',   en: 'ONLINE INTEL',   color: '#a78bfa', hue: 265},
  {key: 'ip_filter',      tag: 'L5', name: 'IP 后置',    en: 'IP POST-FILTER', color: '#fbbf24', hue: 42}
];
function reasonToLayer(r){
  if (!r) return 1;
  if (r === 'local_blacklist') return 0;
  if (r.indexOf('threat_list') === 0) return 1;
  if (r.indexOf('nrd') === 0) return 2;
  if (r.indexOf('threatintel') === 0) return 3;
  if (r === 'ip_filter') return 4;
  return 1;
}
function reasonShort(r){
  if (!r) return '未知';
  if (r.indexOf('threat_list:') === 0) return r.slice(12);
  if (r.indexOf('threatintel:') === 0) return r.slice(12);
  if (r.indexOf('nrd') === 0) return 'NRD';
  var m = {local_blacklist: '本地名单', ip_filter: 'IP 过滤', 'degraded:failsafe': '降级保护'};
  return m[r] || (r.length > 14 ? r.slice(0, 14) : r);
}

/* ── 全局状态 ───────────────────────────────────────────── */
var S = {
  token: localStorage.getItem('dnsf_token') || '',
  lastStreamId: 0, streamReady: false,
  rate: 0, total: 0, blocked: 0, allows: 0,
  layers: LAYERS.map(function(){ return {count: 0, active: true, share: 0, h: 30, flash: 0}; }),
  flow: [], caps: [], absorbs: [],
  booted: false
};

/* ── 视口等比缩放 ───────────────────────────────────────── */
function fit(){
  var s = Math.min(window.innerWidth / STAGE_W, window.innerHeight / STAGE_H);
  var st = document.getElementById('stage');
  st.style.transform = 'scale(' + s + ')';
  st.style.left = ((window.innerWidth - STAGE_W * s) / 2) + 'px';
  st.style.top = ((window.innerHeight - STAGE_H * s) / 2) + 'px';
}
window.addEventListener('resize', function(){ fit(); sizeCanvases(); });

/* ── 工具 ───────────────────────────────────────────────── */
function $(id){ return document.getElementById(id); }
function fmt(n){ return (n == null || isNaN(n)) ? '--' : Number(n).toLocaleString('en-US'); }
function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function pad2(n){ return n < 10 ? '0' + n : '' + n; }
function hms(ts){
  var d = ts ? new Date(String(ts).replace(' ', 'T')) : new Date();
  if (isNaN(d)) d = new Date();
  return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}
function countUp(el, to, suffix, dec){
  if (!el) return;
  suffix = suffix || ''; dec = dec || 0;
  var from = parseFloat(el.dataset.v || '0') || 0;
  el.dataset.v = to;
  function show(v){
    el.textContent = dec ? v.toFixed(dec) + suffix : fmt(Math.round(v)) + suffix;
  }
  if (from === to){ show(to); return; }
  var t0 = performance.now(), dur = 800;
  function step(t){
    var p = Math.min(1, (t - t0) / dur);
    p = 1 - Math.pow(1 - p, 3);
    show(from + (to - from) * p);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* ── API 层 ─────────────────────────────────────────────── */
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
  timers.forEach(clearInterval);
  timers = [];
  S.booted = false;
  showLogin();
}

/* ── 登录 ───────────────────────────────────────────────── */
function showLogin(){ $('loginOverlay').style.display = 'flex'; }
function hideLogin(){ $('loginOverlay').style.display = 'none'; }
$('loginForm').addEventListener('submit', function(ev){
  ev.preventDefault();
  var u = $('loginUser').value.trim(), p = $('loginPass').value;
  $('loginErr').textContent = '';
  fetch('/api/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: u, password: p})
  }).then(function(r){ return r.json(); }).then(function(j){
    if (j.code !== 0){ $('loginErr').textContent = j.message || '登录失败'; return; }
    S.token = j.data.token;
    localStorage.setItem('dnsf_token', S.token);
    hideLogin();
    bootData();
  }).catch(function(){ $('loginErr').textContent = '网络异常，请重试'; });
});

/* ── 时钟 / 全屏 ────────────────────────────────────────── */
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

/* ═══════════════ 背景星尘 ═══════════════ */
var bg = {cv: null, cx: null, stars: [], meteors: []};
function initBg(){
  bg.cv = $('bgCanvas');
  bg.cv.width = STAGE_W; bg.cv.height = STAGE_H;
  bg.cx = bg.cv.getContext('2d');
  for (var i = 0; i < 130; i++){
    bg.stars.push({
      x: Math.random() * STAGE_W, y: Math.random() * STAGE_H * 0.75,
      r: Math.random() * 1.4 + 0.3, a: Math.random() * 0.5 + 0.1,
      vx: (Math.random() - 0.5) * 0.08, ph: Math.random() * 6.28
    });
  }
}
function spawnMeteor(){
  bg.meteors.push({x: Math.random() * STAGE_W, y: -10, vy: 3 + Math.random() * 3, life: 1});
}
function drawBg(t){
  var c = bg.cx;
  c.clearRect(0, 0, STAGE_W, STAGE_H);
  var i, s;
  for (i = 0; i < bg.stars.length; i++){
    s = bg.stars[i];
    s.x += s.vx;
    if (s.x < 0) s.x = STAGE_W; if (s.x > STAGE_W) s.x = 0;
    var tw = s.a * (0.6 + 0.4 * Math.sin(t / 900 + s.ph));
    c.fillStyle = 'rgba(160,220,255,' + tw.toFixed(3) + ')';
    c.fillRect(s.x, s.y, s.r, s.r);
  }
  if (Math.random() < 0.004) spawnMeteor();
  for (i = bg.meteors.length - 1; i >= 0; i--){
    var m = bg.meteors[i];
    m.y += m.vy; m.life -= 0.006;
    if (m.life <= 0 || m.y > STAGE_H * 0.8){ bg.meteors.splice(i, 1); continue; }
    var g = c.createLinearGradient(m.x, m.y - 60, m.x, m.y);
    g.addColorStop(0, 'rgba(34,211,238,0)');
    g.addColorStop(1, 'rgba(34,211,238,' + (0.35 * m.life).toFixed(3) + ')');
    c.strokeStyle = g; c.lineWidth = 1.2;
    c.beginPath(); c.moveTo(m.x, m.y - 60); c.lineTo(m.x, m.y); c.stroke();
  }
}

/* ═══════════════ 中央：五层流水线 ═══════════════ */
var ch = {cv: null, cx: null, W: 1008, H: 640};
var TOWER_X = [130, 320, 510, 700, 890];
var FLOW_Y = 400, BASE_Y = 560, INLET_X = 26, OUTLET_X = 986;

function initChain(){
  ch.cv = $('chainCanvas');
  ch.cv.width = ch.W * 2; ch.cv.height = ch.H * 2;
  ch.cx = ch.cv.getContext('2d');
  ch.cx.scale(2, 2);
}

/* 粒子生成：按真实拦截率与层占比决定命运 */
function spawnFlow(){
  if (S.flow.length >= 110) return;
  var tgt = -1;
  if (Math.random() * 100 < S.rate){
    var tw = Math.random(), acc = 0;
    for (var i = 0; i < 5; i++){
      if (!S.layers[i].active) continue;
      acc += S.layers[i].share;
      if (tw <= acc){ tgt = i; break; }
    }
  }
  S.flow.push({
    x: INLET_X - 14, y: FLOW_Y + (Math.random() - 0.5) * 14,
    sp: 130 + Math.random() * 90, tgt: tgt
  });
}

function drawChain(t){
  if (!ch.cx) return;
  var c = ch.cx, W = ch.W, H = ch.H;
  var dt = 16.7;
  c.clearRect(0, 0, W, H);
  c.save();

  var i, j, ly;

  /* ── 入口 / 出口 ── */
  /* 入口发光门 */
  var gi = c.createLinearGradient(0, 0, 60, 0);
  gi.addColorStop(0, 'rgba(34,211,238,.30)');
  gi.addColorStop(1, 'rgba(34,211,238,0)');
  c.fillStyle = gi;
  c.fillRect(0, FLOW_Y - 34, 60, 68);
  c.strokeStyle = 'rgba(126,231,252,.8)'; c.lineWidth = 2;
  c.beginPath(); c.moveTo(INLET_X, FLOW_Y - 34); c.lineTo(INLET_X, FLOW_Y + 34); c.stroke();
  /* 出口吸收球 */
  var pulse = 1 + Math.sin(t / 700) * 0.06;
  var go = c.createRadialGradient(OUTLET_X, FLOW_Y, 0, OUTLET_X, FLOW_Y, 46 * pulse);
  go.addColorStop(0, 'rgba(52,211,153,.75)');
  go.addColorStop(0.5, 'rgba(52,211,153,.22)');
  go.addColorStop(1, 'rgba(52,211,153,0)');
  c.fillStyle = go;
  c.beginPath(); c.arc(OUTLET_X, FLOW_Y, 46 * pulse, 0, Math.PI * 2); c.fill();
  c.strokeStyle = 'rgba(52,211,153,.8)'; c.lineWidth = 1.6;
  c.beginPath(); c.arc(OUTLET_X, FLOW_Y, 18 * pulse, 0, Math.PI * 2); c.stroke();

  /* ── 主流带（发光底线） ── */
  var gb = c.createLinearGradient(INLET_X, 0, OUTLET_X, 0);
  gb.addColorStop(0, 'rgba(34,211,238,.4)');
  gb.addColorStop(1, 'rgba(52,211,153,.35)');
  c.strokeStyle = gb; c.lineWidth = 1.4;
  c.setLineDash([2, 7]);
  c.beginPath(); c.moveTo(INLET_X, FLOW_Y - 22); c.lineTo(OUTLET_X - 20, FLOW_Y - 22); c.stroke();
  c.beginPath(); c.moveTo(INLET_X, FLOW_Y + 22); c.lineTo(OUTLET_X - 20, FLOW_Y + 22); c.stroke();
  c.setLineDash([]);

  /* ── 五座关卡塔 ── */
  for (i = 0; i < 5; i++){
    ly = LAYERS[i];
    var Ld = S.layers[i];
    var x = TOWER_X[i];
    /* 水位高度缓动逼近 share 目标 */
    var targetH = 26 + Ld.share * 230;
    Ld.h += (targetH - Ld.h) * 0.04;
    Ld.flash = Math.max(0, Ld.flash - 0.025);
    var hue = ly.hue;
    var active = Ld.active;
    var colT = function(a){ return active ? 'hsla(' + hue + ',90%,62%,' + a + ')' : 'rgba(100,116,139,' + (a * 0.8) + ')'; };

    /* 塔轨（虚线导轨） */
    c.strokeStyle = colT(0.22); c.lineWidth = 1;
    c.setLineDash([3, 6]);
    c.beginPath(); c.moveTo(x - 40, 190); c.lineTo(x - 40, BASE_Y); c.stroke();
    c.beginPath(); c.moveTo(x + 40, 190); c.lineTo(x + 40, BASE_Y); c.stroke();
    c.setLineDash([]);

    /* 基座 */
    c.fillStyle = colT(0.16);
    c.beginPath();
    c.moveTo(x - 52, BASE_Y + 14); c.lineTo(x + 52, BASE_Y + 14);
    c.lineTo(x + 40, BASE_Y); c.lineTo(x - 40, BASE_Y);
    c.closePath(); c.fill();
    c.strokeStyle = colT(0.5); c.lineWidth = 1.2;
    c.beginPath(); c.moveTo(x - 52, BASE_Y + 14); c.lineTo(x + 52, BASE_Y + 14); c.stroke();

    /* 水位柱 */
    var colTop = BASE_Y - Ld.h;
    var gw = c.createLinearGradient(0, colTop, 0, BASE_Y);
    gw.addColorStop(0, colT(0.55 + Ld.flash * 0.4));
    gw.addColorStop(1, colT(0.08));
    c.fillStyle = gw;
    c.fillRect(x - 28, colTop, 56, Ld.h);
    /* 柱顶能量盖 */
    c.fillStyle = colT(Math.min(1, 0.75 + Ld.flash * 0.25));
    c.shadowColor = colT(1); c.shadowBlur = 12 + Ld.flash * 26;
    c.fillRect(x - 30, colTop - 3, 60, 4);
    c.shadowBlur = 0;

    /* 捕获闪光环 */
    if (Ld.flash > 0.03){
      c.strokeStyle = 'hsla(' + hue + ',95%,68%,' + (Ld.flash * 0.9).toFixed(3) + ')';
      c.lineWidth = 2;
      c.beginPath(); c.arc(x, FLOW_Y, 30 + (1 - Ld.flash) * 46, 0, Math.PI * 2); c.stroke();
    }

    /* 层标签 + 计数 */
    c.textAlign = 'center';
    c.fillStyle = colT(active ? 0.95 : 0.5);
    c.font = '700 20px Consolas, monospace';
    c.fillText(ly.tag, x, 128);
    c.font = '600 15px "Microsoft YaHei", sans-serif';
    c.fillText(ly.name, x, 152);
    c.font = '600 10px Consolas, monospace';
    c.fillStyle = active ? 'rgba(148,197,255,.55)' : 'rgba(100,116,139,.6)';
    c.fillText(ly.en, x, 170);
    /* 计数 */
    c.font = '700 30px Consolas, monospace';
    c.fillStyle = colT(active ? 1 : 0.45);
    c.shadowColor = colT(0.9); c.shadowBlur = 14;
    c.fillText(fmt(Ld.count), x, 216);
    c.shadowBlur = 0;
    /* 占比 */
    c.font = '600 12px Consolas, monospace';
    c.fillStyle = colT(0.6);
    c.fillText((Ld.share * 100).toFixed(1) + '%', x, 238);
    /* 停用标注 */
    if (!active){
      c.fillStyle = 'rgba(148,163,184,.75)';
      c.font = '600 11px "Microsoft YaHei", sans-serif';
      c.fillText('停 用', x, 262);
    }
  }

  /* ── 查询光流粒子 ── */
  if (Math.random() < 0.13) spawnFlow();
  for (j = S.flow.length - 1; j >= 0; j--){
    var p = S.flow[j];
    p.x += p.sp * dt / 1000;
    /* 到达目标塔：捕获 */
    if (p.tgt >= 0 && p.x >= TOWER_X[p.tgt] - 4){
      S.layers[p.tgt].flash = 1;
      S.caps.push({x: TOWER_X[p.tgt], y: FLOW_Y, vy: 0, hue: LAYERS[p.tgt].hue, life: 1});
      S.flow.splice(j, 1);
      continue;
    }
    /* 到达出口：放行吸收 */
    if (p.x >= OUTLET_X - 20){
      S.absorbs.push({r: 20, a: 0.7});
      S.flow.splice(j, 1);
      continue;
    }
    /* 绘制：光点 + 尾迹 */
    c.fillStyle = 'rgba(190,242,255,.95)';
    c.shadowColor = 'rgba(34,211,238,1)'; c.shadowBlur = 8;
    c.beginPath(); c.arc(p.x, p.y, 2.1, 0, Math.PI * 2); c.fill();
    c.shadowBlur = 0;
    c.strokeStyle = 'rgba(34,211,238,.35)'; c.lineWidth = 1.4;
    c.beginPath(); c.moveTo(p.x - 16, p.y); c.lineTo(p.x, p.y); c.stroke();
  }
  /* 捕获下坠粒子（被塔吸收） */
  for (j = S.caps.length - 1; j >= 0; j--){
    var cp = S.caps[j];
    cp.vy += 0.35; cp.y += cp.vy; cp.life -= 0.03;
    if (cp.life <= 0 || cp.y > BASE_Y - 6){ S.caps.splice(j, 1); continue; }
    c.fillStyle = 'hsla(' + cp.hue + ',95%,66%,' + Math.min(1, cp.life * 1.6).toFixed(3) + ')';
    c.shadowColor = 'hsla(' + cp.hue + ',95%,60%,1)'; c.shadowBlur = 10;
    c.beginPath(); c.arc(cp.x, cp.y, 3, 0, Math.PI * 2); c.fill();
    c.shadowBlur = 0;
  }
  /* 出口吸收环 */
  for (j = S.absorbs.length - 1; j >= 0; j--){
    var ab = S.absorbs[j];
    ab.r += 1.6; ab.a -= 0.03;
    if (ab.a <= 0){ S.absorbs.splice(j, 1); continue; }
    c.strokeStyle = 'rgba(52,211,153,' + ab.a.toFixed(3) + ')';
    c.lineWidth = 1.6;
    c.beginPath(); c.arc(OUTLET_X, FLOW_Y, ab.r, 0, Math.PI * 2); c.stroke();
  }
  c.restore();
  c.textAlign = 'left';
}

/* ═══════════════ 底部：通过剖面流带 ═══════════════ */
var pf = {cv: null, cx: null, w: 0, h: 0};
var pfCur = null;   // 当前动画值 {total, layers[5], allow}

function drawProfile(t){
  if (!pf.cx) return;
  var c = pf.cx, W = pf.w, H = pf.h;
  c.clearRect(0, 0, W, H);
  var total = S.total, allow = S.allows;
  if (total <= 0){
    c.fillStyle = 'rgba(148,197,255,.4)';
    c.font = '600 24px Consolas, monospace';
    c.fillText('剖面采样中…', 24, H / 2);
    return;
  }
  /* sqrt 缩放厚度（拦截占比小但须可见） */
  var maxT = H * 0.52;
  var f = function(v){ return Math.sqrt(Math.max(v, 0) / total) * maxT; };
  /* 动画缓动 */
  var tgt = {total: f(total), allow: f(allow), layers: S.layers.map(function(l){ return f(l.count); })};
  if (!pfCur) pfCur = JSON.parse(JSON.stringify(tgt));
  var k = 0.06;
  pfCur.total += (tgt.total - pfCur.total) * k;
  pfCur.allow += (tgt.allow - pfCur.allow) * k;
  for (var i = 0; i < 5; i++) pfCur.layers[i] += (tgt.layers[i] - pfCur.layers[i]) * k;

  var yc = H * 0.40;
  var x0 = 10, x1 = W - 150;
  var bx = [];   // 分流点 x
  for (i = 0; i < 5; i++) bx.push(x0 + 190 + i * ((x1 - x0 - 320) / 4));

  /* 主带：左→右逐渐变细 */
  var x, remain, peelSum;
  c.beginPath();
  var topPts = [], botPts = [];
  for (x = x0; x <= x1; x += 8){
    remain = pfCur.total;
    for (i = 0; i < 5; i++) if (x > bx[i]) remain -= pfCur.layers[i];
    remain = Math.max(remain, pfCur.allow);
    topPts.push([x, yc - remain / 2]);
    botPts.push([x, yc + remain / 2]);
  }
  c.beginPath();
  c.moveTo(topPts[0][0], topPts[0][1]);
  for (i = 1; i < topPts.length; i++) c.lineTo(topPts[i][0], topPts[i][1]);
  for (i = botPts.length - 1; i >= 0; i--) c.lineTo(botPts[i][0], botPts[i][1]);
  c.closePath();
  var gm = c.createLinearGradient(x0, 0, x1, 0);
  gm.addColorStop(0, 'rgba(34,211,238,.34)');
  gm.addColorStop(0.8, 'rgba(34,211,238,.20)');
  gm.addColorStop(1, 'rgba(52,211,153,.30)');
  c.fillStyle = gm;
  c.fill();
  c.strokeStyle = 'rgba(126,231,252,.55)'; c.lineWidth = 1.4;
  c.stroke();

  /* 五条分流（向下汇入拦截池） */
  for (i = 0; i < 5; i++){
    var th = pfCur.layers[i];
    if (th < 1.5) th = 1.5;   // 最小可见
    var active = S.layers[i].active;
    var colB = active ? LAYERS[i].color : '#64748b';
    var sx = bx[i], syTop = yc + pfCur.total / 2 - 2;
    for (var q = 0; q < i; q++) syTop -= 0;   // 占位：分支从主带底缘分出
    /* 分流曲线 */
    var ey = H - 30;
    c.beginPath();
    c.moveTo(sx - th / 2, syTop);
    c.quadraticCurveTo(sx - th / 2, syTop + (ey - syTop) * 0.55, sx - th / 2 - 8, ey);
    c.lineTo(sx + th / 2 - 8, ey);
    c.quadraticCurveTo(sx + th / 2, syTop + (ey - syTop) * 0.55, sx + th / 2, syTop);
    c.closePath();
    c.fillStyle = colB + '55';
    c.fill();
    c.strokeStyle = colB + 'cc';
    c.lineWidth = 1.2;
    c.stroke();
    /* 分支标签 */
    c.textAlign = 'center';
    c.fillStyle = active ? colB : 'rgba(100,116,139,.8)';
    c.font = '700 19px Consolas, monospace';
    c.fillText(LAYERS[i].tag, sx - 8, ey + 24);
    c.font = '600 14px "Microsoft YaHei", sans-serif';
    c.fillStyle = 'rgba(190,224,255,.7)';
    c.fillText(fmt(S.layers[i].count), sx - 8, ey + 42);
    c.textAlign = 'left';
  }

  /* 左端 / 右端大数字 */
  c.textAlign = 'left';
  c.fillStyle = 'rgba(234,246,255,.95)';
  c.font = '700 26px Consolas, monospace';
  c.shadowColor = 'rgba(34,211,238,.6)'; c.shadowBlur = 10;
  c.fillText(fmt(total), x0 + 4, yc - pfCur.total / 2 - 14);
  c.shadowBlur = 0;
  c.font = '600 11px "Microsoft YaHei", sans-serif';
  c.fillStyle = 'rgba(148,197,255,.6)';
  c.fillText('查询总量', x0 + 4, yc - pfCur.total / 2 - 40);
  c.textAlign = 'right';
  c.fillStyle = 'rgba(233,255,246,.95)';
  c.font = '700 26px Consolas, monospace';
  c.shadowColor = 'rgba(52,211,153,.6)'; c.shadowBlur = 10;
  c.fillText(fmt(allow), W - 12, yc - pfCur.allow / 2 - 14);
  c.shadowBlur = 0;
  c.font = '600 11px "Microsoft YaHei", sans-serif';
  c.fillStyle = 'rgba(110,231,183,.65)';
  c.fillText('穿越放行', W - 12, yc - pfCur.allow / 2 - 40);
  c.textAlign = 'left';
}

/* ═══════════════ 渲染：事件流（瀑布 + 层徽章） ═══════════════ */
var evNodes = {};
function renderStream(items){
  var box = $('eventStream');
  var newest = items[0];
  if (!S.streamReady){
    box.innerHTML = '';
    evNodes = {};
    if (!items.length){
      box.innerHTML = '<div class="stream-empty">今日暂无拦截事件 · 链路静默</div>';
    }
    for (var i = items.length - 1; i >= 0; i--) box.appendChild(evRow(items[i], false));
    while (box.children.length > STREAM_SIZE && box.firstChild){
      var fc = box.firstChild;
      if (fc.dataset && fc.dataset.eid) delete evNodes[fc.dataset.eid];
      fc.remove();
    }
    S.streamReady = true;
  } else {
    for (var j = items.length - 1; j >= 0; j--){
      var it = items[j];
      if (it.id <= S.lastStreamId || evNodes[it.id]) continue;
      var row = evRow(it, true);
      row.style.height = '0px';
      row.style.opacity = '0';
      box.appendChild(row);
      var em = box.querySelector('.stream-empty');
      if (em) em.remove();
      (function(r){
        requestAnimationFrame(function(){
          r.style.height = EV_ROW_H + 'px';
          r.style.opacity = '1';
        });
      })(row);
      /* 联动：对应层塔爆闪 + 捕获粒子 */
      var li = reasonToLayer(it.filter_reason);
      S.layers[li].flash = 1;
      S.caps.push({x: TOWER_X[li], y: FLOW_Y, vy: 0, hue: LAYERS[li].hue, life: 1});
      spawnMeteor();
    }
    while (box.children.length > STREAM_SIZE && box.firstChild){
      var old = box.firstChild;
      if (old.dataset && old.dataset.eid) delete evNodes[old.dataset.eid];
      if (old.classList && old.classList.contains('ev')){
        old.style.height = '0px';
        old.style.opacity = '0';
        old.addEventListener('transitionend', function h(e){
          e.target.removeEventListener('transitionend', h);
          if (e.target.parentNode) e.target.remove();
        });
      } else {
        old.remove();
      }
    }
  }
  if (newest) S.lastStreamId = Math.max(S.lastStreamId, newest.id);
}
function evRow(it, fresh){
  var row = document.createElement('div');
  row.className = 'ev' + (it.action === 'remove_ip' ? ' remove' : '');
  if (fresh) row.classList.add('born');
  row.dataset.eid = it.id;
  var li = reasonToLayer(it.filter_reason);
  var lc = LAYERS[li].color;
  row.innerHTML =
    '<span class="tm">' + esc(hms(it.timestamp)) + '</span>' +
    '<span class="ly" style="color:' + lc + ';border-color:' + lc + '55;background:' + lc + '18">' +
      LAYERS[li].tag + '</span>' +
    '<span class="dm" title="' + esc(it.domain) + '">' + esc(it.domain) + '</span>' +
    '<span class="cl">' + esc(it.client_ip || '-') + ' · ' + esc(reasonShort(it.filter_reason)) + '</span>';
  evNodes[it.id] = row;
  return row;
}

/* ═══════════════ 渲染：总览 / 五层读数 / 链路状态 ═══════════════ */
function renderStatus(d){
  var total = d.today_total || 0;
  var inter = d.today_intercepts || 0;
  var rem = d.today_removes || 0;
  var blocked = inter + rem;
  var allows = Math.max(0, total - blocked);
  var rate = total > 0 ? blocked / total * 100 : 0;
  S.total = total; S.blocked = blocked; S.allows = allows; S.rate = rate;

  countUp($('ovTotal'), total);
  countUp($('ovBlocked'), blocked);
  countUp($('ovAllow'), allows);
  $('ovRate').textContent = total > 0 ? '拦截率 ' + rate.toFixed(1) + '%' : '链路静默';
  $('ovPass').textContent = total > 0 ? '通过率 ' + (100 - rate).toFixed(1) + '%' : '--';

  var hd = $('hdDetect');
  hd.className = 'hd-light ' + (d.detection_enabled ? 'ok' : 'bad');
  hd.querySelector('b').textContent = d.detection_enabled ? 'ONLINE' : 'OFFLINE';

  /* 全场威胁联动（同视角 A 口径） */
  var lvl = 'steady';
  if (total === 0) lvl = 'standby';
  else if (rate >= 15) lvl = 'danger';
  else if (rate >= 8) lvl = 'warn';
  document.getElementById('stage').dataset.level = lvl;
}

function renderLayers(list){
  var sum = 0, i;
  for (i = 0; i < 5; i++){
    var hit = list.filter(function(x){ return x.key === LAYERS[i].key; })[0];
    S.layers[i].count = hit ? hit.count : 0;
    S.layers[i].active = hit ? !!hit.active : true;
    sum += S.layers[i].count;
  }
  for (i = 0; i < 5; i++) S.layers[i].share = sum > 0 ? S.layers[i].count / sum : 0;

  /* 左翼五层读数行 */
  $('layerRows').innerHTML = LAYERS.map(function(ly, i){
    var Ld = S.layers[i];
    return '<div class="lr-row ' + (Ld.active ? 'on' : 'off') + '">' +
      '<span class="dot" style="background:' + ly.color + ';color:' + ly.color + '"></span>' +
      '<span class="tx"><span class="nm"><b>' + ly.tag + '</b>' + ly.name + '</span></span>' +
      '<span class="vl">' + fmt(Ld.count) + '</span>' +
      '<span class="st">' + (Ld.active ? '在线' : '停用') + '</span>' +
      '<span class="bar"><i data-w="' + (Ld.share * 100).toFixed(1) +
        '" style="background:' + ly.color + ';color:' + ly.color + '"></i></span>' +
      '</div>';
  }).join('');
  requestAnimationFrame(function(){
    var bars = $('layerRows').querySelectorAll('.bar i');
    for (var i2 = 0; i2 < bars.length; i2++) bars[i2].style.width = bars[i2].dataset.w + '%';
  });
}

function renderDefense(d){
  var rows = [];
  var det = d.status.detection_enabled;
  rows.push({n: '检测引擎', v: det ? 'ONLINE' : 'OFFLINE', cls: det ? 'ok' : 'bad'});
  var up = (d.breaker && d.breaker.upstream && d.breaker.upstream.state) || 'closed';
  rows.push({
    n: '上游熔断器',
    v: up === 'closed' ? 'STABLE' : (up === 'open' ? 'BROKEN' : 'PROBING'),
    cls: up === 'closed' ? 'ok' : (up === 'open' ? 'bad' : 'warn')
  });
  var wan = d.offlineRows >= 10000 ? (d.offlineRows / 10000).toFixed(1) + ' 万条' : fmt(d.offlineRows) + ' 条';
  rows.push({n: '离线情报库', v: wan + ' · ' + d.offlineSrc + ' 源', cls: d.offlineRows > 0 ? 'ok' : 'bad'});
  rows.push({
    n: '统计口径',
    v: d.status.stats_source === 'query_stats' ? '全量精确' : '日志估算',
    cls: d.status.stats_source === 'query_stats' ? 'ok' : 'warn'
  });
  $('defMatrix').innerHTML = rows.map(function(r){
    return '<div class="def-row ' + r.cls + '"><span class="dl"></span>' +
           '<span class="dn">' + r.n + '</span><span class="dv">' + r.v + '</span></div>';
  }).join('');
}

/* ═══════════════ 轮询调度 ═══════════════ */
function pollStatus(){
  return api('/api/status').then(renderStatus).catch(function(){});
}
function pollStream(){
  return api('/api/logs/stream?size=' + STREAM_SIZE).then(function(d){
    renderStream((d && d.items) || []);
  }).catch(function(){});
}
function pollLayers(){
  return api('/api/status/layers?scope=today').then(function(d){
    renderLayers((d && d.layers) || []);
  }).catch(function(){});
}
function pollDefense(){
  Promise.all([
    api('/api/status'),
    api('/api/circuit-breaker/stats').catch(function(){ return null; }),
    api('/api/threatlist/sources').catch(function(){ return null; })
  ]).then(function(rs){
    var status = rs[0], breaker = rs[1], sources = rs[2];
    var rows = 0, srcCnt = 0;
    if (sources && sources.items){
      sources.items.forEach(function(s){
        rows += s.total || 0;
        srcCnt++;
      });
    }
    renderDefense({status: status, breaker: breaker, offlineRows: rows, offlineSrc: srcCnt});
    var up = breaker && breaker.upstream && breaker.upstream.state || 'closed';
    var hd = $('hdUpstream');
    hd.className = 'hd-light ' + (up === 'closed' ? 'ok' : (up === 'open' ? 'bad' : 'warn'));
    hd.querySelector('b').textContent =
      up === 'closed' ? 'STABLE' : (up === 'open' ? 'BROKEN' : 'PROBING');
  }).catch(function(){});
}

/* ═══════════════ 启动 ═══════════════ */
var timers = [];
function bootData(){
  if (S.booted) return;
  S.booted = true;
  pollStatus(); pollStream(); pollLayers(); pollDefense();
  timers.push(setInterval(pollStatus, 10000));
  timers.push(setInterval(pollStream, 3000));
  timers.push(setInterval(pollLayers, 60000));
  timers.push(setInterval(pollDefense, 15000));
}

function sizeCanvases(){
  var el = $('profileCanvas');
  if (el){
    var stageRect = document.getElementById('stage').getBoundingClientRect();
    var scale = stageRect.width / STAGE_W || 1;
    var r = el.getBoundingClientRect();
    pf.w = Math.max(80, Math.round(r.width / scale)) * 2;
    pf.h = Math.max(50, Math.round(r.height / scale)) * 2;
    el.width = pf.w; el.height = pf.h;
    pf.cx = el.getContext('2d');
  }
}

function loop(t){
  drawBg(t || 0);
  drawChain(t || 0);
  drawProfile(t || 0);
  requestAnimationFrame(loop);
}

fit();
initBg();
initChain();
requestAnimationFrame(function(){ sizeCanvases(); });
requestAnimationFrame(loop);

if (S.token) bootData(); else showLogin();

})();

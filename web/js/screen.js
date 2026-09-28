/* ══════════════════════════════════════════════════════════════
   DNS 安全态势感知平台 · 全息大屏
   数据：复用平台既有 API（Bearer 鉴权与管理端同源）
   渲染：5 个 Canvas（星尘背景 / 全息核心 / 趋势 / 吞吐波形）+ DOM
   ══════════════════════════════════════════════════════════════ */
(function(){
'use strict';

/* ── 常量 ───────────────────────────────────────────────── */
var STAGE_W = 1920, STAGE_H = 1080;
var STREAM_SIZE = 12;
var REASON_MAP = {
  local_blacklist: '本地名单',
  ip_filter: 'IP 过滤',
  'degraded:failsafe': '降级保护',
  nrd: 'NRD',
  nrd_offline: 'NRD 离线'
};
var SOURCE_COLORS = {
  local_blacklist: '#fb4d6d',
  threat_list: '#22d3ee',
  threatintel: '#a78bfa',
  ip_filter: '#fbbf24'
};

/* ── 全局状态 ───────────────────────────────────────────── */
var S = {
  token: localStorage.getItem('dnsf_token') || '',
  lastStreamId: 0,
  streamReady: false,
  lastTotal: null, lastTotalAt: 0,
  qps: 0,
  wave: [],
  trend: null,
  _breaker: null,
  _lastStatus: null,
  core: {
    intensity: 0.35, intensityT: 0.35,
    levelT: 0, levelTarget: 0,
    rot: 0, blips: [], shocks: []
  },
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
window.addEventListener('resize', function(){ fit(); sizeDomCanvases(); });

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
function reasonShort(r){
  if (!r) return '未知';
  if (REASON_MAP[r]) return REASON_MAP[r];
  if (r.indexOf('threat_list:') === 0) return r.slice(12);
  if (r.indexOf('threatintel:') === 0) return r.slice(12);
  if (r.indexOf('nrd') === 0) return 'NRD';
  return r.length > 14 ? r.slice(0, 14) : r;
}
/* 数字滚动：dec=保留小数位 */
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
  /* token 过期：暂停轮询避免空打，待重新登录后恢复 */
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

/* ── 时钟 ───────────────────────────────────────────────── */
var WEEK = ['日','一','二','三','四','五','六'];
function tickClock(){
  var d = new Date();
  $('scrClock').textContent = pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  $('scrDate').textContent = d.getFullYear() + ' 年 ' + pad2(d.getMonth() + 1) + ' 月 ' +
    pad2(d.getDate()) + ' 日 · 星期' + WEEK[d.getDay()];
}
setInterval(tickClock, 1000); tickClock();

/* ── 全屏 ───────────────────────────────────────────────── */
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
  var i;
  for (i = 0; i < 130; i++){
    bg.stars.push({
      x: Math.random() * STAGE_W, y: Math.random() * STAGE_H * 0.75,
      r: Math.random() * 1.4 + 0.3, a: Math.random() * 0.5 + 0.1,
      vx: (Math.random() - 0.5) * 0.08, ph: Math.random() * 6.28
    });
  }
}
function spawnMeteor(x){
  bg.meteors.push({x: x == null ? Math.random() * STAGE_W : x, y: -10, vy: 3 + Math.random() * 3, life: 1});
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

/* ═══════════════ 中央全息核心 ═══════════════ */
var core = {cv: null, cx: null, W: 820, H: 820};
function initCore(){
  core.cv = $('coreCanvas');
  core.cv.width = core.W; core.cv.height = core.H;
  core.cx = core.cv.getContext('2d');
}
function coreHue(){
  /* levelT: 0→青190  0.5→琥珀42  1→红348 */
  var t = S.core.levelT, h;
  if (t < 0.5) h = 190 + (42 - 190) * (t * 2);
  else h = 42 + (348 - 42) * ((t - 0.5) * 2);
  return h;
}
function coreAddBlip(kind){
  var c = S.core;
  c.blips.push({
    ang: Math.random() * Math.PI * 2,
    spd: (0.15 + Math.random() * 0.3) * (Math.random() < 0.5 ? 1 : -1),
    rad: 288 + Math.random() * 40,
    size: 2 + Math.random() * 2.5,
    kind: kind || 'intercept',
    life: 1
  });
  if (c.blips.length > 42) c.blips.splice(0, c.blips.length - 42);
  c.shocks.push({r: 100, a: 0.9, kind: kind || 'intercept'});
  if (c.shocks.length > 6) c.shocks.splice(0, c.shocks.length - 6);
}
function drawCore(t){
  var c = core.cx, W = core.W, cx = W / 2, cy = W / 2;
  var st = S.core;
  var dt = 16.7;
  /* 缓动逼近目标态 */
  st.intensity += (st.intensityT - st.intensity) * 0.02;
  st.levelT += (st.levelTarget - st.levelT) * 0.02;
  st.rot += 0.0016;
  var hue = coreHue();
  var inten = st.intensity;
  var col = function(a){ return 'hsla(' + hue + ',92%,62%,' + a + ')'; };

  c.clearRect(0, 0, W, W);
  c.save();
  c.globalCompositeOperation = 'lighter';

  /* 1. 底部辉光 */
  var pulse = 1 + Math.sin(t / 900) * 0.05 * inten;
  var g0 = c.createRadialGradient(cx, cy, 0, cx, cy, 400);
  g0.addColorStop(0, col(0.16 * inten));
  g0.addColorStop(0.55, col(0.05 * inten));
  g0.addColorStop(1, 'hsla(0,0%,0%,0)');
  c.fillStyle = g0;
  c.fillRect(0, 0, W, W);

  /* 2. 刻度环 */
  c.save();
  c.translate(cx, cy); c.rotate(st.rot * 0.35);
  c.strokeStyle = col(0.4); c.lineWidth = 1;
  var i, a;
  for (i = 0; i < 90; i++){
    a = i / 90 * Math.PI * 2;
    var len = (i % 15 === 0) ? 14 : 6;
    c.globalAlpha = (i % 15 === 0) ? 0.5 : 0.22;
    c.beginPath();
    c.moveTo(Math.cos(a) * 372, Math.sin(a) * 372);
    c.lineTo(Math.cos(a) * (372 + len), Math.sin(a) * (372 + len));
    c.stroke();
  }
  c.restore(); c.globalAlpha = 1;

  /* 3. 双向虚线环 */
  c.save(); c.translate(cx, cy);
  c.rotate(st.rot);
  c.setLineDash([3, 9]); c.strokeStyle = col(0.35); c.lineWidth = 1;
  c.beginPath(); c.arc(0, 0, 348, 0, Math.PI * 2); c.stroke();
  c.rotate(-st.rot * 2.4);
  c.setLineDash([30, 18]); c.strokeStyle = col(0.5); c.lineWidth = 1.4;
  c.beginPath(); c.arc(0, 0, 328, 0, Math.PI * 2); c.stroke();
  c.setLineDash([]);
  c.restore();

  /* 4. 扫描扇 */
  if (c.createConicGradient){
    var sw = c.createConicGradient(st.rot * 1.8, cx, cy);
    sw.addColorStop(0, col(0));
    sw.addColorStop(0.08, col(0.10 + 0.08 * inten));
    sw.addColorStop(0.14, col(0));
    sw.addColorStop(1, col(0));
    c.fillStyle = sw;
    c.beginPath(); c.arc(cx, cy, 340, 0, Math.PI * 2); c.fill();
  }

  /* 5. 线框球体（伪 3D 全息地球） */
  var R = 280 * pulse, tilt = 0.34;
  c.lineWidth = 1;
  var lat, phi;
  for (lat = -60; lat <= 60; lat += 20){
    phi = lat * Math.PI / 180;
    var rx = R * Math.cos(phi), ry = rx * tilt, oy = R * Math.sin(phi) * 0.55;
    c.strokeStyle = col(lat === 0 ? 0.32 : 0.16);
    c.beginPath(); c.ellipse(cx, cy + oy, rx, ry, 0, 0, Math.PI * 2); c.stroke();
  }
  var M = 9, k;
  for (k = 0; k < M; k++){
    var th = st.rot * 2 + k / M * Math.PI;
    var mx = Math.abs(Math.cos(th)) * R;
    var edge = Math.cos(th) > 0 ? 0.20 : 0.08;
    c.strokeStyle = col(edge);
    c.beginPath(); c.ellipse(cx, cy, mx, R * 0.96, 0, 0, Math.PI * 2); c.stroke();
  }
  /* 球缘 */
  c.strokeStyle = col(0.55); c.lineWidth = 1.6;
  c.beginPath(); c.arc(cx, cy, R, 0, Math.PI * 2); c.stroke();
  c.strokeStyle = col(0.12); c.lineWidth = 5;
  c.beginPath(); c.arc(cx, cy, R, 0, Math.PI * 2); c.stroke();

  /* 6. 等离子能量核 */
  var pr = 96 * pulse + inten * 26;
  var g1 = c.createRadialGradient(cx, cy, 0, cx, cy, pr * 1.7);
  g1.addColorStop(0, 'hsla(' + hue + ',100%,88%,' + (0.85 * inten + 0.15) + ')');
  g1.addColorStop(0.35, col(0.5 * inten + 0.12));
  g1.addColorStop(0.75, col(0.12));
  g1.addColorStop(1, 'hsla(0,0%,0%,0)');
  c.fillStyle = g1;
  c.beginPath(); c.arc(cx, cy, pr * 1.7, 0, Math.PI * 2); c.fill();
  /* 内核电弧 */
  c.strokeStyle = col(0.35); c.lineWidth = 1;
  for (i = 0; i < 3; i++){
    a = t / 700 + i * 2.09;
    c.beginPath();
    c.arc(cx, cy, pr * (0.75 + 0.2 * Math.sin(t / 500 + i)), a, a + 1.4);
    c.stroke();
  }

  /* 7. 威胁光点（事件驱动） */
  for (i = st.blips.length - 1; i >= 0; i--){
    var b = st.blips[i];
    b.ang += b.spd * dt / 1000;
    b.life -= dt / 45000;
    if (b.life <= 0){ st.blips.splice(i, 1); continue; }
    var bx = cx + Math.cos(b.ang) * b.rad;
    var by = cy + Math.sin(b.ang) * b.rad * 0.98;
    var bhue = b.kind === 'remove' ? 42 : 348;
    var ba = Math.min(1, b.life * 3);
    c.fillStyle = 'hsla(' + bhue + ',95%,64%,' + (0.9 * ba) + ')';
    c.shadowColor = 'hsla(' + bhue + ',95%,60%,1)';
    c.shadowBlur = 12;
    c.beginPath(); c.arc(bx, by, b.size, 0, Math.PI * 2); c.fill();
    c.shadowBlur = 0;
    /* 拖尾 */
    c.strokeStyle = 'hsla(' + bhue + ',95%,64%,' + (0.25 * ba) + ')';
    c.lineWidth = 1.2;
    c.beginPath();
    c.arc(cx, cy, b.rad, b.ang - 0.3 * Math.sign(b.spd), b.ang, b.spd < 0);
    c.stroke();
  }

  /* 8. 拦截冲击波 */
  for (i = st.shocks.length - 1; i >= 0; i--){
    var sh = st.shocks[i];
    sh.r += 3.4; sh.a -= 0.011;
    if (sh.a <= 0){ st.shocks.splice(i, 1); continue; }
    var shhue = sh.kind === 'remove' ? 42 : 348;
    c.strokeStyle = 'hsla(' + shhue + ',95%,64%,' + sh.a.toFixed(3) + ')';
    c.lineWidth = 2;
    c.beginPath(); c.arc(cx, cy, sh.r, 0, Math.PI * 2); c.stroke();
  }

  c.restore();
}

/* ═══════════════ 趋势图（24H） ═══════════════ */
var tr = {cv: null, cx: null, w: 0, h: 0};
function sizeDomCanvases(){
  var stageRect = document.getElementById('stage').getBoundingClientRect();
  var scale = stageRect.width / STAGE_W || 1;   // 舞台实际缩放比
  [ ['trendCanvas', tr], ['waveCanvas', wv] ].forEach(function(pair){
    var el = $(pair[0]), o = pair[1];
    if (!el) return;
    var r = el.getBoundingClientRect();
    /* getBoundingClientRect 含舞台 transform，换算回舞台坐标系 */
    var w = Math.max(80, Math.round(r.width / scale));
    var h = Math.max(50, Math.round(r.height / scale));
    o.w = w * 2; o.h = h * 2;   // 2x 保证清晰
    el.width = o.w; el.height = o.h;
    o.cv = el; o.cx = el.getContext('2d');
  });
  if (S.trend) drawTrend();
  drawWave();
}
function drawTrend(){
  if (!tr.cx || !S.trend) return;
  var c = tr.cx, W = tr.w, H = tr.h;
  var items = S.trend;
  c.clearRect(0, 0, W, H);
  var padL = 10, padR = 10, padT = 16, padB = 34;
  var cw = W - padL - padR, ch = H - padT - padB;
  var max = 1, i;
  for (i = 0; i < items.length; i++)
    max = Math.max(max, items[i].intercepts + items[i].removes);
  max *= 1.15;
  /* 网格 */
  c.strokeStyle = 'rgba(94,160,220,.14)'; c.lineWidth = 1;
  var gy;
  for (i = 1; i <= 3; i++){
    gy = padT + ch * i / 4;
    c.beginPath(); c.moveTo(padL, gy); c.lineTo(W - padR, gy); c.stroke();
  }
  var n = items.length, bw = cw / n;
  /* 柱：拦截红 + 剔除琥珀 堆叠 */
  for (i = 0; i < n; i++){
    var it = items[i];
    var x = padL + i * bw + bw * 0.2;
    var bwid = bw * 0.6;
    var hi = ch * it.intercepts / max, hr = ch * it.removes / max;
    var last = (i === n - 1);
    c.fillStyle = last ? 'rgba(251,77,109,.95)' : 'rgba(251,77,109,.62)';
    c.fillRect(x, padT + ch - hi, bwid, hi);
    c.fillStyle = last ? 'rgba(251,191,36,.95)' : 'rgba(251,191,36,.55)';
    c.fillRect(x, padT + ch - hi - hr, bwid, hr);
  }
  /* 总量平滑曲线 */
  c.strokeStyle = 'rgba(126,231,252,.9)'; c.lineWidth = 2.4;
  c.shadowColor = 'rgba(34,211,238,.8)'; c.shadowBlur = 10;
  c.beginPath();
  var pts = [];
  for (i = 0; i < n; i++){
    pts.push([padL + i * bw + bw / 2,
              padT + ch - ch * (items[i].intercepts + items[i].removes) / max]);
  }
  c.moveTo(pts[0][0], pts[0][1]);
  for (i = 1; i < pts.length; i++){
    var xc = (pts[i - 1][0] + pts[i][0]) / 2, yc = (pts[i - 1][1] + pts[i][1]) / 2;
    c.quadraticCurveTo(pts[i - 1][0], pts[i - 1][1], xc, yc);
  }
  c.lineTo(pts[pts.length - 1][0], pts[pts.length - 1][1]);
  c.stroke();
  c.shadowBlur = 0;
  /* X 轴刻度（每 4 小时），画布 2x 分辨率，字号同步 2x */
  c.fillStyle = 'rgba(148,197,255,.5)';
  c.font = '600 21px Consolas, monospace';
  c.textAlign = 'center';
  for (i = 0; i < n; i += 4){
    c.fillText(items[i].hour.slice(11, 13) + '时',
               padL + i * bw + bw / 2, H - 10);
  }
  c.textAlign = 'left';
}
/* 平滑补间动画：趋势数据更新时重绘即可（低频 60s） */

/* ═══════════════ 底部吞吐波形 ═══════════════ */
var wv = {cv: null, cx: null, w: 0, h: 0};
var WAVE_LEN = 220;
function pushWave(q, ic){
  S.wave.push({q: q, i: ic});
  if (S.wave.length > WAVE_LEN) S.wave.splice(0, S.wave.length - WAVE_LEN);
}
function drawWave(){
  if (!wv.cx) return;
  var c = wv.cx, W = wv.w, H = wv.h;
  c.clearRect(0, 0, W, H);
  var data = S.wave;
  if (data.length < 2){
    c.fillStyle = 'rgba(148,197,255,.4)';
    c.font = '600 24px Consolas, monospace';
    c.fillText('吞吐采样中…', 24, H / 2);
    return;
  }
  var padT = 14, padB = 8, ch = H - padT - padB;
  var qmax = 1, imax = 1, i;
  for (i = 0; i < data.length; i++){
    qmax = Math.max(qmax, data[i].q);
    imax = Math.max(imax, data[i].i);
  }
  qmax *= 1.2;
  var n = data.length, bw = W / WAVE_LEN;
  /* QPS 面积波 */
  var x0 = W - n * bw;
  var g = c.createLinearGradient(0, padT, 0, H);
  g.addColorStop(0, 'rgba(34,211,238,.34)');
  g.addColorStop(1, 'rgba(34,211,238,.02)');
  c.beginPath();
  c.moveTo(x0, H - padB);
  for (i = 0; i < n; i++)
    c.lineTo(x0 + i * bw, padT + ch * (1 - data[i].q / qmax));
  c.lineTo(x0 + (n - 1) * bw, H - padB);
  c.closePath();
  c.fillStyle = g; c.fill();
  /* 波峰线 */
  c.strokeStyle = 'rgba(126,231,252,.95)'; c.lineWidth = 2;
  c.shadowColor = 'rgba(34,211,238,.7)'; c.shadowBlur = 8;
  c.beginPath();
  for (i = 0; i < n; i++){
    var x = x0 + i * bw, y = padT + ch * (1 - data[i].q / qmax);
    if (i === 0) c.moveTo(x, y); else c.lineTo(x, y);
  }
  c.stroke(); c.shadowBlur = 0;
  /* 拦截脉冲（红） */
  for (i = 0; i < n; i++){
    if (data[i].i <= 0) continue;
    var ih = Math.min(1, data[i].i / imax) * (ch * 0.8) + 4;
    var ix = x0 + i * bw;
    var ig = c.createLinearGradient(0, H - padB - ih, 0, H - padB);
    ig.addColorStop(0, 'rgba(251,77,109,.85)');
    ig.addColorStop(1, 'rgba(251,77,109,.05)');
    c.fillStyle = ig;
    c.fillRect(ix - 1, H - padB - ih, 2.4, ih);
  }
}

/* ═══════════════ 渲染：状态/芯片/威胁指数 ═══════════════
   威胁指数算法（0~100）：避免与拦截率重复显示
     基础分 = 拦截率 × 4（25% 拦截率 = 100 分）
     增速分 = 近 1h 拦截占全天比 × 40%（突发放大）
     多样分 = 活跃来源数 × 6（多源并发攻击加分）
     熔断分 = 上游熔断开启 +20
*/
function calcThreatIndex(d, hourlyItems, breaker){
  var total = d.today_total || 0;
  var blocked = (d.today_intercepts || 0) + (d.today_removes || 0);
  if (total === 0) return {idx: 0, level: 'standby'};
  var rate = blocked / total * 100;

  /* 增速：近 1h 占全天 */
  var recent = 0;
  if (hourlyItems && hourlyItems.length){
    recent = hourlyItems[hourlyItems.length - 1].intercepts +
             hourlyItems[hourlyItems.length - 1].removes;
  }
  var recentPct = blocked > 0 ? Math.min(1, recent / Math.max(blocked, 1)) : 0;

  /* 来源多样 */
  var srcCount = 0;
  if (hourlyItems && hourlyItems.length){
    var last = hourlyItems[hourlyItems.length - 1];
    if (last.local_blacklist > 0) srcCount++;
    if (last.threat_list > 0) srcCount++;
    if (last.threatintel > 0) srcCount++;
    if (last.ip_filter > 0) srcCount++;
  }

  /* 熔断加成 */
  var breakerOpen = breaker && breaker.upstream && breaker.upstream.state === 'open';

  var idx = rate * 4 + recentPct * 40 + srcCount * 6 + (breakerOpen ? 20 : 0);
  idx = Math.min(100, Math.round(idx));

  var level = idx >= 70 ? 'severe' : (idx >= 45 ? 'elevated' : (idx >= 15 ? 'guarded' : 'steady'));
  return {idx: idx, level: level, rate: rate};
}

function renderStatus(d){
  var total = d.today_total || 0;
  var inter = d.today_intercepts || 0;
  var rem = d.today_removes || 0;
  var rate = total > 0 ? (inter + rem) / total * 100 : 0;

  countUp($('chipTotal'), total);
  countUp($('chipInter'), inter);
  countUp($('chipRemove'), rem);
  countUp($('chipRate'), rate, '%', 1);

  var th = calcThreatIndex(d, S.trend, S._breaker);
  var idx = $('threatIndex');
  countUp(idx, th.idx, '', 0);
  var lv = $('threatLevel');
  idx.classList.remove('warn', 'danger');
  lv.classList.remove('warn', 'danger');
  if (th.level === 'standby'){
    idx.textContent = '--';
    lv.textContent = '静默待机 · STANDBY';
    S.core.intensityT = 0.3; S.core.levelTarget = 0;
  } else if (th.level === 'severe'){
    lv.textContent = '高危态势 · SEVERE';
    idx.classList.add('danger'); lv.classList.add('danger');
    S.core.intensityT = 1.0; S.core.levelTarget = 1;
  } else if (th.level === 'elevated'){
    lv.textContent = '威胁升高 · ELEVATED';
    idx.classList.add('warn'); lv.classList.add('warn');
    S.core.intensityT = 0.78; S.core.levelTarget = 0.5;
  } else if (th.level === 'guarded'){
    lv.textContent = '常态警戒 · GUARDED';
    S.core.intensityT = 0.55; S.core.levelTarget = 0;
  } else {
    lv.textContent = '态势平稳 · STEADY';
    S.core.intensityT = 0.38; S.core.levelTarget = 0;
  }

  /* 头部：检测引擎灯 */
  var hd = $('hdDetect');
  hd.className = 'hd-light ' + (d.detection_enabled ? 'ok' : 'bad');
  hd.querySelector('b').textContent = d.detection_enabled ? 'ONLINE' : 'OFFLINE';

  /* QPS：由相邻两次 total 差分 */
  var now = Date.now();
  if (S.lastTotal != null && now > S.lastTotalAt){
    var dq = total - S.lastTotal;
    if (dq >= 0) S.qps = dq / ((now - S.lastTotalAt) / 1000);
  }
  S.lastTotal = total; S.lastTotalAt = now;

  return d;
}

/* ═══════════════ 渲染：事件流 + Ticker + 核心联动 ═══════════════ */
var evNodes = {};   // id -> row node（避免重建旧行重放动画）
function renderStream(items){
  var box = $('eventStream');
  var newest = items[0];
  if (!S.streamReady){
    box.innerHTML = '';
    evNodes = {};
    if (!items.length){
      box.innerHTML = '<div class="stream-empty">今日暂无拦截事件 · 链路静默</div>';
    }
    /* 旧→新 顺序插入（视觉上最新在顶部） */
    for (var i = items.length - 1; i >= 0; i--) box.appendChild(evRow(items[i], false));
    S.streamReady = true;
  } else {
    for (var j = items.length - 1; j >= 0; j--){
      var it = items[j];
      if (it.id <= S.lastStreamId || evNodes[it.id]) continue;
      var row = evRow(it, true);
      box.insertBefore(row, box.firstChild);
      var em = box.querySelector('.stream-empty');
      if (em) em.remove();
      /* 联动：核心冲击波 + 光点 + 背景流星 */
      coreAddBlip(it.action === 'remove_ip' ? 'remove' : 'intercept');
      spawnMeteor();
    }
    /* 修剪多余行 */
    while (box.children.length > STREAM_SIZE){
      var last = box.lastChild;
      if (last.dataset && last.dataset.eid) delete evNodes[last.dataset.eid];
      last.remove();
    }
  }
  if (newest) S.lastStreamId = Math.max(S.lastStreamId, newest.id);

  /* Ticker：最近事件拼滚动条 */
  var html = items.map(function(it){
    return '<span class="tk-item"><span class="t">' + esc(hms(it.timestamp)) + '</span>' +
           '<span class="d">' + esc(it.domain) + '</span>' +
           '<span class="s">← ' + esc(it.client_ip || '-') + ' · ' +
           esc(reasonShort(it.filter_reason)) + '</span></span>';
  }).join('');
  if (html){
    var inner = $('tickerInner');
    inner.innerHTML = html + html;   // 双份无缝滚动
    inner.style.animation = 'none';
    void inner.offsetWidth;          // 重置动画
    inner.style.animation = '';
  }
}
function evRow(it, fresh){
  var row = document.createElement('div');
  row.className = 'ev' + (it.action === 'remove_ip' ? ' remove' : '');
  row.dataset.eid = it.id;
  if (!fresh) row.style.animation = 'none';
  row.innerHTML =
    '<span class="tm">' + esc(hms(it.timestamp)) + '</span>' +
    '<span class="dm" title="' + esc(it.domain) + '">' + esc(it.domain) + '</span>' +
    '<span class="cl">' + esc(it.client_ip || '-') + '</span>' +
    '<span class="tag">' + (it.action === 'remove_ip' ? '剔除' : '拦截') + ' · ' +
      esc(reasonShort(it.filter_reason)) + '</span>';
  evNodes[it.id] = row;
  return row;
}

/* ═══════════════ 渲染：构成环 / TOP 榜 / 防御矩阵 ═══════════════ */
function renderBreakdown(d){
  /* 构成环 */
  var src = d.sources || [];
  var sum = src.reduce(function(a, s){ return a + (s.count || 0); }, 0);
  var acc = 0, segs = [];
  src.forEach(function(s){
    var pct = sum > 0 ? s.count / sum : 0;
    if (pct > 0){
      segs.push(SOURCE_COLORS[s.key] + ' ' + (acc * 100).toFixed(2) + '% ' +
                ((acc + pct) * 100).toFixed(2) + '%');
    }
    acc += pct;
  });
  $('donut').style.background = segs.length
    ? 'conic-gradient(' + segs.join(',') + ')'
    : 'conic-gradient(rgba(56,150,220,.15) 0 100%)';
  countUp($('donutTotal'), sum);
  $('donutLegend').innerHTML = src.map(function(s){
    var pct = sum > 0 ? (s.count / sum * 100) : 0;
    return '<div class="lg-row"><i style="background:' + SOURCE_COLORS[s.key] +
           ';color:' + SOURCE_COLORS[s.key] + '"></i>' +
           '<span class="lb">' + esc(s.label) + '</span>' +
           '<span class="vl">' + fmt(s.count) + '</span>' +
           '<span class="pc">' + pct.toFixed(1) + '%</span></div>';
  }).join('');

  /* TOP 域名 / 客户端 */
  renderRank($('topDomains'), d.top_domains || [], 'domain');
  renderRank($('topClients'), d.top_clients || [], 'client_ip');
}
function renderRank(box, rows, key){
  if (!rows.length){
    box.innerHTML = '<div class="stream-empty">暂无数据</div>';
    return;
  }
  var max = rows[0].count || 1;
  box.innerHTML = rows.slice(0, 6).map(function(r, i){
    return '<div class="rank-row">' +
           '<span class="rk">' + (i + 1) + '</span>' +
           '<span class="nm" title="' + esc(r[key]) + '">' + esc(r[key]) + '</span>' +
           '<span class="ct">' + fmt(r.count) + '</span>' +
           '<span class="bar"><i data-w="' + (r.count / max * 100).toFixed(1) + '"></i></span>' +
           '</div>';
  }).join('');
  /* 触发动画 */
  requestAnimationFrame(function(){
    var bars = box.querySelectorAll('.bar i');
    for (var i = 0; i < bars.length; i++) bars[i].style.width = bars[i].dataset.w + '%';
  });
}
function renderDefense(d){
  /* d = {status, breaker, intelOn, intelTotal, offlineRows, offlineSrc} */
  var rows = [];
  var det = d.status.detection_enabled;
  rows.push({n: '检测引擎', v: det ? 'ONLINE' : 'OFFLINE', cls: det ? 'ok' : 'bad'});
  var up = (d.breaker && d.breaker.upstream && d.breaker.upstream.state) || 'closed';
  rows.push({
    n: '上游熔断器',
    v: up === 'closed' ? 'STABLE' : (up === 'open' ? 'BROKEN' : 'PROBING'),
    cls: up === 'closed' ? 'ok' : (up === 'open' ? 'bad' : 'warn')
  });
  rows.push({
    n: '在线情报源',
    v: d.intelOn + ' / ' + d.intelTotal + ' 启用',
    cls: d.intelOn > 0 ? 'ok' : 'warn'
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
  return api('/api/status').then(function(d){
    S._lastStatus = d;
    renderStatus(d);
  }).catch(function(){});
}
function pollStream(){
  return api('/api/logs/stream?size=' + STREAM_SIZE).then(function(d){
    var items = (d && d.items) || [];
    var newCnt = S.streamReady
      ? items.filter(function(it){ return it.id > S.lastStreamId; }).length : 0;
    renderStream(items);
    pushWave(S.qps, newCnt);
    drawWave();
  }).catch(function(){ pushWave(S.qps, 0); });
}
function pollHourly(){
  return api('/api/status/hourly?hours=24').then(function(d){
    S.trend = (d && d.items) || [];
    var sum = S.trend.reduce(function(a, it){ return a + it.intercepts + it.removes; }, 0);
    $('trendTotal').textContent = fmt(sum) + ' / 24H';
    drawTrend();
    /* 威胁指数依赖 trend，趋势到达后联动重算 */
    if (S._lastStatus) renderStatus(S._lastStatus);
  }).catch(function(){});
}
function pollBreakdown(){
  return api('/api/status/breakdown?scope=today&top=6').then(renderBreakdown).catch(function(){});
}
function pollDefense(){
  Promise.all([
    api('/api/status'),
    api('/api/circuit-breaker/stats').catch(function(){ return null; }),
    api('/api/threatlist/sources').catch(function(){ return null; })
  ]).then(function(rs){
    var status = rs[0], breaker = rs[1], sources = rs[2];
    S._breaker = breaker;
    var rows = 0, srcCnt = 0;
    if (sources && sources.items){
      sources.items.forEach(function(s){
        if (s.enabled){ rows += s.enabled_cnt || 0; srcCnt++; }
      });
    }
    var ti = status.threatintel_sources || [];
    renderDefense({
      status: status,
      breaker: breaker,
      intelOn: ti.filter(function(s){ return s.enabled; }).length,
      intelTotal: ti.length,
      offlineRows: rows,
      offlineSrc: srcCnt
    });
    /* 头部：上游灯 */
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
  pollStatus(); pollStream(); pollHourly(); pollBreakdown(); pollDefense();
  timers.push(setInterval(pollStatus, 10000));
  timers.push(setInterval(pollStream, 3000));
  timers.push(setInterval(pollHourly, 60000));
  timers.push(setInterval(pollBreakdown, 60000));
  timers.push(setInterval(pollDefense, 15000));
}

/* 主渲染循环 */
function loop(t){
  drawBg(t || 0);
  drawCore(t || 0);
  requestAnimationFrame(loop);
}

fit();
initBg();
initCore();
/* DOM 画布尺寸依赖缩放完成后的布局 */
requestAnimationFrame(function(){ sizeDomCanvases(); });
requestAnimationFrame(loop);

/* 鉴权引导：有 token 直接启动，401 时 api 层自动弹登录 */
if (S.token) bootData(); else showLogin();

})();

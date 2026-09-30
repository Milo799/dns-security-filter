/* ══════════════════════════════════════════════════════════════
   DNS 安全态势感知平台 · 全息大屏 v2
   数据：复用平台既有 API（Bearer 鉴权与管理端同源）
   渲染：4 个 Canvas（星尘背景 / 全息核心 / 趋势 / 吞吐波形）+ DOM
   v2：四指标轨道卫星 / 中央真实拦截率 / 防御态势面板 / 情报数字带
   ══════════════════════════════════════════════════════════════ */
(function(){
'use strict';

/* ── 常量 ───────────────────────────────────────────────── */
var STAGE_W = 1920, STAGE_H = 1080;
var STREAM_SIZE = 10;   // 右侧面板约 370px 高，10 行不溢出
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
  evMinute: null,
  _breaker: null,
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
  if (!el) return false;
  suffix = suffix || ''; dec = dec || 0;
  var from = parseFloat(el.dataset.v || '0') || 0;
  var changed = (from !== to);
  el.dataset.v = to;
  function show(v){
    el.textContent = dec ? v.toFixed(dec) + suffix : fmt(Math.round(v)) + suffix;
  }
  if (!changed){ show(to); return false; }
  var t0 = performance.now(), dur = 800;
  function step(t){
    var p = Math.min(1, (t - t0) / dur);
    p = 1 - Math.pow(1 - p, 3);
    show(from + (to - from) * p);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
  return true;
}
/* 轨道卫星赋值：数值变化时卫星闪烁一次 */
function satSet(boxId, elId, to, suffix, dec){
  var changed = countUp($(elId), to, suffix, dec);
  if (changed){
    var box = $(boxId);
    box.classList.remove('upd');
    void box.offsetWidth;
    box.classList.add('upd');
  }
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
  var scale = stageRect.width / STAGE_W || 1;
  [ ['trendCanvas', tr], ['waveCanvas', wv] ].forEach(function(pair){
    var el = $(pair[0]), o = pair[1];
    if (!el) return;
    var r = el.getBoundingClientRect();
    var w = Math.max(80, Math.round(r.width / scale));
    var h = Math.max(50, Math.round(r.height / scale));
    o.w = w * 2; o.h = h * 2;   // 2x 保证清晰
    el.width = o.w; el.height = o.h;
    o.cv = el; o.cx = el.getContext('2d');
  });
  if (S.trend) drawTrend(0);
  drawWave();
}
/* 趋势图（24H）：小时区（前段）+ 分钟区（后段 30 分钟，细颗粒流动）
   每帧渲染——扫描光带/曲线流光/当前柱呼吸/数据生长过渡 */
var trendAnim = {hi: [], hr: []};   // 柱高动画当前值（lerp 逼近目标）
var MIN_SPLIT = 18;                 // 前 18 格=小时，后 10 格=分钟（10 分钟窗）
function drawTrend(t){
  if (!tr.cx || !S.trend || !S.trend.length) return;
  var c = tr.cx, W = tr.w, H = tr.h;
  var hourly = S.trend;             // 24 小时
  /* 分钟段：事件流按分钟聚合最近 10 分钟（10 格） */
  var mins = [];
  if (S.evMinute && S.evMinute.length){
    mins = S.evMinute;
  }
  /* 组合序列：小时[0..17] + 分钟[0..11] */
  var n = MIN_SPLIT + 10;
  var items = [];
  var i, j;
  for (i = 0; i < Math.min(MIN_SPLIT, hourly.length); i++)
    items.push({label: hourly[i].hour.slice(11, 13) + '时',
                intercepts: hourly[i].intercepts, removes: hourly[i].removes,
                kind: 'hour'});
  for (i = 0; i < 10; i++){
    var m = mins.length > i ? mins[i] : {label: '', intercepts: 0, removes: 0};
    items.push({label: m.label || '', intercepts: m.intercepts || 0,
                removes: m.removes || 0, kind: 'min'});
  }
  c.clearRect(0, 0, W, H);
  var padL = 10, padR = 10, padT = 16, padB = 34;
  var cw = W - padL - padR, ch = H - padT - padB;
  var max = 1;
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
  var bw = cw / n;
  /* 分区背景：分钟区微亮标出 */
  var minX0 = padL + MIN_SPLIT * bw;
  c.fillStyle = 'rgba(34,211,238,.04)';
  c.fillRect(minX0, padT, W - padR - minX0, ch);
  c.strokeStyle = 'rgba(126,231,252,.25)';
  c.lineWidth = 1;
  c.setLineDash([3, 4]);
  c.beginPath(); c.moveTo(minX0, padT); c.lineTo(minX0, padT + ch); c.stroke();
  c.setLineDash([]);
  /* 柱高动画目标值与缓动 */
  if (trendAnim.hi.length !== n){
    trendAnim.hi = items.map(function(it){ return ch * it.intercepts / max; });
    trendAnim.hr = items.map(function(it){ return ch * it.removes / max; });
  }
  for (i = 0; i < n; i++){
    var thi = ch * items[i].intercepts / max;
    var thr = ch * items[i].removes / max;
    trendAnim.hi[i] += (thi - trendAnim.hi[i]) * 0.08;
    trendAnim.hr[i] += (thr - trendAnim.hr[i]) * 0.08;
  }
  /* 柱：拦截红 + 剔除琥珀 堆叠（当前柱呼吸脉动） */
  for (i = 0; i < n; i++){
    var x = padL + i * bw + bw * 0.2;
    var bwid = bw * 0.6;
    var hi = trendAnim.hi[i], hr = trendAnim.hr[i];
    var cur = (i === n - 1);
    var ba = cur ? (0.72 + 0.23 * Math.sin(t / 380)) : 1;
    c.fillStyle = cur ? 'rgba(251,77,109,' + (0.95 * ba).toFixed(3) + ')'
                      : 'rgba(251,77,109,.62)';
    c.fillRect(x, padT + ch - hi, bwid, hi);
    c.fillStyle = cur ? 'rgba(251,191,36,' + (0.95 * ba).toFixed(3) + ')'
                      : 'rgba(251,191,36,.55)';
    c.fillRect(x, padT + ch - hi - hr, bwid, hr);
  }
  /* 总量平滑曲线 */
  var pts = [];
  for (i = 0; i < n; i++){
    pts.push([padL + i * bw + bw / 2,
              padT + ch - (trendAnim.hi[i] + trendAnim.hr[i])]);
  }
  c.strokeStyle = 'rgba(126,231,252,.9)'; c.lineWidth = 2.4;
  c.shadowColor = 'rgba(34,211,238,.8)'; c.shadowBlur = 10;
  c.beginPath();
  c.moveTo(pts[0][0], pts[0][1]);
  for (i = 1; i < pts.length; i++){
    var xc = (pts[i - 1][0] + pts[i][0]) / 2, yc = (pts[i - 1][1] + pts[i][1]) / 2;
    c.quadraticCurveTo(pts[i - 1][0], pts[i - 1][1], xc, yc);
  }
  c.lineTo(pts[pts.length - 1][0], pts[pts.length - 1][1]);
  c.stroke();
  c.shadowBlur = 0;
  /* 扫描光带：周期从左扫到右 */
  var scanP = (t % 12000) / 12000;
  var scanX = padL + scanP * cw;
  var sg = c.createLinearGradient(padL, 0, scanX, 0);
  sg.addColorStop(0, 'rgba(126,231,252,0)');
  sg.addColorStop(0.85, 'rgba(126,231,252,.03)');
  sg.addColorStop(1, 'rgba(126,231,252,.10)');
  c.fillStyle = sg;
  c.fillRect(padL, padT, Math.max(0, scanX - padL), ch);
  c.fillStyle = 'rgba(126,231,252,.30)';
  c.fillRect(scanX - 1.5, padT, 1.5, ch);
  /* 曲线流光点 + 拖尾 */
  var prog = (t % 9000) / 9000 * (n - 1);
  var pi = Math.min(n - 2, Math.floor(prog)), pf2 = prog - pi;
  var fx = pts[pi][0] + (pts[pi + 1][0] - pts[pi][0]) * pf2;
  var fy = pts[pi][1] + (pts[pi + 1][1] - pts[pi][1]) * pf2;
  for (i = 1; i <= 4; i++){
    var tp = Math.max(0, prog - i * 0.35);
    var ti2 = Math.min(n - 2, Math.floor(tp)), tf = tp - ti2;
    var tx = pts[ti2][0] + (pts[ti2 + 1][0] - pts[ti2][0]) * tf;
    var ty = pts[ti2][1] + (pts[ti2 + 1][1] - pts[ti2][1]) * tf;
    c.fillStyle = 'rgba(126,231,252,' + (0.28 - i * 0.06).toFixed(3) + ')';
    c.beginPath(); c.arc(tx, ty, 3.5 - i * 0.5, 0, Math.PI * 2); c.fill();
  }
  c.fillStyle = 'rgba(224,251,255,.98)';
  c.shadowColor = 'rgba(126,231,252,1)'; c.shadowBlur = 14;
  c.beginPath(); c.arc(fx, fy, 4.5, 0, Math.PI * 2); c.fill();
  c.shadowBlur = 0;
  /* X 轴刻度：小时区每 6 小时、分钟区每 6 分钟 */
  c.fillStyle = 'rgba(148,197,255,.5)';
  c.font = '600 20px Consolas, monospace';
  c.textAlign = 'center';
  for (i = 0; i < MIN_SPLIT; i += 6){
    c.fillText(items[i].label, padL + i * bw + bw / 2, H - 10);
  }
  c.fillStyle = 'rgba(148,197,255,.65)';
  c.font = '600 19px Consolas, monospace';
  for (i = MIN_SPLIT; i < n; i += 5){
    c.fillText(items[i].label, padL + i * bw + bw / 2, H - 10);
  }
  /* 分钟区标识 */
  c.textAlign = 'right';
  c.fillStyle = 'rgba(126,231,252,.5)';
  c.font = '600 16px Consolas, monospace';
  c.fillText('近 10 分钟（分钟级）', W - padR - 4, padT + 14);
  c.textAlign = 'left';
}
/* 分钟聚合：事件流时间戳按分钟归入最近 10 分钟窗（10 格） */
function buildMinuteBins(items){
  var now = Date.now();
  var bins = [];
  var i;
  for (i = 9; i >= 0; i--){
    var mStart = new Date(now - i * 60000);
    bins.push({label: pad2(mStart.getMinutes()) + '分',
               key: mStart.getFullYear() + '-' + mStart.getMonth() + '-' + mStart.getDate() + '-' +
                    mStart.getHours() + ':' + mStart.getMinutes(),
               intercepts: 0, removes: 0});
  }
  items.forEach(function(it){
    var d = new Date(String(it.timestamp).replace(' ', 'T'));
    if (isNaN(d)) return;
    var key = d.getFullYear() + '-' + d.getMonth() + '-' + d.getDate() + '-' +
              d.getHours() + ':' + d.getMinutes();
    for (var b = 0; b < bins.length; b++){
      if (bins[b].key === key){
        if (it.action === 'remove_ip') bins[b].removes++;
        else bins[b].intercepts++;
        return;
      }
    }
  });
  S.evMinute = bins;
}

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
  c.strokeStyle = 'rgba(126,231,252,.95)'; c.lineWidth = 2;
  c.shadowColor = 'rgba(34,211,238,.7)'; c.shadowBlur = 8;
  c.beginPath();
  for (i = 0; i < n; i++){
    var x = x0 + i * bw, y = padT + ch * (1 - data[i].q / qmax);
    if (i === 0) c.moveTo(x, y); else c.lineTo(x, y);
  }
  c.stroke(); c.shadowBlur = 0;
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

/* ═══════════════ 渲染：中央读数 + 轨道卫星 ═══════════════
   中央大数字 = 真实拦截率（可解释口径，不用复合指数吓人）；
   态势等级只以文字徽章 + 核心色相表达（蓝/青/琥珀/红）。
*/
function renderStatus(d){
  var total = d.today_total || 0;
  var inter = d.today_intercepts || 0;
  var rem = d.today_removes || 0;
  var blocked = inter + rem;
  var rate = total > 0 ? blocked / total * 100 : 0;

  /* 轨道卫星（数据变化才闪烁） */
  satSet('satBoxTotal', 'satTotal', total);
  satSet('satBoxInter', 'satInter', inter);
  satSet('satBoxRemove', 'satRemove', rem);

  /* 中央读数 */
  var idx = $('threatRate');
  var lv = $('threatLevel');
  idx.classList.remove('warn', 'danger');
  lv.classList.remove('warn', 'danger');
  if (total === 0){
    idx.textContent = '--';
    $('threatSub').textContent = '链路静默 · 等待查询流量';
    lv.textContent = '静默待机 · STANDBY';
    S.core.intensityT = 0.3; S.core.levelTarget = 0;
  } else {
    countUp(idx, rate, '%', 1);
    $('threatSub').textContent = '拦截 ' + fmt(blocked) + ' / 查询 ' + fmt(total);
    if (rate >= 15){
      lv.textContent = '高危态势 · SEVERE';
      idx.classList.add('danger'); lv.classList.add('danger');
      S.core.intensityT = 1.0; S.core.levelTarget = 1;
    } else if (rate >= 8){
      lv.textContent = '威胁升高 · ELEVATED';
      idx.classList.add('warn'); lv.classList.add('warn');
      S.core.intensityT = 0.78; S.core.levelTarget = 0.5;
    } else if (rate >= 2){
      lv.textContent = '常态警戒 · GUARDED';
      S.core.intensityT = 0.55; S.core.levelTarget = 0;
    } else {
      lv.textContent = '态势平稳 · STEADY';
      S.core.intensityT = 0.38; S.core.levelTarget = 0;
    }
  }

  /* 头部：检测引擎灯 */
  var hd = $('hdDetect');
  hd.className = 'hd-light ' + (d.detection_enabled ? 'ok' : 'bad');
  hd.querySelector('b').textContent = d.detection_enabled ? 'ONLINE' : 'OFFLINE';

  /* 态势等级 → data-level 驱动全场联动（网格/极光/面板角/数字带） */
  var lvl = 'steady';
  if (total === 0){
    lvl = 'standby';
  } else if (rate >= 15){
    lvl = 'danger';
  } else if (rate >= 8){
    lvl = 'warn';
  }
  document.getElementById('stage').dataset.level = lvl;

  /* QPS：由相邻两次 total 差分；更新卫星与底部数字带 */
  var now = Date.now();
  if (S.lastTotal != null && now > S.lastTotalAt){
    var dq = total - S.lastTotal;
    if (dq >= 0) S.qps = dq / ((now - S.lastTotalAt) / 1000);
  }
  S.lastTotal = total; S.lastTotalAt = now;
  satSet('satBoxRate', 'satQps', Math.round(S.qps * 10) / 10, '', 1);
  var fq = $('ftQps');
  if (fq) fq.textContent = S.qps.toFixed(1);
}

/* ═══════════════ 渲染：事件流 + Ticker + 核心联动 ═══════════════
   瀑布流式：最新事件在底部涌生（0 高展开+闪光），旧事件向上流动，
   超容量时最老一条在顶部收缩消散——无跳变，视觉连续。
*/
var EV_ROW_H = 29;   // 与 CSS：4px*2 padding + ~21px 行高一致
var evNodes = {};
function renderStream(items){
  var box = $('eventStream');
  var newest = items[0];
  if (!S.streamReady){
    /* 首次：底部对齐铺入（旧→新，最新在最底部） */
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
    /* 增量：新事件底部涌生（0 高展开上推旧行），最老行顶部收缩消散 */
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
      coreAddBlip(it.action === 'remove_ip' ? 'remove' : 'intercept');
      spawnMeteor();
    }
    /* 修剪：最老行顶部收缩消散。
       必须用定界 for 循环+快照数组——while(firstChild) 在异步移除下
       会永远取到同一节点形成主线程死循环（生产冻结根因）。 */
    var rowsArr = Array.prototype.slice.call(box.children);
    var excess = rowsArr.length - STREAM_SIZE;
    var trimmed = 0;
    for (var k = 0; k < rowsArr.length && trimmed < excess; k++){
      var old = rowsArr[k];
      if (!old.classList || !old.classList.contains('ev') ||
          old.dataset.collapse === '1') continue;
      old.dataset.collapse = '1';
      if (old.dataset.eid) delete evNodes[old.dataset.eid];
      old.style.height = '0px';
      old.style.opacity = '0';
      (function(node){
        setTimeout(function(){
          if (node.parentNode) node.parentNode.removeChild(node);
        }, 480);
      })(old);
      trimmed++;
    }
  }
  if (newest) S.lastStreamId = Math.max(S.lastStreamId, newest.id);
  buildMinuteBins(items);

  var html = items.map(function(it){
    return '<span class="tk-item"><span class="t">' + esc(hms(it.timestamp)) + '</span>' +
           '<span class="d">' + esc(it.domain) + '</span>' +
           '<span class="s">← ' + esc(it.client_ip || '-') + ' · ' +
           esc(reasonShort(it.filter_reason)) + '</span></span>';
  }).join('');
  if (html){
    var inner = $('tickerInner');
    inner.innerHTML = html + html;
    inner.style.animation = 'none';
    void inner.offsetWidth;
    inner.style.animation = '';
  }
}
function evRow(it, fresh){
  var row = document.createElement('div');
  row.className = 'ev' + (it.action === 'remove_ip' ? ' remove' : '');
  if (fresh) row.classList.add('born');
  row.dataset.eid = it.id;
  row.innerHTML =
    '<span class="tm">' + esc(hms(it.timestamp)) + '</span>' +
    '<span class="dm" title="' + esc(it.domain) + '">' + esc(it.domain) + '</span>' +
    '<span class="cl">' + esc(it.client_ip || '-') + '</span>' +
    '<span class="tag">' + (it.action === 'remove_ip' ? '剔除' : '拦截') + ' · ' +
      esc(reasonShort(it.filter_reason)) + '</span>';
  evNodes[it.id] = row;
  return row;
}

/* ═══════════════ 渲染：构成堆叠条 / TOP 榜 / 防御矩阵 / 数字带 ═══════════════ */
function renderBreakdown(d){
  var src = d.sources || [];
  var sum = src.reduce(function(a, s){ return a + (s.count || 0); }, 0);

  /* 构成堆叠条 */
  $('stackBar').innerHTML = src.map(function(s){
    var pct = sum > 0 ? s.count / sum * 100 : 0;
    return '<i data-w="' + pct.toFixed(2) + '" style="background:' +
           (SOURCE_COLORS[s.key] || '#475569') + ';box-shadow:0 0 10px ' +
           (SOURCE_COLORS[s.key] || '#475569') + '66" title="' + esc(s.label) + ' ' +
           fmt(s.count) + ' (' + pct.toFixed(1) + '%)"></i>';
  }).join('');
  $('stackLegend').innerHTML = src.map(function(s){
    var pct = sum > 0 ? s.count / sum * 100 : 0;
    return '<div class="lg-row"><i style="background:' + SOURCE_COLORS[s.key] +
           ';color:' + SOURCE_COLORS[s.key] + '"></i>' +
           '<span class="lb">' + esc(s.label) + '</span>' +
           '<span class="vl">' + fmt(s.count) + '</span>' +
           '<span class="pc">' + pct.toFixed(1) + '%</span></div>';
  }).join('');
  requestAnimationFrame(function(){
    var segs = $('stackBar').querySelectorAll('i');
    for (var i = 0; i < segs.length; i++) segs[i].style.width = segs[i].dataset.w + '%';
  });

  /* TOP 域名榜 */
  renderRank($('topDomains'), d.top_domains || [], 'domain', sum);

  /* 底部数字带：最热威胁域名 / 最活跃拦截源 */
  var td = (d.top_domains || [])[0], tc = (d.top_clients || [])[0];
  $('ftTopDom').textContent = td ? td.domain : '--';
  $('ftTopDomN').textContent = td ? fmt(td.count) + ' 次' : '';
  $('ftTopDom').title = td ? td.domain : '';
  $('ftTopCli').textContent = tc ? tc.client_ip : '--';
  $('ftTopCliN').textContent = tc ? fmt(tc.count) + ' 次' : '';
}
function renderRank(box, rows, key, total){
  if (!rows.length){
    box.innerHTML = '<div class="stream-empty">暂无数据</div>';
    return;
  }
  var max = rows[0].count || 1;
  box.innerHTML = rows.slice(0, 6).map(function(r, i){
    var pct = total > 0 ? (r.count / total * 100).toFixed(1) : '0.0';
    return '<div class="rank-row">' +
           '<span class="rk">' + (i + 1) + '</span>' +
           '<span class="nm" title="' + esc(r[key]) + '">' + esc(r[key]) + '</span>' +
           '<span class="pc">' + pct + '%</span>' +
           '<span class="ct">' + fmt(r.count) + '</span>' +
           '<span class="bar"><i data-w="' + (r.count / max * 100).toFixed(1) + '"></i></span>' +
           '</div>';
  }).join('');
  requestAnimationFrame(function(){
    var bars = box.querySelectorAll('.bar i');
    for (var i = 0; i < bars.length; i++) bars[i].style.width = bars[i].dataset.w + '%';
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

  /* 底部数字带：离线情报库 */
  $('ftIntel').textContent = d.offlineRows >= 10000
    ? (d.offlineRows / 10000).toFixed(1) + ' 万' : fmt(d.offlineRows);
}

/* ═══════════════ 轮询调度 ═══════════════ */
function pollStatus(){
  return api('/api/status').then(function(d){
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
    $('ftDay').textContent = fmt(sum);
    drawTrend();
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
    /* 离线情报库：所有离线源 total 之和（在库规模，含停用源的在库数据）。
       注意：接口返回无 enabled 字段（None），真实字段是 total/enabled_cnt，
       按 enabled 过滤会全排除得 0——生产 09-29 实锤。 */
    var rows = 0, srcCnt = 0;
    if (sources && sources.items){
      sources.items.forEach(function(s){
        rows += s.total || 0;
        srcCnt++;
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

/* 主渲染循环（单帧异常不中断调度） */
function loop(t){
  try {
    drawBg(t || 0);
    drawCore(t || 0);
    drawTrend(t || 0);
  } catch (e){ /* 单帧异常不致命，下一帧继续 */ }
  requestAnimationFrame(loop);
}

fit();
initBg();
initCore();
requestAnimationFrame(function(){ sizeDomCanvases(); });
requestAnimationFrame(loop);

if (S.token) bootData(); else showLogin();

})();

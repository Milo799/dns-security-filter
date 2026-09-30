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
  hourly: null,
  layers: LAYERS.map(function(){ return {count: 0, active: true, share: 0, h: 30, flash: 0}; }),
  flow: [], shards: [], absorbs: [], ringRot: [0, 0.9, 1.8, 2.7, 3.6],
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
/* 横卧透视管道：左侧近端大截面 → 右侧远端收分，五道竖立椭圆闸门箍于管上 */
var PIPE_X0 = 64, PIPE_X1 = 952, PIPE_CY = 316;
var GATE_X = [182, 332, 482, 632, 782];      /* L1→L5 闸门 x */
function pipeH(x){                            /* 截面半高：近 120 → 远 74 */
  return 120 - (x - PIPE_X0) / (PIPE_X1 - PIPE_X0) * 46;
}
var RING_SPD = [0.0011, 0.0015, 0.0019, 0.0024, 0.0030];  /* 同向不同速，环不相交 */

function initChain(){
  ch.cv = $('chainCanvas');
  ch.cv.width = ch.W * 2; ch.cv.height = ch.H * 2;
  ch.cx = ch.cv.getContext('2d');
  ch.cx.scale(2, 2);
}

/* 粒子生成：左端入口进入管道内腔向右穿行，按真实拦截率与层占比决定命运 */
function spawnFlow(){
  if (S.flow.length >= 130) return;
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
    x: PIPE_X0 - 20,
    yOff: (Math.random() - 0.5) * 1.5,       /* 管内垂直偏移（-0.75~0.75） */
    sp: 150 + Math.random() * 100,
    tgt: tgt
  });
}

function drawChain(t){
  if (!ch.cx) return;
  var c = ch.cx, dt = 16.7;
  c.clearRect(0, 0, ch.W, ch.H);
  c.save();
  c.globalCompositeOperation = 'lighter';

  var i, j, ly, x;

  /* ── 管道内腔发光雾 ── */
  var fog = c.createLinearGradient(PIPE_X0, 0, PIPE_X1, 0);
  fog.addColorStop(0, 'rgba(34,211,238,.10)');
  fog.addColorStop(0.6, 'rgba(34,211,238,.05)');
  fog.addColorStop(1, 'rgba(52,211,153,.09)');
  c.beginPath();
  c.moveTo(PIPE_X0, PIPE_CY - pipeH(PIPE_X0));
  for (x = PIPE_X0; x <= PIPE_X1; x += 16) c.lineTo(x, PIPE_CY - pipeH(x));
  for (x = PIPE_X1; x >= PIPE_X0; x -= 16) c.lineTo(x, PIPE_CY + pipeH(x));
  c.closePath();
  c.fillStyle = fog;
  c.fill();

  /* ── 管壁轮廓（上下双线 + 纵向龙骨椭圆） ── */
  c.strokeStyle = 'rgba(56,189,248,.30)';
  c.lineWidth = 1.6;
  c.beginPath();
  c.moveTo(PIPE_X0, PIPE_CY - pipeH(PIPE_X0));
  for (x = PIPE_X0; x <= PIPE_X1; x += 16) c.lineTo(x, PIPE_CY - pipeH(x));
  c.stroke();
  c.beginPath();
  c.moveTo(PIPE_X0, PIPE_CY + pipeH(PIPE_X0));
  for (x = PIPE_X0; x <= PIPE_X1; x += 16) c.lineTo(x, PIPE_CY + pipeH(x));
  c.stroke();
  c.strokeStyle = 'rgba(56,189,248,.10)';
  c.lineWidth = 1;
  for (x = PIPE_X0 + 44; x < PIPE_X1; x += 88){
    var hh = pipeH(x);
    c.beginPath();
    c.ellipse(x, PIPE_CY, hh * 0.26, hh, 0, 0, Math.PI * 2);
    c.stroke();
  }

  /* ── 左端入口盖 + INBOUND ── */
  c.strokeStyle = 'rgba(126,231,252,.75)';
  c.lineWidth = 2;
  c.beginPath();
  c.ellipse(PIPE_X0, PIPE_CY, pipeH(PIPE_X0) * 0.26, pipeH(PIPE_X0), 0, 0, Math.PI * 2);
  c.stroke();
  c.fillStyle = 'rgba(126,231,252,.5)';
  c.font = '600 12px Consolas, monospace';
  c.textAlign = 'center';
  c.fillText('INBOUND', PIPE_X0 + 6, PIPE_CY - pipeH(PIPE_X0) - 12);

  /* ── 五道闸门环（竖立椭圆，近大远小） ── */
  for (i = 0; i < 5; i++){
    ly = LAYERS[i];
    var Ld = S.layers[i];
    var gx = GATE_X[i], gh = pipeH(gx);
    Ld.flash = Math.max(0, Ld.flash - 0.022);
    S.ringRot[i] += RING_SPD[i] * dt;
    var hue = ly.hue;
    var active = Ld.active;
    var colG = function(a){ return active ? 'hsla(' + hue + ',90%,62%,' + a + ')'
                                          : 'rgba(100,116,139,' + (a * 0.8) + ')'; };
    var alpha = active ? (0.30 + Ld.share * 0.45 + Ld.flash * 0.5) : 0.16;

    /* 闸门主体椭圆环 */
    c.strokeStyle = colG(Math.min(1, alpha));
    c.lineWidth = 3 + Ld.flash * 2.5;
    c.shadowColor = colG(0.9); c.shadowBlur = 12 + Ld.share * 20 + Ld.flash * 26;
    c.beginPath();
    c.ellipse(gx, PIPE_CY, 15, gh + 10, 0, 0, Math.PI * 2);
    c.stroke();
    c.shadowBlur = 0;

    /* 环上旋转能量弧（两段，同向不同速） */
    c.strokeStyle = colG(active ? 0.8 : 0.3);
    c.lineWidth = 4;
    for (var seg = 0; seg < 2; seg++){
      var a0 = S.ringRot[i] + seg * Math.PI;
      c.beginPath();
      c.ellipse(gx, PIPE_CY, 15, gh + 10, 0, a0, a0 + 0.7);
      c.stroke();
    }

    /* 拦截冲击：环膨胀波 */
    if (Ld.flash > 0.03){
      var ex = (1 - Ld.flash) * 26;
      c.strokeStyle = 'hsla(' + hue + ',95%,68%,' + (Ld.flash * 0.8).toFixed(3) + ')';
      c.lineWidth = 1.8;
      c.beginPath();
      c.ellipse(gx, PIPE_CY, 15 + ex * 0.4, gh + 10 + ex, 0, 0, Math.PI * 2);
      c.stroke();
    }

    /* 停用：灰虚线环 */
    if (!active){
      c.strokeStyle = 'rgba(100,116,139,.3)';
      c.lineWidth = 1.2;
      c.setLineDash([4, 8]);
      c.beginPath();
      c.ellipse(gx, PIPE_CY, 20, gh + 16, 0, 0, Math.PI * 2);
      c.stroke();
      c.setLineDash([]);
    }

    /* 闸门上方悬浮标签 + 引导线 */
    var labY = PIPE_CY - gh - 64;
    c.strokeStyle = colG(0.35);
    c.lineWidth = 1;
    c.beginPath(); c.moveTo(gx, labY + 34); c.lineTo(gx, PIPE_CY - gh - 12); c.stroke();
    c.fillStyle = colG(0.3);
    c.beginPath(); c.arc(gx, PIPE_CY - gh - 10, 2, 0, Math.PI * 2); c.fill();
    c.font = '700 15px Consolas, monospace';
    c.fillStyle = colG(active ? 0.95 : 0.45);
    c.shadowColor = colG(0.8); c.shadowBlur = 8;
    c.fillText(ly.tag + ' · ' + ly.name, gx, labY + 4);
    c.shadowBlur = 0;
    c.font = '600 12px Consolas, monospace';
    c.fillStyle = colG(active ? 0.7 : 0.4);
    c.fillText(fmt(Ld.count) + ' · ' + (Ld.share * 100).toFixed(1) + '%' +
               (active ? '' : ' · 停用'), gx, labY + 22);
  }

  /* ── 右端出口 + CORE 放行核 ── */
  var oh = pipeH(PIPE_X1);
  c.strokeStyle = 'rgba(52,211,153,.7)';
  c.lineWidth = 2;
  c.beginPath();
  c.ellipse(PIPE_X1, PIPE_CY, oh * 0.26, oh, 0, 0, Math.PI * 2);
  c.stroke();
  var pulse = 1 + Math.sin(t / 800) * 0.1;
  var gc = c.createRadialGradient(PIPE_X1 + 30, PIPE_CY, 0, PIPE_X1 + 30, PIPE_CY, 40 * pulse);
  gc.addColorStop(0, 'rgba(52,211,153,.8)');
  gc.addColorStop(0.5, 'rgba(52,211,153,.2)');
  gc.addColorStop(1, 'rgba(52,211,153,0)');
  c.fillStyle = gc;
  c.beginPath(); c.arc(PIPE_X1 + 30, PIPE_CY, 40 * pulse, 0, Math.PI * 2); c.fill();
  c.fillStyle = 'rgba(233,255,246,.95)';
  c.font = '600 11px Consolas, monospace';
  c.fillText('CORE', PIPE_X1 + 30, PIPE_CY + 4);

  /* ── 查询光流粒子（管内穿行） ── */
  if (Math.random() < 0.15) spawnFlow();
  for (j = S.flow.length - 1; j >= 0; j--){
    var p = S.flow[j];
    p.x += p.sp * dt / 1000;
    /* 抵达命运闸门：爆碎 */
    if (p.tgt >= 0 && p.x >= GATE_X[p.tgt] - 8){
      S.layers[p.tgt].flash = 1;
      var py0 = PIPE_CY + p.yOff * pipeH(p.x) * 0.55;
      for (var sN = 0; sN < 6; sN++){
        var sa2 = Math.random() * Math.PI * 2, sv = 0.6 + Math.random() * 1.8;
        S.shards.push({x: GATE_X[p.tgt], y: py0,
          vx: Math.cos(sa2) * sv, vy: Math.sin(sa2) * sv,
          hue: LAYERS[p.tgt].hue, life: 1});
      }
      S.flow.splice(j, 1);
      continue;
    }
    /* 抵达出口：放行 */
    if (p.x >= PIPE_X1 - 12){
      S.absorbs.push({r: 12, a: 0.6});
      S.flow.splice(j, 1);
      continue;
    }
    var py = PIPE_CY + p.yOff * pipeH(p.x) * 0.55;
    var persp = 0.5 + pipeH(p.x) / 120 * 0.5;
    c.fillStyle = 'rgba(190,242,255,' + (0.95 * persp).toFixed(3) + ')';
    c.shadowColor = 'rgba(34,211,238,1)'; c.shadowBlur = 8 * persp;
    c.beginPath(); c.arc(p.x, py, 2.3 * persp, 0, Math.PI * 2); c.fill();
    c.shadowBlur = 0;
    /* 水平尾迹 */
    c.strokeStyle = 'rgba(34,211,238,' + (0.35 * persp).toFixed(3) + ')';
    c.lineWidth = 1.4;
    c.beginPath(); c.moveTo(p.x - 18 * persp, py); c.lineTo(p.x, py); c.stroke();
  }

  /* ── 被拦碎裂粒子（四散燃尽） ── */
  for (j = S.shards.length - 1; j >= 0; j--){
    var sh = S.shards[j];
    sh.x += sh.vx; sh.y += sh.vy;
    sh.vx *= 0.97; sh.vy *= 0.97;
    sh.life -= dt / 900;
    if (sh.life <= 0){ S.shards.splice(j, 1); continue; }
    c.fillStyle = 'hsla(' + sh.hue + ',95%,66%,' + Math.min(1, sh.life * 1.8).toFixed(3) + ')';
    c.shadowColor = 'hsla(' + sh.hue + ',95%,60%,1)'; c.shadowBlur = 8;
    c.beginPath(); c.arc(sh.x, sh.y, 2, 0, Math.PI * 2); c.fill();
    c.shadowBlur = 0;
  }

  /* ── 出口放行微光环 ── */
  for (j = S.absorbs.length - 1; j >= 0; j--){
    var ab = S.absorbs[j];
    ab.r += 1.2; ab.a -= 0.025;
    if (ab.a <= 0){ S.absorbs.splice(j, 1); continue; }
    c.strokeStyle = 'rgba(52,211,153,' + ab.a.toFixed(3) + ')';
    c.lineWidth = 1.5;
    c.beginPath(); c.arc(PIPE_X1 + 30, PIPE_CY, ab.r, 0, Math.PI * 2); c.stroke();
  }

  c.restore();
  c.textAlign = 'left';
}

/* ═══════════════ 底部：24H 分层拦截热力图 ═══════════════
   五层 × 24 小时格阵：亮度=该层该小时拦截量（sqrt 映射+全局归一），
   与中央流水线互补——中央=实时透视，底部=全天回顾。
*/
var hm = {cv: null, cx: null, w: 0, h: 0};
var HM_PADL = 116, HM_PADR = 96, HM_PADT = 6, HM_PADB = 22;

function hexRgb(hex){
  return [parseInt(hex.slice(1, 3), 16), parseInt(hex.slice(3, 5), 16),
          parseInt(hex.slice(5, 7), 16)];
}
function drawHeat(t){
  if (!hm.cx) return;
  var c = hm.cx, W = hm.w, H = hm.h;
  c.clearRect(0, 0, W, H);
  var items = S.hourly;
  if (!items || !items.length){
    c.fillStyle = 'rgba(148,197,255,.4)';
    c.font = '600 24px Consolas, monospace';
    c.fillText('热力采样中…', 24, H / 2);
    return;
  }
  var cols = items.length, rows = 5, i, j;
  var gw = (W - HM_PADL - HM_PADR) / cols;
  var gh = (H - HM_PADT - HM_PADB) / rows;
  var cw = Math.max(2, gw - 4), chh = Math.max(2, gh - 4);
  /* 全局归一（sqrt 提升小数值可见度） */
  var vmax = 1;
  for (i = 0; i < rows; i++)
    for (j = 0; j < cols; j++)
      vmax = Math.max(vmax, items[j][LAYERS[i].key] || 0);
  /* 行末层合计（今日口径=24h 合计） */
  var rowSum = [0, 0, 0, 0, 0];
  for (i = 0; i < rows; i++)
    for (j = 0; j < cols; j++) rowSum[i] += items[j][LAYERS[i].key] || 0;

  for (i = 0; i < rows; i++){
    var ly = LAYERS[i];
    var y = HM_PADT + i * gh;
    /* 层标签 */
    var rgb = hexRgb(ly.color);
    c.fillStyle = 'rgba(' + rgb[0] + ',' + rgb[1] + ',' + rgb[2] + ',.95)';
    c.font = '700 17px Consolas, monospace';
    c.textAlign = 'left';
    c.fillText(ly.tag, 6, y + gh / 2 + 5);
    c.fillStyle = 'rgba(190,224,255,.75)';
    c.font = '600 14px "Microsoft YaHei", sans-serif';
    c.fillText(ly.name, 42, y + gh / 2 + 5);
    /* 行末合计 */
    c.textAlign = 'right';
    c.fillStyle = 'rgba(234,246,255,.9)';
    c.font = '700 17px Consolas, monospace';
    c.fillText(fmt(rowSum[i]), W - 8, y + gh / 2 + 5);
    c.textAlign = 'left';
    /* 格阵 */
    for (j = 0; j < cols; j++){
      var v = items[j][ly.key] || 0;
      var x = HM_PADL + j * gw;
      var cur = (j === cols - 1);
      if (v > 0){
        var a = 0.14 + 0.86 * Math.sqrt(v / vmax);
        if (cur) a = Math.min(1, a * (0.75 + 0.25 * Math.sin(t / 300)));
        c.fillStyle = 'rgba(' + rgb[0] + ',' + rgb[1] + ',' + rgb[2] + ',' + a.toFixed(3) + ')';
        c.fillRect(x, y, cw, chh);
      } else {
        c.fillStyle = 'rgba(56,150,220,.05)';
        c.fillRect(x, y, cw, chh);
        c.strokeStyle = 'rgba(56,150,220,.10)';
        c.lineWidth = 1;
        c.strokeRect(x + 0.5, y + 0.5, cw - 1, chh - 1);
      }
    }
  }
  /* X 轴刻度（每 4 小时） */
  c.fillStyle = 'rgba(148,197,255,.5)';
  c.font = '600 13px Consolas, monospace';
  c.textAlign = 'center';
  for (j = 0; j < cols; j += 4){
    c.fillText(items[j].hour.slice(11, 13) + '时',
               HM_PADL + j * gw + cw / 2, H - 6);
  }
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
      for (var sN2 = 0; sN2 < 5; sN2++){
        var sa3 = Math.random() * Math.PI * 2, sv2 = 0.6 + Math.random() * 1.8;
        S.shards.push({x: GATE_X[li], y: PIPE_CY,
          vx: Math.cos(sa3) * sv2, vy: Math.sin(sa3) * sv2,
          hue: LAYERS[li].hue, life: 1});
      }
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
function pollHourly(){
  return api('/api/status/hourly?hours=24').then(function(d){
    S.hourly = (d && d.items) || [];
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
  pollStatus(); pollStream(); pollLayers(); pollHourly(); pollDefense();
  timers.push(setInterval(pollStatus, 10000));
  timers.push(setInterval(pollStream, 3000));
  timers.push(setInterval(pollLayers, 60000));
  timers.push(setInterval(pollHourly, 60000));
  timers.push(setInterval(pollDefense, 15000));
}

function sizeCanvases(){
  var el = $('heatCanvas');
  if (el){
    var stageRect = document.getElementById('stage').getBoundingClientRect();
    var scale = stageRect.width / STAGE_W || 1;
    var r = el.getBoundingClientRect();
    hm.w = Math.max(80, Math.round(r.width / scale)) * 2;
    hm.h = Math.max(50, Math.round(r.height / scale)) * 2;
    el.width = hm.w; el.height = hm.h;
    hm.cx = el.getContext('2d');
  }
}

/* 主渲染循环（单帧异常不中断调度） */
function loop(t){
  try {
    drawBg(t || 0);
    drawChain(t || 0);
    drawHeat(t || 0);
  } catch (e){ /* 单帧异常不致命，下一帧继续 */ }
  requestAnimationFrame(loop);
}

fit();
initBg();
initChain();
requestAnimationFrame(function(){ sizeCanvases(); });
requestAnimationFrame(loop);

if (S.token) bootData(); else showLogin();

})();

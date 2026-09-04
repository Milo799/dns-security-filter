/* ============================================================
   pages/dashboard.js — 安全态势总览（SOC 三段式大屏）
   威胁总览大数字带(countUp+风险仪表) / 近24h柱线图 / 来源构成+Top5
   五层链路+情报健康 / 实时拦截事件流(3s) / 客户端Top / 24h热力图
   主数据 10s 自动刷新，进入页面时重置计时器
   ============================================================ */

var dashTimer = null, evTimer = null, evLastId = 0, dashLast = {};

/* ---------- countUp：数字滚动动效 ---------- */
function countUp(el, target){
  if (!el) return;
  target = target || 0;
  var start = performance.now(), dur = 700;
  function frame(now){
    var t = Math.min(1, (now - start) / dur);
    var eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(target * eased).toLocaleString();
    if (t < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}
/* 值变化才滚动，避免 10s 刷新反复闪动 */
function countUpIfChanged(id, val){
  var el = document.getElementById(id);
  if (!el) return;
  if (dashLast[id] === val) return;
  dashLast[id] = val;
  countUp(el, val);
}

/* ---------- 环比芯片：涨红跌绿（国内习惯） ----------
   Task #166（迭代 26）：今日是进行中的部分天，直接与昨日整天对比
   必虚降（上午看永远大降）——改为"今日当前值 vs 昨日同时刻折算"：
   昨日全天值 × (今日已过时长/24) 作基准，并标注"按同时刻折算"。 */
function trendChip(cur, prev, elapsedH){
  if (cur == null || prev == null || !prev) return '<span class="kpi-trend flat">较上一日 --</span>';
  var base = prev;
  var note = '较上一日';
  if (elapsedH && elapsedH > 0 && elapsedH < 24){
    base = prev * (elapsedH / 24);
    note = '较昨日同时刻';
  }
  if (base <= 0) base = 0.001; /* 防零除：昨日折算为零但有今日量时按新增计 */
  var delta = cur - base;
  var pct = Math.round(delta / base * 1000) / 10;
  if (delta > 0) return '<span class="kpi-trend up">↑ ' + pct + '%</span><span class="kpi-note">' + note + '</span>';
  if (delta < 0) return '<span class="kpi-trend down">↓ ' + (-pct) + '%</span><span class="kpi-note">' + note + '</span>';
  return '<span class="kpi-trend flat">持平</span><span class="kpi-note">' + note + '</span>';
}

/* ---------- 风险等级：由今日拦截率推导 ---------- */
function riskLevel(rate, total){
  if (rate >= 15) return { label: '危', color: Charts.cssVar('--danger', '#f43f5e'), desc: '拦截率 ≥15% · 高度警惕' };
  if (rate >= 5)  return { label: '高', color: Charts.cssVar('--danger', '#f43f5e'), desc: '拦截率 5~15%' };
  if (rate >= 1)  return { label: '中', color: Charts.cssVar('--warning', '#fbbf24'), desc: '拦截率 1~5%' };
  return { label: '低', color: Charts.cssVar('--success', '#34d399'), desc: '拦截率 <1%' };
}

/* ---------- 半环风险仪表 ----------
   rate 为数字时渲染精确仪表；rate 为 null/非数字（估算口径不给
   误导性数字）时渲染 "?" 占位 + 中性色。 */
function renderGauge(rate, risk){
  var el = document.getElementById('riskGauge');
  if (!el) return;
  var numeric = (typeof rate === 'number' && isFinite(rate));
  var p = numeric ? Math.min(1, rate / 20) : 0;
  var cx = 80, cy = 84, r = 56, w = 11;
  var circ = Math.PI * r;
  var len = numeric ? Math.max(2, circ * p) : 2;
  var arcColor = numeric ? (risk ? risk.color : Charts.cssVar('--accent', '#38bdf8'))
                         : Charts.cssVar('--text', '#e6edf7');
  var sweep = 1; /* 起点左 终点右，经过上方 */
  var mainText = numeric ? rate + '%' : '?';
  var subText = numeric ? ((risk ? risk.label : '') + ' 风险') : '口径不足';
  el.innerHTML =
    '<svg viewBox="0 0 160 104" xmlns="http://www.w3.org/2000/svg" role="img" style="width:132px;height:auto">' +
    '<path d="M ' + (cx - r) + ' ' + cy + ' A ' + r + ' ' + r + ' 0 0 ' + sweep + ' ' + (cx + r) + ' ' + cy + '"' +
    ' fill="none" stroke="' + Charts.cssVar('--border', '#1f2b47') + '" stroke-width="' + w + '" stroke-linecap="round"/>' +
    '<path d="M ' + (cx - r) + ' ' + cy + ' A ' + r + ' ' + r + ' 0 0 ' + sweep + ' ' + (cx + r) + ' ' + cy + '"' +
    ' fill="none" stroke="' + arcColor + '" stroke-width="' + w + '" stroke-linecap="round"' +
    ' stroke-dasharray="' + len.toFixed(1) + ' ' + (circ + 4).toFixed(1) + '" opacity=".92"/>' +
    '<text x="' + cx + '" y="' + (cy - 6) + '" text-anchor="middle" font-size="22" font-weight="500" fill="' + Charts.cssVar('--text', '#e6edf7') + '">' + mainText + '</text>' +
    '<text x="' + cx + '" y="' + (cy + 12) + '" text-anchor="middle" font-size="11" fill="' + arcColor + '">' + subText + '</text>' +
    '</svg>';
}

/* ---------- 加载主数据（10s 周期） ---------- */
async function loadDashboard(){
  clearInterval(dashTimer); clearInterval(evTimer);
  dashTimer = setInterval(loadDashboard, 10000);
  evTimer = setInterval(loadEventStream, 3000);
  loadEventStream();
  try{
    var s = (await api('GET', '/api/status')).data;

    var badge = document.getElementById('statusBadge');
    if (badge){
      badge.className = 'tag ' + (s.detection_enabled ? 'tag-success' : 'tag-error');
      badge.innerHTML = '<span class="dot pulse"></span>' + (s.detection_enabled ? '检测运行中' : '检测已关闭');
    }

    var tr = (await api('GET', '/api/status/trend?days=7')).data;
    var items = tr.items || [];
    var last = items[items.length - 1] || {}, prev = items[items.length - 2] || {};
    var elapsedH = tr.today_elapsed_hours || 0;
    /* 环比用"已完成整天"链：items 末位是今日（进行中），其前一位
       才是昨日整天——trendChip 内部按同时刻折算对比 */
    var today = tr.today || last;
    var yesterday = tr.yesterday || (items.length >= 2 ? items[items.length - 2] : null);
    var sum = (s.today_intercepts || 0) + (s.today_removes || 0) + (s.today_allows || 0);
    var rate = sum ? Math.round((s.today_intercepts || 0) / sum * 100) : 0;

    /* 威胁总览大数字带 */
    countUpIfChanged('hkTotal', s.today_total || 0);
    countUpIfChanged('hkInter', s.today_intercepts || 0);
    countUpIfChanged('hkRem', s.today_removes || 0);
    countUpIfChanged('hkAllow', s.today_allows || 0);
    document.getElementById('hkInterFoot').innerHTML =
      trendChip((today ? today.intercept : 0) || 0,
                (yesterday ? yesterday.intercept : 0) || 0, elapsedH);
    document.getElementById('hkRemFoot').innerHTML =
      trendChip((today ? today.remove_ip : 0) || 0,
                (yesterday ? yesterday.remove_ip : 0) || 0, elapsedH);

    /* 今日请求卡脚注：标注口径来源（filter_log=估算时不给"决策数"
       的精确暗示，防误导） */
    var hkTotalFoot = document.getElementById('hkTotalFoot');
    if (hkTotalFoot){
      hkTotalFoot.textContent = (s.stats_source === 'query_stats')
        ? '今日 DNS 查询总量（全量口径）'
        : '估算口径（放行日志未全量，数值偏低）';
    }
    var hkAllowFoot = document.getElementById('hkAllowFoot');
    if (hkAllowFoot){
      hkAllowFoot.textContent = (s.stats_source === 'query_stats')
        ? '检测放行（全量计数）'
        : '估算：仅采样命中的 allow 日志';
    }
    var riskFoot = document.getElementById('riskFoot');
    if (s.stats_source === 'query_stats'){
      var risk = riskLevel(rate, sum);
      renderGauge(rate, risk);
      riskFoot.textContent = risk.desc;
    } else {
      /* filter_log 估算口径：allows 被采样低估，拦截率必然虚高，
         精确数字有误导性——只给定性档位不给数字 */
      renderGauge('?');
      riskFoot.textContent = '口径说明：放行日志未全量，精确拦截率不可算';
    }

    /* 近 24h 柱线图（柱=拦截 线=剔除） */
    var hr = (await api('GET', '/api/status/hourly?hours=24')).data.items || [];
    var hLabels = hr.map(function(d){ return d.hour ? d.hour.slice(11, 16) : ''; });
    Charts.barLineChart(document.getElementById('hourlyChart'), hLabels,
      [{ name: '拦截', color: Charts.cssVar('--danger', '#f43f5e'),
         data: hr.map(function(d){ return d.intercepts || 0; }) }],
      [{ name: '剔除', color: Charts.cssVar('--warning', '#fbbf24'),
         data: hr.map(function(d){ return d.removes || 0; }) }]);

    /* breakdown：来源构成 + Top5 域名 + 客户端 Top */
    var bd = (await api('GET', '/api/status/breakdown?days=7&top=5')).data;
    var smap = {};
    (bd.sources || []).forEach(function(x){ smap[x.key] = x.count || 0; });
    var srcItems = [
      { key: 'local_blacklist', label: '人工黑名单', value: smap.local_blacklist || 0,
        color: Charts.cssVar('--danger', '#f43f5e') },
      { key: 'threat_list', label: '离线情报源', value: smap.threat_list || 0,
        color: Charts.cssVar('--warning', '#fbbf24') },
      { key: 'threatintel', label: '在线情报', value: smap.threatintel || 0,
        color: Charts.cssVar('--accent-2', '#6366f1') },
      { key: 'ip_filter', label: 'IP 后置', value: smap.ip_filter || 0,
        color: Charts.cssVar('--accent', '#38bdf8') }
    ];
    Charts.donut(document.getElementById('donutChart'), srcItems, { centerLabel: '次拦截/剔除' });
    renderTopMini(bd.top_domains || []);
    renderClients(bd.top_clients || []);
    renderChain(smap);

    /* 24h 热力图（小时 × 来源类型） */
    var hmRows = [
      { name: '人工黑名单', color: Charts.cssVar('--danger', '#f43f5e'),
        data: hr.map(function(d){ return d.local_blacklist || 0; }) },
      { name: '离线情报源', color: Charts.cssVar('--warning', '#fbbf24'),
        data: hr.map(function(d){ return d.threat_list || 0; }) },
      { name: '在线情报', color: Charts.cssVar('--accent-2', '#6366f1'),
        data: hr.map(function(d){ return d.threatintel || 0; }) },
      { name: 'IP 后置', color: Charts.cssVar('--accent', '#38bdf8'),
        data: hr.map(function(d){ return d.ip_filter || 0; }) }
    ];
    Charts.heatmap(document.getElementById('heatmap'), hLabels, hmRows, { height: 150 });

    renderHealth();
  }catch(e){ toast(e.message, true); }
}

/* ---------- 情报健康面板（在线源 / 离线库 / 上游 DNS） ---------- */
async function renderHealth(){
  try{
    var ti = (await api('GET', '/api/threatintel')).data.items || [];
    var enabled = ti.filter(function(x){ return x.enabled; }).length;
    var hpSrc = document.getElementById('hpSources');
    if (hpSrc) hpSrc.textContent = enabled + ' 启用';

    var tl = (await api('GET', '/api/threatlist/sources')).data.items || [];
    var total = tl.reduce(function(a, b){ return a + (b.count || 0); }, 0);
    var nexts = tl.map(function(x){ return x.next_update_at || ''; })
                  .filter(function(x){ return x; }).sort();
    var hpOff = document.getElementById('hpOffline');
    if (hpOff) hpOff.textContent = total.toLocaleString() + ' 条 · 下次 ' + (nexts.length ? nexts[0].slice(11, 16) : '--');

    var cfg = (await api('GET', '/api/config')).data.items || {};
    var up = (cfg.upstream_dns && cfg.upstream_dns.value) || '未配置';
    var hpUp = document.getElementById('hpUpstream');
    if (hpUp) hpUp.textContent = up;
  }catch(e){ /* 健康信息获取失败不阻塞主视图 */ }
}

/* ---------- 实时拦截事件流（3s 轮询，新事件置顶） ---------- */
function reasonLabel(reason){
  if (!reason) return '';
  if (reason === 'local_blacklist') return '人工黑名单';
  if (reason === 'threat_list') return '离线情报源';
  if (reason === 'ip_filter') return 'IP 后置';
  if (reason.indexOf('threatintel:') === 0) return '在线情报';
  return reason;
}
async function loadEventStream(){
  var el = document.getElementById('eventStream');
  if (!el) return;
  try{
    var d = (await api('GET', '/api/logs?size=8')).data;
    var items = (d && d.items) || [];
    if (items.length && items[0].id && items[0].id <= evLastId) return;
    evLastId = items.length ? items[0].id : 0;
    if (!items.length){
      el.innerHTML = '<div class="empty-state" style="padding:20px 0"><span class="es-ico">📭</span>暂无拦截事件</div>';
      return;
    }
    el.innerHTML = items.map(function(it){
      var t = (it.timestamp || '').slice(11, 19);
      var rm = it.action === 'remove_ip';
      return '<div class="ev-item ' + (rm ? 'ev-rm' : 'ev-in') + '">' +
             '<span class="ev-time">' + t + '</span>' +
             '<span class="ev-dom">' + esc(it.domain) + '</span>' +
             '<span class="ev-reason">' + esc(reasonLabel(it.filter_reason)) + '</span>' +
             '<span class="ev-act">' + (rm ? '剔除' : '拦截') + '</span></div>';
    }).join('');
  }catch(e){ /* 轮询失败静默，等待下一周期 */ }
}

/* ---------- Top5 域名（紧凑条） ---------- */
function renderTopMini(items){
  var el = document.getElementById('topDomainsMini');
  if (!el) return;
  if (!items.length){
    el.innerHTML = '<div class="empty-state" style="padding:10px 0"><span class="es-ico">🏆</span>暂无拦截域名</div>';
    return;
  }
  var max = items[0].count || 1;
  el.innerHTML = '<div class="toplist mini">' + items.map(function(it, i){
    var w = Math.max(4, Math.round((it.count / max) * 100));
    return '<div class="tl-item"><span class="tl-rank ' + (i < 3 ? 'r' + (i + 1) : '') + '">' + (i + 1) + '</span>' +
           '<span class="tl-domain" title="' + esc(it.domain) + '">' + esc(it.domain) + '</span>' +
           '<span class="tl-bar"><i style="width:' + w + '%"></i></span>' +
           '<span class="tl-count">' + it.count.toLocaleString() + '</span></div>';
  }).join('') + '</div>';
}

/* ---------- 客户端 Top（内网 IP） ---------- */
function renderClients(items){
  var el = document.getElementById('topClients');
  if (!el) return;
  if (!items.length){
    el.innerHTML = '<div class="empty-state" style="padding:20px 0"><span class="es-ico">💻</span>近 7 日无拦截记录或缺少客户端 IP</div>';
    return;
  }
  var max = items[0].count || 1;
  el.innerHTML = '<div class="toplist clients">' + items.map(function(it, i){
    var w = Math.max(4, Math.round((it.count / max) * 100));
    return '<div class="tl-item"><span class="tl-rank ' + (i < 3 ? 'r' + (i + 1) : '') + '">' + (i + 1) + '</span>' +
           '<span class="tl-domain" style="max-width:150px" title="' + esc(it.client_ip) + '">' + esc(it.client_ip) + '</span>' +
           '<span class="tl-bar"><i style="width:' + w + '%"></i></span>' +
           '<span class="tl-count">' + it.count.toLocaleString() + '</span></div>';
  }).join('') + '</div>';
}

/* ---------- 五层检测链路（纵向流水线，命中层发光） ---------- */
function renderChain(smap){
  var rows = [
    { step: '1', icon: '🛡', name: '人工白名单', desc: '命中即放行', state: 'ok', badge: '✓ 放行' },
    { step: '2', icon: '🚫', name: '人工黑名单', desc: '域名精确 + 父域匹配',
      state: smap.local_blacklist ? 'hit' : 'idle', badge: smap.local_blacklist ? '⚡ 命中 ' + smap.local_blacklist.toLocaleString() + ' 次' : '未命中' },
    { step: '3', icon: '📋', name: '离线情报源', desc: '本地离线域名库匹配',
      state: smap.threat_list ? 'hit' : 'idle', badge: smap.threat_list ? '⚡ 命中 ' + smap.threat_list.toLocaleString() + ' 次' : '未命中' },
    { step: '4', icon: '🌐', name: '在线情报', desc: '16 路威胁源实时查询',
      state: smap.threatintel ? 'hit' : 'idle', badge: smap.threatintel ? '⚡ 命中 ' + smap.threatintel.toLocaleString() + ' 次' : '未命中' },
    { step: '5', icon: '🔍', name: 'IP 后置', desc: '应答前源 IP 校验',
      state: smap.ip_filter ? 'hit' : 'idle', badge: smap.ip_filter ? '⚡ 命中 ' + smap.ip_filter.toLocaleString() + ' 次' : '未命中' },
    { step: '终', icon: '📡', name: '应答', desc: '放行 / 阻断告警', state: 'end', badge: '终点' }
  ];
  var html = '';
  rows.forEach(function(r, i){
    if (i > 0){
      html += '<div class="cf-line' + (r.state === 'hit' ? ' to-hit' : '') + '"></div>';
    }
    html += '<div class="cf-row ' + r.state + '">' +
            '<span class="cf-step">' + r.step + '</span>' +
            '<span class="cf-body"><span class="cf-name">' + r.icon + ' ' + r.name + '</span>' +
            '<span class="cf-desc">' + r.desc + '</span></span>' +
            '<span class="cf-badge ' + r.state + '">' + r.badge + '</span></div>';
  });
  document.getElementById('chainViz').innerHTML = html;
}

PAGE_LOADERS.dashboard = loadDashboard;

/* ============================================================
   pages/dashboard.js — 安全态势总览（P2 重做）
   指标卡(含环比) / 近7日趋势面积图 / 来源构成环形图 / Top榜 / 五层链路
   ============================================================ */

/* 环比箭头：涨红跌绿（国内习惯），返回 HTML 片段 */
function trendChip(cur, prev){
  if (cur == null || prev == null || !prev) return '<span class="kpi-trend flat">较上一日 —</span>';
  var delta = cur - prev;
  var pct = (prev === 0) ? (delta > 0 ? 100 : 0) : Math.round(delta / prev * 1000) / 10;
  if (delta > 0) return '<span class="kpi-trend up">↑ ' + pct + '%</span><span class="kpi-note">较上一日</span>';
  if (delta < 0) return '<span class="kpi-trend down">↓ ' + (-pct) + '%</span><span class="kpi-note">较上一日</span>';
  return '<span class="kpi-trend flat">持平</span><span class="kpi-note">较上一日</span>';
}

async function loadDashboard(){
  try{
    var s = (await api('GET', '/api/status')).data;

    /* 顶栏检测状态徽标 */
    var badge = document.getElementById('statusBadge');
    if (badge){
      badge.className = 'tag ' + (s.detection_enabled ? 'tag-success' : 'tag-error');
      badge.innerHTML = '<span class="dot pulse"></span>' + (s.detection_enabled ? '检测运行中' : '检测已关闭');
    }

    /* 指标卡（含环比，来自 trend 最近两天） */
    var tr = (await api('GET', '/api/status/trend?days=7')).data.items || [];
    var last = tr[tr.length - 1] || {}, prev = tr[tr.length - 2] || {};
    var tInter = last.intercepts || 0, tPrev = prev.intercepts || 0;
    var tRem = last.removes || 0, rPrev = prev.removes || 0;
    var sum = (s.today_intercepts || 0) + (s.today_removes || 0) + (s.today_allows || 0);
    var rate = sum ? Math.round((s.today_intercepts || 0) / sum * 100) : 0;

    document.getElementById('kpiGrid').innerHTML =
      '<div class="kpi kpi-red"><div class="kpi-top"><span class="kpi-label">今日拦截</span><span class="kpi-icon">🚫</span></div>' +
      '<div class="kpi-value">' + (s.today_intercepts || 0).toLocaleString() + '</div>' +
      '<div class="kpi-foot">' + trendChip(tInter, tPrev) + '</div></div>' +
      '<div class="kpi kpi-orange"><div class="kpi-top"><span class="kpi-label">今日剔除 IP</span><span class="kpi-icon">🧹</span></div>' +
      '<div class="kpi-value">' + (s.today_removes || 0).toLocaleString() + '</div>' +
      '<div class="kpi-foot">' + trendChip(tRem, rPrev) + '</div></div>' +
      '<div class="kpi kpi-green"><div class="kpi-top"><span class="kpi-label">今日放行</span><span class="kpi-icon">✅</span></div>' +
      '<div class="kpi-value">' + (s.today_allows || 0).toLocaleString() + '</div>' +
      '<div class="kpi-foot"><span class="kpi-trend flat">allow 记录</span><span class="kpi-note">需开启放行日志</span></div></div>' +
      '<div class="kpi kpi-blue"><div class="kpi-top"><span class="kpi-label">今日拦截率</span><span class="kpi-icon">📊</span></div>' +
      '<div class="kpi-value">' + rate + '<span style="font-size:17px;font-weight:700">%</span></div>' +
      '<div class="kpi-foot"><span class="kpi-trend flat">' + sum.toLocaleString() + ' 次决策</span><span class="kpi-note">拦/剔/放</span></div></div>';

    /* 近 7 日趋势面积图 */
    var labels = tr.map(function(d){ return d.day.slice(5); });
    Charts.areaChart(document.getElementById('trendChart'), labels, [
      { name: '拦截', color: Charts.cssVar('--danger', '#f43f5e'),
        data: tr.map(function(d){ return d.intercepts || 0; }) },
      { name: '剔除', color: Charts.cssVar('--warning', '#fbbf24'),
        data: tr.map(function(d){ return d.removes || 0; }) }
    ]);

    /* 来源构成 + Top 榜 + 链路（一次只读聚合接口） */
    var bd = (await api('GET', '/api/status/breakdown?days=7&top=10')).data;
    var smap = {};
    (bd.sources || []).forEach(function(x){ smap[x.key] = x.count || 0; });
    var items = [
      { key: 'local_blacklist', label: '本地黑名单', value: smap.local_blacklist || 0,
        color: Charts.cssVar('--danger', '#f43f5e') },
      { key: 'threat_list', label: '离线大名单', value: smap.threat_list || 0,
        color: Charts.cssVar('--warning', '#fbbf24') },
      { key: 'threatintel', label: '在线情报', value: smap.threatintel || 0,
        color: Charts.cssVar('--accent-2', '#6366f1') },
      { key: 'ip_filter', label: 'IP 后置', value: smap.ip_filter || 0,
        color: Charts.cssVar('--accent', '#38bdf8') }
    ];
    Charts.donut(document.getElementById('donutChart'), items, { centerLabel: '次拦截/剔除' });
    Charts.toplist(document.getElementById('topDomains'), bd.top_domains || []);
    renderChain(smap);

  }catch(e){ toast(e.message, true); }
}

/* ---------- 五层检测链路可视化 ---------- */
function renderChain(smap){
  function node(step, icon, name, countHtml, extra){
    return '<div class="chain-node ' + (extra || '') + '"><span class="cn-step">' + step + '</span>' +
           '<span class="cn-name">' + icon + ' ' + name + '</span><span class="cn-count">' + countHtml + '</span></div>';
  }
  function arrow(){ return '<div class="chain-arrow">➜</div>'; }
  var chain =
    node('Step 1', '🛡', '白名单', '优先放行') + arrow() +
    node('Step 2', '🚫', '本地黑名单', (smap.local_blacklist || 0) + ' 次', smap.local_blacklist ? 'hit' : '') + arrow() +
    node('Step 3', '📋', '离线大名单', (smap.threat_list || 0) + ' 次', smap.threat_list ? 'hit' : '') + arrow() +
    node('Step 4', '🌐', '在线情报', (smap.threatintel || 0) + ' 次', smap.threatintel ? 'hit' : '') + arrow() +
    node('Step 5', '🔍', 'IP 后置', (smap.ip_filter || 0) + ' 次', smap.ip_filter ? 'hit' : '') + arrow() +
    node('Reply', '📡', '应答', '放行/告警');
  document.getElementById('chainViz').innerHTML = chain;
}

PAGE_LOADERS.dashboard = loadDashboard;

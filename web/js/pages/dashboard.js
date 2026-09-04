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

    /* 近 24h 柱线图（柱=拦截 线=剔除）+ 下半来源热力图（同一 hourly
       数据源共享 X 轴——趋势看总量走势，热力看各来源的时段分布，
       两图意图互补合并一卡；原独立热力图卡位让给平台运行健康） */
    var hr = (await api('GET', '/api/status/hourly?hours=24')).data.items || [];
    var hLabels = hr.map(function(d){ return d.hour ? d.hour.slice(11, 16) : ''; });
    Charts.barLineChart(document.getElementById('hourlyChart'), hLabels,
      [{ name: '拦截', color: Charts.cssVar('--danger', '#f43f5e'),
         data: hr.map(function(d){ return d.intercepts || 0; }) }],
      [{ name: '剔除', color: Charts.cssVar('--warning', '#fbbf24'),
         data: hr.map(function(d){ return d.removes || 0; }) }]);

    /* breakdown：来源构成 + Top10 域名 + 客户端 Top（迭代 34：域名榜
       5→10 条，donut 同步缩至 150px 腾空间；top_clients 与 top_domains
       共用 top 参数，renderClients 内 slice(0,5) 保持客户端卡 5 条不变） */
    var bd = (await api('GET', '/api/status/breakdown?days=7&top=10')).data;
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
    Charts.donut(document.getElementById('donutChart'), srcItems, { centerLabel: '次拦截/剔除', size: 150 });
    renderTopMini(bd.top_domains || []);
    renderClients(bd.top_clients || []);
    renderChain(smap);

    /* 24h 热力图（小时 × 来源类型）——渲染进趋势卡下半区 */
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
    Charts.heatmap(document.getElementById('hourlyHeat'), hLabels, hmRows, { height: 118 });

    renderHealth();
    /* 健康卡独立 30s 周期（迭代 33）：首轮立即渲染（复用本轮已取的
       /api/status），此后 _hpTick 自主轮询，不随主数据 10s 刷新 */
    renderPlatformHealth(s);
    if (!hpTimer){
      hpTimer = setInterval(_hpTick, 30000);
    }
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
    /* Task #175：字段名对齐——后端返回 total/enabled_cnt（count 恒
       undefined → 旧版恒显示"0 条"）；total 含停用源条目，展示启用数
       与真实匹配口径一致（生产已停 hagezi_ult/stevenblack 等）。 */
    var total = tl.reduce(function(a, b){ return a + (b.enabled_cnt || 0); }, 0);
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

/* ---------- 平台运行健康（原热力图卡位，迭代 32；迭代 33 美化+刷新） ----------
   汇聚既有观测端点：检测开关 + 域名缓存命中率 + 日志写入队列 +
   保留清理 + 线程池队列。所有指标都有明确的"异常判据"，
   正常时显示数值，异常时整格标红——一眼巡检，无需翻系统配置页。
   性能设计（迭代 33）：
   - 独立 30s 定时器（健康指标变化缓慢，无需跟随主数据 10s 周期；
     4 端点全部 O(1) 内存计数读取，零 SQL）；
   - 值 diff：无变化跳过 innerHTML 重建，杜绝周期性整卡重绘闪烁；
     变化的格短暂闪烁高亮，肉眼可感知"刚更新"；
   - 注意：双进程部署下 queue-stats 读 Web 进程自身计数（恒 0），
     该格在 pending>0 时才有意义（单进程形态/本地验证）。 */
var hpTimer = null, hpLast = {};

function _fmtPct(rate){
  return (typeof rate === 'number') ? Math.round(rate * 100) + '%' : '--';
}
function _hpCell(key, ok, label, value, sub, color, warnText){
  var tip = warnText ? ' title="' + esc(warnText) + '"' : '';
  var badge = ok ? '✓' : '⚠';
  return '<div class="hpg-cell ' + (ok ? 'ok' : 'bad') + '" data-hp="' + key + '"' + tip + '>' +
         '<span class="hpg-bar" style="background:' + color + '"></span>' +
         '<div class="hpg-head"><span class="hpg-dot"></span>' +
         '<span class="hpg-label">' + esc(label) + '</span>' +
         '<span class="hpg-badge">' + badge + '</span></div>' +
         '<span class="hpg-value">' + value + '</span>' +
         '<span class="hpg-sub">' + sub + '</span></div>';
}
async function renderPlatformHealth(status){
  var el = document.getElementById('platformHealth');
  if (!el) return;
  try{
    var det = status && status.detection_enabled;
    var results = await Promise.allSettled([
      api('GET', '/api/domain-cache/stats'),
      api('GET', '/api/log-writer/stats'),
      api('GET', '/api/queue-stats'),
      api('GET', '/api/log-retention/stats'),
    ]);
    var dc = results[0].status === 'fulfilled' ? results[0].value.data : null;
    var lw = results[1].status === 'fulfilled' ? results[1].value.data : null;
    var qs = results[2].status === 'fulfilled' ? results[2].value.data : null;
    var lr = results[3].status === 'fulfilled' ? results[3].value.data : null;
    var OK = Charts.cssVar('--success', '#34d399');
    var AC = Charts.cssVar('--accent', '#38bdf8');
    var A2 = Charts.cssVar('--accent-2', '#6366f1');
    var WA = Charts.cssVar('--warning', '#fbbf24');

    var cells = [
      _hpCell('det', det, '检测引擎', det ? '运行中' : '已关闭',
              det ? '黑白名单+情报源全链路' : '检测关闭 · 全部放行',
              det ? OK : Charts.cssVar('--danger', '#f43f5e'),
              det ? '' : '检测总开关已关闭，全部请求直接放行'),
      _hpCell('dc', true, '域名缓存',
              dc ? (dc.size || 0).toLocaleString() : '--',
              dc ? '命中率 ' + _fmtPct(dc.hit_rate) + ' · 容量 ' +
                   ((dc.max_size || 0) / 10000).toLocaleString() + '万' : '',
              AC),
      _hpCell('lw', !lw || !(lw.dropped > 0), '日志写入',
              lw ? ('队列 ' + (lw.queue_size || 0)) : '--',
              lw ? ('累计 ' + (lw.flushed || 0).toLocaleString() + ' 条 · 丢 ' + (lw.dropped || 0)) : '',
              WA,
              'dropped>0：写入跟不上，需调大批量/缩短间隔或检查磁盘 IO'),
      _hpCell('qs', !qs || (qs.pending || 0) < 100, '检测队列',
              qs ? ('待 ' + (qs.pending || 0)) : '--',
              qs ? ('执行 ' + (qs.inflight || 0) + ' · 峰值 ' + (qs.max_pending || 0)) : '',
              A2,
              'pending≥100：检测线程池供不应求（双进程部署读 Web 计数恒 0 属正常）'),
      _hpCell('lr', !lr || (lr.last_run_at || 0) > 0 || (lr.total_deleted || 0) === 0, '日志清理',
              lr ? ((lr.total_deleted || 0).toLocaleString() + ' 条') : '--',
              lr ? ((lr.total_runs || 0) + ' 轮 · 保留天数自动清理') : '',
              OK,
              '清理线程未运行且库持续增长时检查保留天数配置'),
    ];

    /* 值 diff：格子内容（value/sub/ok 三元组）与上次一致则跳过重建 */
    var sig = cells.join('|');
    if (sig !== hpLast.sig){
      hpLast.sig = sig;
      el.innerHTML = '<div class="hpg-wrap">' + cells.join('') + '</div>';
    }
    /* 卡头徽标 */
    var tag = document.getElementById('healthTag');
    if (tag){
      var bad = 0;
      cells.forEach(function(c){ if (c.indexOf('hpg-cell bad') >= 0) bad++; });
      var tagSig = 'tag' + bad;
      if (hpLast.tagSig !== tagSig){
        hpLast.tagSig = tagSig;
        tag.className = 'tag ' + (bad ? 'tag-error' : 'tag-success');
        tag.innerHTML = '<span class="dot pulse"></span>' +
                        (bad ? bad + ' 项异常' : '全部正常');
      }
    }
  }catch(e){
    el.innerHTML = '<div class="empty-state" style="padding:20px 0"><span class="es-ico">⚠</span>健康数据获取失败</div>';
  }
}
/* 独立 30s 刷新（ detached 自 loadDashboard 的 10s 主周期——
   健康指标变化缓慢，降频 3 倍省请求；与 dashTimer 同生命周期管理） */
function _hpTick(){
  api('GET', '/api/status').then(function(r){
    renderPlatformHealth(r.data);
  }).catch(function(){ /* 静默等下个周期 */ });
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
    /* Task #175（迭代 28）：改走轻量事件流端点——只含拦截/剔除，
       不混 allow 采样日志（旧 /api/logs 会把放行日志渲染成"拦截"），
       且无 COUNT(*) 全表扫描，3s 高频轮询开销 O(size)。 */
    var d = (await api('GET', '/api/logs/stream?size=8')).data;
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
  /* 迭代 34：breakdown 的 top 参数升 10 后，客户端卡仍保持 5 条
     （布局不动；如未来要同步 10 条，去掉 slice 即可） */
  items = (items || []).slice(0, 5);
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

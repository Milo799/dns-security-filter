/* ============================================================
   charts.js — 自绘 SVG 图表（零第三方依赖，离线可用）
   颜色全部取自 theme.css CSS 变量，随深浅主题自动切换
   对外：window.Charts = { areaChart, donut, toplist, cssVar }
   ============================================================ */
window.Charts = (function(){

  function cssVar(name, fallback){
    var v = getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
    return v || fallback;
  }
  var C = {
    danger:   function(){ return cssVar('--danger', '#f43f5e'); },
    warning:  function(){ return cssVar('--warning', '#fbbf24'); },
    accent:   function(){ return cssVar('--accent', '#38bdf8'); },
    accent2:  function(){ return cssVar('--accent-2', '#6366f1'); },
    success:  function(){ return cssVar('--success', '#34d399'); },
    text:     function(){ return cssVar('--text', '#e6edf7'); },
    textDim:  function(){ return cssVar('--text-dim', '#5d7299'); },
    textSec:  function(){ return cssVar('--text-sec', '#94a3bd'); },
    grid:     function(){ return cssVar('--border', '#1f2b47'); }
  };

  /* ---------- 面积图（多序列折线 + 渐变填充 + 峰值标注） ----------
     areaChart(el, labels, series, {height, format})
       labels:  ['07-21', ...]
       series:  [{name, color, data:[...]}]
     el 为容器（清空后填入 svg） */
  function areaChart(el, labels, series, opts){
    opts = opts || {};
    var W = 560, H = opts.height || 220;
    var padL = 36, padR = 12, padT = 20, padB = 26;
    var pw = W - padL - padR, ph = H - padT - padB;
    var n = labels.length;
    if (!n){ el.innerHTML = '<div class="empty-state"><span class="es-ico">📈</span>暂无数据</div>'; return; }

    var max = 1;
    series.forEach(function(s){ s.data.forEach(function(v){ max = Math.max(max, v || 0); }); });
    max = Math.ceil(max * 1.15 / Math.max(1, Math.pow(10, Math.floor(Math.log10(max * 1.15 || 1))))) * Math.max(1, Math.pow(10, Math.floor(Math.log10(max * 1.15 || 1))));

    function X(i){ return padL + (n === 1 ? pw / 2 : i / (n - 1) * pw); }
    function Y(v){ return padT + ph - (v / max) * ph; }

    // Y 网格
    var grid = '';
    for (var g = 0; g <= 4; g++){
      var gy = padT + ph * g / 4;
      var gv = Math.round(max * (4 - g) / 4);
      grid += '<line x1="' + padL + '" y1="' + gy + '" x2="' + (W - padR) + '" y2="' + gy +
              '" stroke="' + C.grid() + '" stroke-width="1" stroke-dasharray="3 4" opacity=".6"/>' +
              '<text x="' + (padL - 7) + '" y="' + (gy + 3.5) + '" text-anchor="end" font-size="9" fill="' + C.textDim() + '">' + gv + '</text>';
    }

    // 序列折线 + 面积
    var paths = '', peak = null;
    series.forEach(function(s, si){
      var d = s.data.map(function(v, i){
        return (i === 0 ? 'M' : 'L') + X(i).toFixed(1) + ' ' + Y(v || 0).toFixed(1);
      }).join(' ');
      var area = d + ' L' + X(n - 1).toFixed(1) + ' ' + (padT + ph) + ' L' + X(0).toFixed(1) + ' ' + (padT + ph) + ' Z';
      var gid = 'ag' + si;
      paths += '<defs><linearGradient id="' + gid + '" x1="0" y1="0" x2="0" y2="1">' +
               '<stop offset="0" stop-color="' + s.color + '" stop-opacity=".32"/>' +
               '<stop offset="1" stop-color="' + s.color + '" stop-opacity=".02"/>' +
               '</linearGradient></defs>' +
               '<path d="' + area + '" fill="url(#' + gid + ')"/>' +
               '<path d="' + d + '" fill="none" stroke="' + s.color + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" opacity=".95"/>';
      s.data.forEach(function(v, i){
        if (peak === null || v > peak.v){ peak = {v: v, x: X(i), y: Y(v || 0), i: i, color: s.color}; }
      });
    });

    // 峰值标注
    var peakMark = '';
    if (peak && peak.v > 0){
      peakMark = '<circle cx="' + peak.x.toFixed(1) + '" cy="' + peak.y.toFixed(1) + '" r="4" fill="' + peak.color + '" stroke="' + cssVar('--card', '#121a2e') + '" stroke-width="2"/>' +
                 '<text x="' + peak.x.toFixed(1) + '" y="' + (peak.y - 8).toFixed(1) + '" text-anchor="middle" font-size="10" font-weight="700" fill="' + peak.color + '">' + peak.v + '</text>';
    }

    // X 轴标签（防重叠：n>7 时隔一显示）
    var xlabels = '';
    var step = n > 7 ? 2 : 1;
    for (var i = 0; i < n; i += step){
      xlabels += '<text x="' + X(i).toFixed(1) + '" y="' + (H - 8) + '" text-anchor="middle" font-size="9" fill="' + C.textDim() + '">' + esc(labels[i]) + '</text>';
    }

    var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" xmlns="http://www.w3.org/2000/svg" role="img">' +
              grid + paths + peakMark + xlabels + '</svg>';

    // 图例
    var legend = '<div class="donut-legend" style="flex-direction:row;justify-content:center;gap:16px;margin-bottom:2px">' +
      series.map(function(s){
        return '<span class="dl-item"><span class="dl-dot" style="background:' + s.color + '"></span><span class="dl-name">' + esc(s.name) + '</span></span>';
      }).join('') + '</div>';

    el.innerHTML = legend + svg;
  }

  /* ---------- 环形图（分类占比，中心显总数） ---------- */
  function donut(el, items, opts){
    opts = opts || {};
    var total = items.reduce(function(a, b){ return a + (b.value || 0); }, 0);
    if (!total){
      el.innerHTML = '<div class="empty-state"><span class="es-ico">🍩</span>暂无拦截数据</div>';
      return;
    }
    var W = 210, cx = 105, cy = 105, r = 74, sw = 26;
    var circ = 2 * Math.PI * r;
    var off = 0, segs = '';
    items.forEach(function(it, idx){
      var len = circ * (it.value / total);
      var gap = circ - len;
      var id = 'seg' + idx;
      segs += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + it.color + '" stroke-width="' + sw + '"' +
              ' stroke-dasharray="' + len.toFixed(2) + ' ' + gap.toFixed(2) + '" stroke-dashoffset="' + (-off).toFixed(2) + '"' +
              ' transform="rotate(-90 ' + cx + ' ' + cy + ')" opacity=".92" stroke-linecap="butt"/>';
      off += len;
    });
    var svg = '<svg viewBox="0 0 ' + W + ' ' + W + '" xmlns="http://www.w3.org/2000/svg" style="width:190px;height:190px">' +
              '<circle cx="' + cx + '" cy="' + cy + '" r="' + (r - sw / 2 - 8) + '" fill="none" stroke="' + C.grid() + '" stroke-width="1" stroke-dasharray="2 4" opacity=".5"/>' +
              segs +
              '<text x="' + cx + '" y="' + (cy - 2) + '" text-anchor="middle" font-size="24" font-weight="800" fill="' + C.text() + '">' + total.toLocaleString() + '</text>' +
              '<text x="' + cx + '" y="' + (cy + 17) + '" text-anchor="middle" font-size="10.5" fill="' + C.textDim() + '">' + (opts.centerLabel || '次拦截') + '</text>' +
              '</svg>';
    var legend = '<div class="donut-legend">' +
      items.map(function(it){
        return '<div class="dl-item"><span class="dl-dot" style="background:' + it.color + '"></span>' +
               '<span class="dl-name">' + esc(it.label) + '</span>' +
               '<span class="dl-val">' + (it.value || 0).toLocaleString() + '</span></div>';
      }).join('') + '</div>';
    el.innerHTML = '<div class="donut-wrap">' + svg + legend + '</div>';
  }

  /* ---------- Top 榜（HTML 横向条形，纯 CSS） ---------- */
  function toplist(el, items){
    if (!items || !items.length){
      el.innerHTML = '<div class="empty-state"><span class="es-ico">🏆</span>暂无拦截域名</div>';
      return;
    }
    var max = items[0].count || 1;
    var ranks = ['r1', 'r2', 'r3'];
    el.innerHTML = '<div class="toplist">' + items.map(function(it, i){
      var w = Math.max(4, Math.round((it.count / max) * 100));
      return '<div class="tl-item">' +
        '<span class="tl-rank ' + (ranks[i] || '') + '">' + (i + 1) + '</span>' +
        '<span class="tl-domain" title="' + esc(it.domain) + '">' + esc(it.domain) + '</span>' +
        '<span class="tl-bar"><i style="width:' + w + '%"></i></span>' +
        '<span class="tl-count">' + it.count.toLocaleString() + '</span></div>';
    }).join('') + '</div>';
  }

  return { areaChart: areaChart, donut: donut, toplist: toplist, cssVar: cssVar };
})();

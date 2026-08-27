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

  /* ---------- 柱 + 线混合图（近24h 趋势，SOC 大屏） ----------
     barLineChart(el, labels, bars, lines, opts)
       bars:  [{name, color, data}]  主序列 → 柱（左轴刻度）
       lines: [{name, color, data}]  次序列 → 线（右轴自身 max 缩放）
     opts: {height} */
  function barLineChart(el, labels, bars, lines, opts){
    opts = opts || {};
    var W = 560, H = opts.height || 190;
    var padL = 36, padR = 40, padT = 16, padB = 24;
    var pw = W - padL - padR, ph = H - padT - padB;
    var n = labels.length;
    if (!n || (!bars.length && !lines.length)){
      el.innerHTML = '<div class="empty-state"><span class="es-ico">📊</span>暂无数据</div>'; return;
    }
    // 左轴：柱序列最大值
    var maxB = 1;
    bars.forEach(function(s){ s.data.forEach(function(v){ maxB = Math.max(maxB, v || 0); }); });
    var maxL = 1;
    lines.forEach(function(s){ s.data.forEach(function(v){ maxL = Math.max(maxL, v || 0); }); });
    function X(i){ return padL + (n === 1 ? pw / 2 : i / (n - 1) * pw); }
    function Yb(v){ return padT + ph - (v / maxB) * ph; }
    function Yl(v){ return padT + ph - (v / maxL) * ph; }
    var bw = Math.min(22, pw / n * 0.55);

    // 网格（左轴刻度）
    var grid = '';
    for (var g = 0; g <= 4; g++){
      var gy = padT + ph * g / 4;
      var gv = Math.round(maxB * (4 - g) / 4);
      grid += '<line x1="' + padL + '" y1="' + gy + '" x2="' + (W - padR) + '" y2="' + gy +
              '" stroke="' + C.grid() + '" stroke-width="1" stroke-dasharray="3 4" opacity=".6"/>' +
              '<text x="' + (padL - 7) + '" y="' + (gy + 3.5) + '" text-anchor="end" font-size="9" fill="' + C.textDim() + '">' + gv + '</text>';
    }
    // 柱
    var barsSvg = '';
    bars.forEach(function(s){
      s.data.forEach(function(v, i){
        var h = Math.max(1, (v || 0) / maxB * ph);
        var x = X(i) - bw / 2;
        var y = padT + ph - h;
        barsSvg += '<rect x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" width="' + bw.toFixed(1) +
                   '" height="' + h.toFixed(1) + '" rx="3" fill="' + s.color + '" opacity=".9">' +
                   '<title>' + esc(labels[i] || '') + ' ' + esc(s.name) + ': ' + (v || 0) + '</title></rect>';
      });
    });
    // 线（右轴自身 max）
    var linesSvg = '';
    lines.forEach(function(s){
      var d = s.data.map(function(v, i){
        return (i === 0 ? 'M' : 'L') + X(i).toFixed(1) + ' ' + Yl(v || 0).toFixed(1);
      }).join(' ');
      linesSvg += '<path d="' + d + '" fill="none" stroke="' + s.color + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" opacity=".95"/>';
      s.data.forEach(function(v, i){
        if (v > 0) linesSvg += '<circle cx="' + X(i).toFixed(1) + '" cy="' + Yl(v || 0).toFixed(1) + '" r="2.5" fill="' + s.color + '"/>';
      });
      // 右轴 max 标注
      linesSvg += '<text x="' + (W - padR + 6) + '" y="' + (padT + 4) + '" font-size="9" fill="' + s.color + '">' + maxL + '</text>';
    });
    // X 轴标签（每 3 小时标一个）
    var xlabels = '';
    for (var i = 0; i < n; i += 3){
      xlabels += '<text x="' + X(i).toFixed(1) + '" y="' + (H - 8) + '" text-anchor="middle" font-size="9" fill="' + C.textDim() + '">' + esc(labels[i]) + '</text>';
    }
    var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" xmlns="http://www.w3.org/2000/svg" role="img">' +
              grid + barsSvg + linesSvg + xlabels + '</svg>';
    var legend = '<div class="donut-legend" style="flex-direction:row;justify-content:center;gap:16px;margin-bottom:2px">' +
      bars.concat(lines).map(function(s){
        return '<span class="dl-item"><span class="dl-dot" style="background:' + s.color + '"></span><span class="dl-name">' + esc(s.name) + '</span></span>';
      }).join('') + '</div>';
    el.innerHTML = legend + svg;
  }

  /* ---------- 热力图（小时 × 来源，SOC 大屏） ----------
     heatmap(el, labels, rows, opts)
       labels: ['00', '03', ...] 24 个列标签（每 N 个标一个）
       rows:   [{name, color, data:[n]}]
     opts: {height} 单元格高度按行数自适应 */
  function heatmap(el, labels, rows, opts){
    opts = opts || {};
    var W = 560, H = opts.height || 150;
    var padL = 74, padR = 8, padT = 14, padB = 20;
    var pw = W - padL - padR, ph = H - padT - padB;
    var n = labels.length;
    if (!n || !rows.length){
      el.innerHTML = '<div class="empty-state"><span class="es-ico">🔥</span>暂无数据</div>'; return;
    }
    var maxV = 1;
    rows.forEach(function(r){ r.data.forEach(function(v){ maxV = Math.max(maxV, v || 0); }); });
    var cw = pw / n, ch = Math.min(22, ph / rows.length);
    var html = '<div class="heatmap">';
    // 行头
    rows.forEach(function(r, ri){
      var y = padT + ri * ch;
      html += '<div class="hm-row-head" style="color:' + r.color + ';top:' + y + 'px">' + esc(r.name) + '</div>';
    });
    // 单元格 + 列头
    html += '<svg viewBox="0 0 ' + W + ' ' + H + '" xmlns="http://www.w3.org/2000/svg" role="img" style="width:100%;height:auto">';
    for (var i = 0; i < n; i++){
      if (i % 4 === 0){
        html += '<text x="' + (padL + i * cw + cw / 2).toFixed(1) + '" y="' + (padT - 5) + '" text-anchor="middle" font-size="9" fill="' + C.textDim() + '">' + esc(labels[i]) + '</text>';
      }
      rows.forEach(function(r, ri){
        var v = r.data[i] || 0;
        var a = v ? 0.18 + 0.82 * (v / maxV) : 0.07;
        var x = padL + i * cw + 1, y = padT + ri * ch + 1;
        html += '<rect x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" width="' + (cw - 2).toFixed(1) +
                '" height="' + (ch - 2).toFixed(1) + '" rx="2" fill="' + r.color + '" opacity="' + a.toFixed(2) + '">' +
                '<title>' + (labels[i] || '') + ':00 ' + esc(r.name) + ': ' + v + '</title></rect>';
      });
    }
    html += '</svg></div>';
    el.innerHTML = html;
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

  return { areaChart: areaChart, donut: donut, toplist: toplist,
           barLineChart: barLineChart, heatmap: heatmap, cssVar: cssVar };
})();

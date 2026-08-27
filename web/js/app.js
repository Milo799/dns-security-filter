/* ============================================================
   app.js — 核心工具 + REST 封装 + 全局状态（页面模块依赖本文件）
   加载顺序：app.js → charts.js → pages/*.js → boot.js
   ============================================================ */
var TOKEN = localStorage.getItem('dnsf_token') || '';
var USERNAME = localStorage.getItem('dnsf_user') || '';
var PAGE_LOADERS = {};   // 各页面模块在此注册加载器，boot.js 的 go() 调用

/* ---------- 转义 ---------- */
function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}

/* ---------- 轻提示 ---------- */
function toast(msg, err){
  var t = document.getElementById('toast');
  t.className = 'show ' + (err ? 'err' : 'ok');
  t.innerHTML = '<span class="t-ico">' + (err ? '⚠' : '✔') + '</span><span>' + esc(msg) + '</span>';
  clearTimeout(toast._t);
  toast._t = setTimeout(function(){ t.className = ''; }, 2800);
}

/* ---------- REST 封装（Bearer 鉴权，401 自动登出） ---------- */
async function api(method, path, body, raw){
  var opts = {method: method, headers: {}};
  if (TOKEN) opts.headers['Authorization'] = 'Bearer ' + TOKEN;
  if (body !== undefined){
    if (raw){
      opts.headers['Content-Type'] = 'text/csv; charset=utf-8';
      opts.body = body;
    } else {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
  }
  var r = await fetch(path, opts);
  if (r.status === 401){ doLogout(true); throw new Error('登录已过期，请重新登录'); }
  var ct = r.headers.get('content-type') || '';
  if (ct.indexOf('json') >= 0){
    var j = await r.json();
    if (!r.ok) throw new Error((j.detail) || ('HTTP ' + r.status));
    return j;
  }
  return r;
}

/* ---------- 文件下载 ---------- */
function downloadBlob(blob, name){
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
  setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);
}

/* ---------- 分页器 ---------- */
function pager(el, total, page, size, loader){
  var pages = Math.max(1, Math.ceil(total / size));
  el.innerHTML = '<span>共 ' + total + ' 条 · 第 ' + page + ' / ' + pages + ' 页</span>'
    + (page > 1 ? '<button class="btn btn-normal btn-compact" onclick="' + loader + '(' + (page - 1) + ')">‹ 上一页</button>' : '')
    + (page < pages ? '<button class="btn btn-normal btn-compact" onclick="' + loader + '(' + (page + 1) + ')">下一页 ›</button>' : '');
}

/* ---------- 弹窗 ---------- */
function closeModal(id){ document.getElementById(id).classList.remove('show'); }

/* ---------- 导航（页面模块先注册 PAGE_LOADERS） ---------- */
function go(page){
  document.querySelectorAll('.nav-item').forEach(function(n){
    n.classList.toggle('active', n.dataset.page === page);
  });
  document.querySelectorAll('.page').forEach(function(p){
    p.classList.toggle('active', p.id === 'page-' + page);
  });
  window.scrollTo(0, 0);
  if (PAGE_LOADERS[page]) PAGE_LOADERS[page]();
}

/* ---------- 字节格式化（大名单进度用） ---------- */
function fmtBytes(n){
  if (!n && n !== 0) return '';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(0) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

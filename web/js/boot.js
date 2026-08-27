/* ============================================================
   boot.js — 启动逻辑（登录 / 导航 / 主题切换 / Token 校验）
   必须在 app.js、charts.js、pages/*.js 之后加载
   ============================================================ */

/* ---------- 主题切换（深色 SOC 默认，浅色可选） ---------- */
(function(){
  if (localStorage.getItem('dnsf_theme') === 'light') document.body.classList.add('light');
})();
function toggleTheme(){
  document.body.classList.toggle('light');
  localStorage.setItem('dnsf_theme', document.body.classList.contains('light') ? 'light' : 'dark');
  var btn = document.getElementById('themeToggle');
  if (btn) btn.textContent = document.body.classList.contains('light') ? '☀' : '☾';
}

/* ---------- 登录 ---------- */
async function doLogin(){
  var u = document.getElementById('loginUser').value.trim();
  var p = document.getElementById('loginPass').value;
  document.getElementById('loginErr').textContent = '';
  try{
    var r = await api('POST', '/api/auth/login', {username: u, password: p});
    TOKEN = r.data.token;
    USERNAME = u;
    localStorage.setItem('dnsf_token', TOKEN);
    localStorage.setItem('dnsf_user', u);
    enterApp();
  }catch(e){ document.getElementById('loginErr').textContent = e.message; }
}

function doLogout(expired){
  TOKEN = '';
  localStorage.removeItem('dnsf_token');
  document.getElementById('app').style.display = 'none';
  document.getElementById('loginScreen').style.display = 'flex';
  if (expired) toast('登录已过期', true);
}

function enterApp(){
  document.getElementById('loginScreen').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  document.getElementById('avatar').textContent = (USERNAME || 'admin').slice(0, 2).toUpperCase();
  loadDashboard();
}

/* ---------- 事件绑定 ---------- */
document.getElementById('loginPass').addEventListener('keydown', function(e){
  if (e.key === 'Enter') doLogin();
});
document.querySelectorAll('.nav-item').forEach(function(el){
  el.addEventListener('click', function(){ go(el.dataset.page); });
});

/* ---------- 启动：已有 Token 则校验并进入 ---------- */
if (TOKEN){
  api('GET', '/api/status').then(enterApp).catch(function(){
    TOKEN = '';
    localStorage.removeItem('dnsf_token');
  });
}

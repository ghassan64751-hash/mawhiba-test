'use strict';
/*
  خادم اختبار القدرات العقلية: تسجيل دخول + لوحة المعلم + حفظ النتائج (بدون قاعدة بيانات).
  البيانات تُحفظ في ملف واحد data.json. لا يغيّر ملف index.html: يقرؤه ويضيف إليه سكربتًا صغيرًا عند تقديمه للطالب.
  المتغيرات في Render:
    TEACHER_PASS  كلمة مرور المعلم (مطلوب)
    TEACHER_USER  اسم دخول المعلم (اختياري، الافتراضي teacher)
    DATA_DIR      مجلد حفظ البيانات (اختياري). اجعله /data إذا أضفت Disk في Render.
*/
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const TEACHER_USER = (process.env.TEACHER_USER || 'teacher').toLowerCase();
const TEACHER_PASS = process.env.TEACHER_PASS;
if (!TEACHER_PASS) {
  console.error('Missing environment variable: TEACHER_PASS is required.');
  process.exit(1);
}
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update('mw|' + TEACHER_PASS).digest('hex');

/* ---------- تشفير وجلسات ---------- */
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken(obj, hours) {
  const body = Buffer.from(JSON.stringify(Object.assign({}, obj, { exp: Date.now() + hours * 3600e3 }))).toString('base64url');
  return body + '.' + sign(body);
}
function readToken(tok) {
  if (!tok || tok.indexOf('.') < 0) return null;
  const parts = tok.split('.');
  const a = Buffer.from(parts[1] || ''), b = Buffer.from(sign(parts[0]));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const o = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    return o.exp > Date.now() ? o : null;
  } catch (e) { return null; }
}
function parseCookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) { try { o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch (e) { /* ignore */ } }
  });
  return o;
}
function setSession(req, res, obj, hours) {
  res.cookie('mw', makeToken(obj, hours), { httpOnly: true, sameSite: 'lax', secure: !!req.secure, maxAge: hours * 3600e3, path: '/' });
}
const scrypt = (pw, salt) => new Promise((resolve, reject) =>
  crypto.scrypt(pw, salt, 32, { N: 4096, r: 8, p: 1 }, (e, k) => (e ? reject(e) : resolve(k))));
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + (await scrypt(pw, salt)).toString('hex');
}
async function checkPw(pw, stored) {
  const parts = String(stored).split(':');
  const k = await scrypt(pw, Buffer.from(parts[0], 'hex'));
  const h = Buffer.from(parts[1] || '', 'hex');
  return h.length === k.length && crypto.timingSafeEqual(h, k);
}
const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

/* ---------- حماية من تخمين كلمات المرور ---------- */
const fails = new Map();
function locked(key) {
  const f = fails.get(key);
  if (!f || f.n < 6) return false;
  if (Date.now() - f.t > 5 * 60e3) { fails.delete(key); return false; }
  return true;
}
function addFail(key) {
  const f = fails.get(key) || { n: 0, t: 0 };
  f.n++; f.t = Date.now(); fails.set(key, f);
}

/* ---------- التخزين في ملف ---------- */
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'data.json');
let D = { users: [], results: [], open: true, nextUserId: 1, nextResultId: 1 };
function loadData() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    const j = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    D = Object.assign(D, j);
  } catch (e) {
    if (e.code !== 'ENOENT') { console.error('Cannot read data file (not overwriting it):', e.message); process.exit(1); }
  }
}
let saving = Promise.resolve();
function save() {
  saving = saving.then(async () => {
    const tmp = DATA_FILE + '.tmp';
    await fs.promises.writeFile(tmp, JSON.stringify(D));
    await fs.promises.rename(tmp, DATA_FILE);
  }).catch(e => console.error('Save failed:', e.message));
  return saving;
}
const isOpen = () => D.open !== false;
const findUser = id => D.users.find(u => u.id === id);
async function auth(req) {
  const t = readToken(parseCookies(req).mw);
  if (!t) return null;
  if (t.r === 't') return { role: 't' };
  const u = findUser(t.id);
  return u ? { role: 's', id: u.id, username: u.username, name: u.name } : null;
}

/* ---------- كود المتصفح (يُدمج في الصفحات كنص) ---------- */
function clientHook() {
  var $ = function (id) { return document.getElementById(id); };
  var n = $('sname');
  if (n && window.MW_NAME) {
    n.value = window.MW_NAME; n.readOnly = true;
    setInterval(function () { if (!n.value) n.value = window.MW_NAME; }, 500);
  }
  var h = document.querySelector('header.top');
  if (h) {
    var a = document.createElement('a');
    a.href = '/logout'; a.className = 'chip'; a.style.textDecoration = 'none'; a.textContent = 'تسجيل الخروج';
    h.appendChild(a);
  }
  var tt;
  function toast(m, bad) {
    var t = $('mwToast');
    if (!t) {
      t = document.createElement('div'); t.id = 'mwToast';
      t.style.cssText = 'position:fixed;left:16px;right:16px;bottom:16px;max-width:420px;margin:auto;padding:10px 16px;border-radius:12px;text-align:center;z-index:99;font-weight:700;color:#fff';
      document.body.appendChild(t);
    }
    t.style.background = bad ? '#c43c3c' : '#1d8a55'; t.textContent = m; t.style.display = 'block';
    clearTimeout(tt); tt = setTimeout(function () { t.style.display = 'none'; }, 5000);
  }
  function txt(id) { var e = $(id); return e ? e.textContent.trim() : ''; }
  function post(body, sig, tries) {
    fetch('/api/result', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-MW': '1' }, body: JSON.stringify(body) })
      .then(function (r) {
        if (r.ok) {
          try { localStorage.setItem('__mwlast', sig); } catch (e) { /* ignore */ }
          toast('تم حفظ نتيجتك عند المعلم ✓');
        } else if (r.status >= 500 && tries > 0) {
          setTimeout(function () { post(body, sig, tries - 1); }, 3000);
        } else {
          r.json().then(function (j) { toast(j.error || 'تعذّر حفظ النتيجة', true); }, function () { toast('تعذّر حفظ النتيجة', true); });
        }
      })
      .catch(function () {
        if (tries > 0) setTimeout(function () { post(body, sig, tries - 1); }, 3000);
        else toast('تعذّر حفظ النتيجة، تأكد من الاتصال بالإنترنت', true);
      });
  }
  function send() {
    var rv = document.querySelectorAll('#rvList .rv'), total = rv.length, score = 0;
    rv.forEach(function (x) { if (!x.classList.contains('wrong') && !x.classList.contains('skip')) score++; });
    if (!total) {
      score = parseInt(txt('sc'), 10) || 0;
      total = parseInt((txt('scOf').match(/\d+/) || [0])[0], 10) || 0;
    }
    var secs = [];
    document.querySelectorAll('#secs .secrow').forEach(function (r) {
      var c = r.children;
      secs.push({ n: c[0] ? c[0].textContent.trim() : '', v: c.length ? c[c.length - 1].textContent.trim() : '' });
    });
    var body = { model: txt('whoModel'), score: score, total: total, grade: txt('grade'), meta: txt('rMeta'), sections: secs };
    var sig = [body.model, body.score, body.total, body.meta].join('|');
    try { if (localStorage.getItem('__mwlast') === sig) return; } catch (e) { /* ignore */ }
    post(body, sig, 3);
  }
  var res = $('result'), armed = false;
  if (res) {
    new MutationObserver(function () {
      if (!res.hidden && !armed) { armed = true; setTimeout(send, 1500); }
      else if (res.hidden) armed = false;
    }).observe(res, { attributes: true, attributeFilter: ['hidden'] });
  }
}

function loginClient() {
  var f = document.getElementById('f'), err = document.getElementById('err');
  f.addEventListener('submit', function (e) {
    e.preventDefault(); err.textContent = '';
    fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-MW': '1' }, body: JSON.stringify({ username: f.u.value, password: f.p.value }) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (x) { if (x.ok) location.href = x.j.to; else err.textContent = x.j.error || 'تعذّر الدخول'; })
      .catch(function () { err.textContent = 'تعذّر الاتصال بالخادم'; });
  });
}

function teacherClient() {
  var $ = function (id) { return document.getElementById(id); };
  var S = { users: [], results: [], open: true }, tt;
  function api(method, url, body) {
    return fetch(url, { method: method, headers: { 'Content-Type': 'application/json', 'X-MW': '1' }, body: method === 'GET' ? undefined : JSON.stringify(body || {}) })
      .then(function (r) {
        if (r.status === 401) { location.href = '/login'; throw new Error('انتهت الجلسة'); }
        return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || 'حدث خطأ'); return j; });
      });
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function fmt(d) { return d ? new Date(d).toLocaleString('ar-u-ca-gregory-nu-latn', { dateStyle: 'short', timeStyle: 'short' }) : '—'; }
  function pct(r) { return r.total ? Math.round(r.score / r.total * 100) : 0; }
  function toast(m, bad) {
    var t = $('toast'); t.textContent = m; t.className = 'toast' + (bad ? ' bad' : ''); t.hidden = false;
    clearTimeout(tt); tt = setTimeout(function () { t.hidden = true; }, 3500);
  }
  function err(e) { toast(e.message || 'حدث خطأ', true); }

  function load() { return api('GET', '/api/t/data').then(function (d) { S = d; render(); }).catch(err); }

  function render() {
    $('stat').className = 'pill ' + (S.open ? 'on' : 'off');
    $('stat').textContent = S.open ? 'الموقع يعمل' : 'الموقع متوقف';
    $('toggle').textContent = S.open ? 'إيقاف الموقع' : 'تشغيل الموقع';
    $('toggle').className = 'btn ' + (S.open ? 'bad' : 'ok');
    var took = S.users.filter(function (u) { return u.attempts > 0; }).length;
    var avg = S.results.length ? Math.round(S.results.reduce(function (a, r) { return a + pct(r); }, 0) / S.results.length) : 0;
    $('nU').textContent = S.users.length; $('nT').textContent = took;
    $('nA').textContent = S.results.length; $('nAvg').textContent = avg + '%';
    renderUsers(); renderResults();
  }

  function renderUsers() {
    var s = $('qs').value.trim().toLowerCase(), only = $('notTaken').checked;
    var rows = S.users.filter(function (u) {
      return (!s || (u.name + ' ' + u.username).toLowerCase().indexOf(s) >= 0) && (!only || !u.attempts);
    });
    $('ub').innerHTML = rows.length ? rows.map(function (u) {
      return '<tr><td>' + esc(u.name) + '</td><td dir="ltr">' + esc(u.username) + '</td><td>' + u.attempts + '</td><td>' +
        (u.best == null ? '—' : u.best) + '</td><td>' + fmt(u.last_at) + '</td><td><div class="acts">' +
        '<button class="sm" data-a="pw" data-id="' + u.id + '">كلمة مرور جديدة</button>' +
        '<button class="sm bad" data-a="du" data-id="' + u.id + '">حذف</button></div></td></tr>';
    }).join('') : '<tr><td colspan="6" class="empty">لا يوجد طلاب بعد. أضف طلابك من الأعلى.</td></tr>';
  }

  function renderResults() {
    var s = $('qr').value.trim().toLowerCase();
    var rows = S.results.filter(function (r) { return !s || (r.name + ' ' + r.username + ' ' + r.model).toLowerCase().indexOf(s) >= 0; });
    $('rb').innerHTML = rows.length ? rows.map(function (r) {
      var secs = (r.sections || []).map(function (x) { return '<li><span>' + esc(x.n) + '</span><b dir="ltr">' + esc(x.v) + '</b></li>'; }).join('');
      return '<tr><td>' + esc(r.name) + '</td><td>' + esc(r.model) + '</td><td dir="ltr">' + r.score + ' / ' + r.total +
        '</td><td>' + pct(r) + '%</td><td>' + fmt(r.created_at) + '</td><td><div class="acts">' +
        '<button class="sm" data-a="det" data-id="' + r.id + '">التفاصيل</button>' +
        '<button class="sm bad" data-a="dr" data-id="' + r.id + '">حذف</button></div></td></tr>' +
        '<tr class="det" id="d' + r.id + '" hidden><td colspan="6"><div class="meta">' + esc(r.grade) + ' · ' + esc(r.meta) +
        '</div><ul class="secl">' + secs + '</ul></td></tr>';
    }).join('') : '<tr><td colspan="6" class="empty">لا توجد نتائج بعد.</td></tr>';
  }

  function showCreds(list) {
    window.__creds = list;
    $('credBox').hidden = false;
    $('credBody').innerHTML = list.map(function (c) {
      return '<tr><td>' + esc(c.name) + '</td><td dir="ltr">' + esc(c.username) + '</td><td dir="ltr">' + esc(c.password) + '</td></tr>';
    }).join('');
    $('credBox').scrollIntoView({ behavior: 'smooth' });
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-a]'); if (!b) return;
    var a = b.dataset.a, id = b.dataset.id;
    if (a === 'det') { var t = $('d' + id); t.hidden = !t.hidden; }
    else if (a === 'dr') { if (confirm('حذف هذه النتيجة؟')) api('DELETE', '/api/t/results/' + id).then(load).catch(err); }
    else if (a === 'du') {
      var u = S.users.filter(function (x) { return String(x.id) === id; })[0];
      if (u && confirm('حذف الطالب «' + u.name + '» وجميع نتائجه؟')) api('DELETE', '/api/t/users/' + id).then(load).catch(err);
    } else if (a === 'pw') {
      var p = prompt('كلمة المرور الجديدة (اتركها فارغة لتوليد رقم عشوائي):');
      if (p === null) return;
      api('POST', '/api/t/users/' + id + '/password', { password: p }).then(function (j) { alert('كلمة المرور الجديدة: ' + j.password); }).catch(err);
    }
  });

  $('toggle').onclick = function () {
    var next = !S.open;
    if (!next && !confirm('إيقاف الموقع؟ لن يتمكن الطلاب من الاختبار حتى تعيد تشغيله.')) return;
    api('POST', '/api/t/site', { open: next }).then(load).catch(err);
  };
  $('refresh').onclick = load;
  $('bulk').onclick = function () {
    var names = $('names').value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
    if (!names.length) return toast('اكتب اسمًا واحدًا على الأقل', true);
    api('POST', '/api/t/users/bulk', { names: names }).then(function (j) { $('names').value = ''; showCreds(j.created); load(); }).catch(err);
  };
  $('addOne').onclick = function () {
    var c = { name: $('n1').value.trim(), username: $('u1').value.trim().toLowerCase(), password: $('p1').value };
    api('POST', '/api/t/users', c).then(function () { showCreds([c]); $('n1').value = ''; $('u1').value = ''; $('p1').value = ''; load(); }).catch(err);
  };
  $('copyCreds').onclick = function () {
    var t = (window.__creds || []).map(function (c) { return c.name + '\t' + c.username + '\t' + c.password; }).join('\n');
    navigator.clipboard.writeText(t).then(function () { toast('تم النسخ'); }, function () { toast('تعذّر النسخ', true); });
  };
  $('printCreds').onclick = function () { window.print(); };
  $('hideCreds').onclick = function () { $('credBox').hidden = true; window.__creds = []; };
  $('delAll').onclick = function () {
    if (confirm('حذف جميع النتائج لكل الطلاب؟ لا يمكن التراجع.')) api('DELETE', '/api/t/results').then(load).catch(err);
  };
  $('restore').onclick = function () { $('restoreFile').click(); };
  $('restoreFile').onchange = function () {
    var inp = this, f = inp.files[0]; if (!f) return;
    if (!confirm('الاسترجاع يستبدل جميع الطلاب والنتائج الحالية بمحتوى الملف. متابعة؟')) { inp.value = ''; return; }
    f.text().then(function (t) {
      var data; try { data = JSON.parse(t); } catch (e) { throw new Error('الملف غير صالح'); }
      return api('POST', '/api/t/restore', data);
    }).then(function () { toast('تم استرجاع النسخة الاحتياطية'); load(); }).catch(err);
    inp.value = '';
  };
  $('qs').oninput = renderUsers; $('notTaken').onchange = renderUsers; $('qr').oninput = renderResults;
  load();
}

/* ---------- الصفحات ---------- */
const FONTS = '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=El+Messiri:wght@500;700&family=Tajawal:wght@400;500;700;800&display=swap">';
const CSS = '<style>' +
  '[hidden]{display:none!important}*{box-sizing:border-box}' +
  ':root{--bg:#f3f5fa;--surface:#fff;--ink:#18233d;--muted:#5d6886;--line:#dde2ee;--accent:#2e4fa8;--accent-soft:#e6ecfb;--gold:#c98a12;--gold-soft:#fbf1dc;--ok:#1d8a55;--ok-soft:#e2f4ea;--bad:#c43c3c;--bad-soft:#fbe7e7;--display:"El Messiri","Tajawal",system-ui,sans-serif;--body:"Tajawal",system-ui,"Segoe UI",Tahoma,sans-serif}' +
  '@media (prefers-color-scheme:dark){:root{--bg:#0f1524;--surface:#18203a;--ink:#e8ecf7;--muted:#9aa5c4;--line:#2a3455;--accent:#8aa6ff;--accent-soft:#233063;--gold:#f0b545;--gold-soft:#3a2f17;--ok:#4fcb8a;--ok-soft:#163a2a;--bad:#ff7a7a;--bad-soft:#432023;color-scheme:dark}}' +
  'body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--body);font-size:16px;line-height:1.7;padding:0 16px 40px}' +
  '.wrap{max-width:1000px;margin:0 auto}h1,h2{font-family:var(--display);margin:0}h2{font-size:1.25rem;margin-bottom:12px}' +
  '.card{background:var(--surface);border:1px solid var(--line);border-radius:18px;padding:20px;margin-bottom:16px}' +
  '.btn{font:inherit;font-weight:700;border:0;border-radius:12px;padding:10px 18px;cursor:pointer;background:var(--accent);color:var(--surface);text-decoration:none;display:inline-block}' +
  '.btn.ghost{background:transparent;color:var(--accent);border:1.5px solid var(--line)}.btn.ok{background:var(--ok);color:#fff}.btn.bad{background:var(--bad);color:#fff}' +
  '.btn:focus-visible,.sm:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid var(--gold);outline-offset:2px}' +
  'input,textarea{width:100%;font:inherit;padding:10px 12px;border-radius:12px;border:1.5px solid var(--line);background:var(--bg);color:var(--ink)}' +
  'label{display:block;font-weight:700;margin-bottom:6px}.meta{color:var(--muted);font-size:.92rem}.err{color:var(--bad);min-height:1.5em;margin:8px 0 0}' +
  '</style>';
const HEAD = '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">';

const LOGIN_HTML = HEAD + '<title>تسجيل الدخول</title>' + FONTS + CSS +
  '<style>.box{max-width:400px;margin:12vh auto 0}.box h1{font-size:1.6rem;margin-bottom:4px}.fld{margin-top:14px}.box .btn{width:100%;margin-top:18px}</style></head><body><div class="wrap"><div class="box card">' +
  '<h1>اختبار القدرات العقلية</h1><p class="meta">مدرسة التويثير الابتدائية · سجّل دخولك للبدء</p>' +
  '<form id="f" autocomplete="off"><div class="fld"><label for="u">اسم المستخدم</label><input id="u" name="u" dir="ltr" autocapitalize="none" required></div>' +
  '<div class="fld"><label for="p">كلمة المرور</label><input id="p" name="p" type="password" dir="ltr" required></div>' +
  '<p class="err" id="err" role="alert"></p><button class="btn" type="submit">دخول</button></form></div></div>' +
  '<script>(' + loginClient.toString() + ')()</script></body></html>';

const CLOSED_HTML = HEAD + '<title>الاختبار متوقف</title>' + FONTS + CSS +
  '<style>.box{max-width:460px;margin:14vh auto 0;text-align:center}</style></head><body><div class="wrap"><div class="box card">' +
  '<h1>الاختبار متوقف حاليًا</h1><p class="meta">أوقف المعلم الاختبار مؤقتًا. حاول مرة أخرى حين يعيد تشغيله.</p>' +
  '<a class="btn ghost" href="/logout">تسجيل الخروج</a></div></div></body></html>';

const TEACHER_HTML = HEAD + '<title>لوحة المعلم</title>' + FONTS + CSS +
  '<style>' +
  'header.top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:18px 0;border-bottom:1px solid var(--line);margin-bottom:20px}' +
  'header.top h1{font-size:1.5rem}.pill{font-size:.88rem;font-weight:700;padding:4px 14px;border-radius:999px}' +
  '.pill.on{background:var(--ok-soft);color:var(--ok)}.pill.off{background:var(--bad-soft);color:var(--bad)}' +
  '.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}' +
  '.stats div{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:12px 14px}' +
  '.stats b{display:block;font-family:var(--display);font-size:1.7rem;color:var(--accent);font-variant-numeric:tabular-nums}.stats span{color:var(--muted);font-size:.9rem}' +
  '.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media (max-width:760px){.grid2{grid-template-columns:1fr}}.grid2 .card{margin:0}' +
  '.grid2+.card,.grid2{margin-bottom:16px}.fld{margin-bottom:10px}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}' +
  '.tw{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.95rem}' +
  'th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:start;white-space:nowrap}th{color:var(--muted);font-weight:700;background:var(--bg)}' +
  '.acts{display:flex;gap:6px}.sm{font:inherit;font-size:.85rem;font-weight:700;padding:4px 10px;border-radius:8px;border:1.5px solid var(--line);background:var(--surface);color:var(--accent);cursor:pointer}.sm.bad{color:var(--bad)}' +
  '.empty{text-align:center;color:var(--muted);padding:22px}.det td{background:var(--bg);white-space:normal}' +
  '.secl{list-style:none;margin:8px 0 0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:4px 18px}.secl li{display:flex;justify-content:space-between;gap:8px}' +
  '.tools{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}.tools input[type=search]{max-width:260px}.chk{display:flex;gap:6px;align-items:center;font-weight:500;margin:0}.chk input{width:auto}' +
  '.toast{position:fixed;left:16px;right:16px;bottom:16px;max-width:420px;margin:auto;background:var(--ink);color:var(--surface);padding:10px 16px;border-radius:12px;text-align:center;z-index:9;font-weight:700}.toast.bad{background:var(--bad);color:#fff}' +
  '@media print{.noprint{display:none!important}body{background:#fff;color:#000}.card{border:0}}' +
  '</style></head><body><div class="wrap">' +
  '<header class="top noprint"><div><h1>لوحة المعلم</h1><span class="meta">مدرسة التويثير الابتدائية · اختبار القدرات العقلية</span></div>' +
  '<div class="row"><span id="stat" class="pill on">…</span><button id="toggle" class="btn" type="button">…</button><button id="refresh" class="btn ghost" type="button">تحديث</button><a class="btn ghost" href="/logout">خروج</a></div></header>' +
  '<div class="stats noprint"><div><b id="nU">0</b><span>عدد الطلاب</span></div><div><b id="nT">0</b><span>اختبروا</span></div><div><b id="nA">0</b><span>عدد المحاولات</span></div><div><b id="nAvg">0%</b><span>متوسط الدرجات</span></div></div>' +
  '<section id="credBox" class="card" hidden><h2>بيانات الدخول الجديدة</h2><p class="meta">انسخها أو اطبعها الآن؛ كلمات المرور لا تظهر مرة أخرى بعد إغلاق هذا الصندوق (يمكنك توليد كلمة جديدة لأي طالب).</p>' +
  '<div class="tw"><table><thead><tr><th>الاسم</th><th>اسم المستخدم</th><th>كلمة المرور</th></tr></thead><tbody id="credBody"></tbody></table></div>' +
  '<div class="row noprint" style="margin-top:12px"><button id="copyCreds" class="btn" type="button">نسخ</button><button id="printCreds" class="btn ghost" type="button">طباعة</button><button id="hideCreds" class="btn ghost" type="button">إغلاق</button></div></section>' +
  '<div class="grid2 noprint"><section class="card"><h2>إضافة طلاب دفعة واحدة</h2><p class="meta">اكتب اسم كل طالب في سطر. يُنشأ لكل طالب اسم مستخدم وكلمة مرور تلقائيًا.</p>' +
  '<textarea id="names" rows="6" placeholder="محمد أحمد&#10;خالد سعد"></textarea><div class="row" style="margin-top:10px"><button id="bulk" class="btn" type="button">إنشاء الحسابات</button></div></section>' +
  '<section class="card"><h2>إضافة طالب بيانات مخصصة</h2><div class="fld"><label for="n1">الاسم</label><input id="n1"></div>' +
  '<div class="fld"><label for="u1">اسم المستخدم (بدون مسافات)</label><input id="u1" dir="ltr" autocapitalize="none"></div>' +
  '<div class="fld"><label for="p1">كلمة المرور (4 أحرف على الأقل)</label><input id="p1" dir="ltr"></div><button id="addOne" class="btn" type="button">إضافة الطالب</button></section></div>' +
  '<section class="card noprint"><h2>الطلاب</h2><div class="tools"><input id="qs" type="search" placeholder="بحث بالاسم"><label class="chk"><input id="notTaken" type="checkbox">من لم يختبر بعد</label></div>' +
  '<div class="tw"><table><thead><tr><th>الاسم</th><th>اسم المستخدم</th><th>المحاولات</th><th>أعلى درجة</th><th>آخر محاولة</th><th></th></tr></thead><tbody id="ub"></tbody></table></div></section>' +
  '<section class="card noprint"><h2>النتائج</h2><div class="tools"><input id="qr" type="search" placeholder="بحث بالاسم أو النموذج"><a class="btn ghost" href="/api/t/export.csv">تصدير إلى Excel</a><a class="btn ghost" href="/api/t/backup.json">نسخة احتياطية</a><button id="restore" class="btn ghost" type="button">استرجاع نسخة</button><input id="restoreFile" type="file" accept=".json,application/json" hidden><button id="delAll" class="btn ghost" type="button" style="color:var(--bad)">حذف كل النتائج</button></div>' +
  '<div class="tw"><table><thead><tr><th>الطالب</th><th>النموذج</th><th>الدرجة</th><th>النسبة</th><th>التاريخ</th><th></th></tr></thead><tbody id="rb"></tbody></table></div></section>' +
  '</div><div id="toast" class="toast" role="status" hidden></div><script>(' + teacherClient.toString() + ')()</script></body></html>';

const HOOK = '<script>(' + clientHook.toString() + ')()</script>';

/* ---------- التطبيق ---------- */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '5mb' }));
app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); res.set('X-Content-Type-Options', 'nosniff'); next(); });
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.get('X-MW') !== '1') return res.status(400).json({ error: 'طلب غير صالح' });
  next();
});
const teacherOnly = (req, res, next) => {
  const t = readToken(parseCookies(req).mw);
  if (t && t.r === 't') return next();
  res.status(401).json({ error: 'غير مصرّح' });
};
app.use('/api/t', teacherOnly);
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  console.error(e);
  if (!res.headersSent) res.status(500).json({ error: 'خطأ في الخادم' });
});
const validUser = u => /^\S{2,30}$/.test(u);

app.get('/healthz', (req, res) => res.send('ok'));

app.get('/login', wrap(async (req, res) => {
  const a = await auth(req);
  if (a) return res.redirect(a.role === 't' ? '/teacher' : '/');
  res.type('html').send(LOGIN_HTML);
}));
app.get('/logout', (req, res) => { res.clearCookie('mw', { path: '/' }); res.redirect('/login'); });

app.post('/api/login', wrap(async (req, res) => {
  const u = String((req.body || {}).username || '').trim().toLowerCase().slice(0, 60);
  const p = String((req.body || {}).password || '').slice(0, 200);
  const key = req.ip + '|' + u;
  if (locked(key)) return res.status(429).json({ error: 'محاولات كثيرة، انتظر 5 دقائق ثم حاول مرة أخرى' });
  if (u === TEACHER_USER) {
    if (safeEq(p, TEACHER_PASS)) {
      fails.delete(key); setSession(req, res, { r: 't' }, 8);
      return res.json({ to: '/teacher' });
    }
  } else {
    const user = D.users.find(x => x.username === u);
    if (user && await checkPw(p, user.pass_hash)) {
      fails.delete(key); setSession(req, res, { r: 's', id: user.id }, 12);
      return res.json({ to: '/' });
    }
  }
  addFail(key);
  res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
}));

app.get('/', wrap(async (req, res) => {
  const a = await auth(req);
  if (!a) return res.redirect('/login');
  if (a.role === 't') return res.redirect('/teacher');
  if (!isOpen()) return res.status(503).type('html').send(CLOSED_HTML);
  let html = await fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8');
  const j = v => JSON.stringify(v).replace(/</g, '\\u003c');
  const boot = '<script>var MW_USER=' + j(a.username) + ';var MW_NAME=' + j(a.name) +
    ';try{if(localStorage.getItem("__mwuser")!==MW_USER){localStorage.clear();localStorage.setItem("__mwuser",MW_USER)}}catch(e){}</script>';
  html = html.replace(/<head[^>]*>/i, m => m + boot);
  const i = html.lastIndexOf('</body>');
  html = i < 0 ? html + HOOK : html.slice(0, i) + HOOK + html.slice(i);
  res.type('html').send(html);
}));

app.post('/api/result', wrap(async (req, res) => {
  const a = await auth(req);
  if (!a || a.role !== 's') return res.status(401).json({ error: 'انتهت الجلسة، سجّل الدخول من جديد' });
  if (!isOpen()) return res.status(503).json({ error: 'الموقع متوقف حاليًا ولم تُحفظ النتيجة' });
  const b = req.body || {};
  const total = Math.max(0, Math.min(500, parseInt(b.total, 10) || 0));
  const score = Math.max(0, Math.min(total, parseInt(b.score, 10) || 0));
  const secs = (Array.isArray(b.sections) ? b.sections : []).slice(0, 20)
    .map(s => ({ n: String((s && s.n) || '').slice(0, 80), v: String((s && s.v) || '').slice(0, 20) }));
  D.results.push({
    id: D.nextResultId++, user_id: a.id, model: String(b.model || '').slice(0, 60), score, total,
    grade: String(b.grade || '').slice(0, 100), meta: String(b.meta || '').slice(0, 300), sections: secs,
    created_at: new Date().toISOString()
  });
  await save();
  res.json({ ok: true });
}));

/* ---------- لوحة المعلم ---------- */
app.get('/teacher', (req, res) => {
  const t = readToken(parseCookies(req).mw);
  if (!t || t.r !== 't') return res.redirect('/login');
  res.type('html').send(TEACHER_HTML);
});

app.get('/api/t/data', (req, res) => {
  const byUser = new Map();
  D.results.forEach(r => {
    const s = byUser.get(r.user_id) || { attempts: 0, best: null, last_at: null };
    s.attempts++;
    if (s.best === null || r.score > s.best) s.best = r.score;
    if (!s.last_at || r.created_at > s.last_at) s.last_at = r.created_at;
    byUser.set(r.user_id, s);
  });
  const users = D.users.map(u => {
    const s = byUser.get(u.id) || { attempts: 0, best: null, last_at: null };
    return { id: u.id, username: u.username, name: u.name, attempts: s.attempts, best: s.best, last_at: s.last_at };
  }).sort((a, b) => a.name.localeCompare(b.name, 'ar'));
  const results = D.results.slice().sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).slice(0, 3000).map(r => {
    const u = findUser(r.user_id) || {};
    return Object.assign({}, r, { name: u.name || '', username: u.username || '' });
  });
  res.json({ open: isOpen(), users, results });
});

app.post('/api/t/users', wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!name || !validUser(username) || password.length < 4) {
    return res.status(400).json({ error: 'تأكد من الاسم، واسم المستخدم (بدون مسافات)، وكلمة المرور (4 أحرف على الأقل)' });
  }
  if (username === TEACHER_USER) return res.status(400).json({ error: 'اسم المستخدم محجوز' });
  const hash = await hashPw(password);
  if (D.users.some(u => u.username === username)) return res.status(409).json({ error: 'اسم المستخدم مستخدم من قبل' });
  D.users.push({ id: D.nextUserId++, username, name, pass_hash: hash, created_at: new Date().toISOString() });
  await save();
  res.json({ ok: true });
}));

app.post('/api/t/users/bulk', wrap(async (req, res) => {
  const names = (Array.isArray(req.body.names) ? req.body.names : [])
    .map(s => String(s).trim().slice(0, 80)).filter(Boolean).slice(0, 100);
  if (!names.length) return res.status(400).json({ error: 'اكتب اسمًا واحدًا على الأقل' });
  const passwords = names.map(() => String(crypto.randomInt(10000, 100000)));
  const hashes = await Promise.all(passwords.map(hashPw));
  let n = D.users.reduce((m, u) => { const x = /^s(\d+)$/.exec(u.username); return x ? Math.max(m, parseInt(x[1], 10)) : m; }, 0);
  const created = names.map((name, i) => {
    n++;
    const username = 's' + String(n).padStart(2, '0');
    D.users.push({ id: D.nextUserId++, username, name, pass_hash: hashes[i], created_at: new Date().toISOString() });
    return { name, username, password: passwords[i] };
  });
  await save();
  res.json({ created });
}));

app.post('/api/t/users/:id/password', wrap(async (req, res) => {
  let password = String(req.body.password || '');
  if (!password) password = String(crypto.randomInt(10000, 100000));
  if (password.length < 4) return res.status(400).json({ error: 'كلمة المرور قصيرة (4 أحرف على الأقل)' });
  const hash = await hashPw(password);
  const u = findUser(parseInt(req.params.id, 10));
  if (!u) return res.status(404).json({ error: 'الطالب غير موجود' });
  u.pass_hash = hash;
  await save();
  res.json({ password });
}));

app.delete('/api/t/users/:id', wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  D.users = D.users.filter(u => u.id !== id);
  D.results = D.results.filter(r => r.user_id !== id);
  await save();
  res.json({ ok: true });
}));

app.delete('/api/t/results/:id', wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  D.results = D.results.filter(r => r.id !== id);
  await save();
  res.json({ ok: true });
}));

app.delete('/api/t/results', wrap(async (req, res) => {
  D.results = [];
  await save();
  res.json({ ok: true });
}));

app.post('/api/t/site', wrap(async (req, res) => {
  D.open = !!req.body.open;
  await save();
  res.json({ open: D.open });
}));

app.get('/api/t/export.csv', (req, res) => {
  const esc = v => {
    let s = String(v == null ? '' : v);
    if (/^[=+\-@]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  };
  const rows = D.results.map(r => ({ r, u: findUser(r.user_id) || {} }))
    .sort((a, b) => String(a.u.name).localeCompare(String(b.u.name), 'ar') || (a.r.created_at < b.r.created_at ? -1 : 1));
  const head = ['الاسم', 'اسم المستخدم', 'النموذج', 'الدرجة', 'من', 'التقدير', 'التفاصيل', 'التاريخ'];
  const lines = [head.map(esc).join(',')].concat(rows.map(x =>
    [x.u.name, x.u.username, x.r.model, x.r.score, x.r.total, x.r.grade, x.r.meta, x.r.created_at].map(esc).join(',')));
  res.set('Content-Type', 'text/csv; charset=utf-8');
  res.set('Content-Disposition', 'attachment; filename="results.csv"');
  res.send('\uFEFF' + lines.join('\r\n'));
});

app.get('/api/t/backup.json', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.set('Content-Disposition', 'attachment; filename="mawhiba-backup-' + new Date().toISOString().slice(0, 10) + '.json"');
  res.send(JSON.stringify({ users: D.users, results: D.results }));
});

app.post('/api/t/restore', wrap(async (req, res) => {
  const b = req.body || {};
  if (!Array.isArray(b.users) || !Array.isArray(b.results)) return res.status(400).json({ error: 'ملف النسخة الاحتياطية غير صالح' });
  const seenId = new Set(), seenName = new Set(), users = [];
  b.users.forEach(u => {
    if (!u || !Number.isInteger(u.id) || seenId.has(u.id)) return;
    const username = String(u.username || '').toLowerCase();
    if (!validUser(username) || seenName.has(username) || !/^[0-9a-f]+:[0-9a-f]+$/.test(String(u.pass_hash))) return;
    seenId.add(u.id); seenName.add(username);
    users.push({ id: u.id, username, name: String(u.name || '').slice(0, 80), pass_hash: String(u.pass_hash), created_at: String(u.created_at || new Date().toISOString()) });
  });
  const seenR = new Set(), results = [];
  b.results.forEach(r => {
    if (!r || !Number.isInteger(r.id) || seenR.has(r.id) || !seenId.has(r.user_id)) return;
    seenR.add(r.id);
    results.push({
      id: r.id, user_id: r.user_id, model: String(r.model || '').slice(0, 60),
      score: parseInt(r.score, 10) || 0, total: parseInt(r.total, 10) || 0,
      grade: String(r.grade || '').slice(0, 100), meta: String(r.meta || '').slice(0, 300),
      sections: (Array.isArray(r.sections) ? r.sections : []).slice(0, 20).map(s => ({ n: String((s && s.n) || '').slice(0, 80), v: String((s && s.v) || '').slice(0, 20) })),
      created_at: String(r.created_at || new Date().toISOString())
    });
  });
  D.users = users; D.results = results;
  D.nextUserId = users.reduce((m, u) => Math.max(m, u.id), 0) + 1;
  D.nextResultId = results.reduce((m, r) => Math.max(m, r.id), 0) + 1;
  await save();
  res.json({ ok: true, users: users.length, results: results.length });
}));

loadData();
app.listen(PORT, () => console.log('Server running on port ' + PORT + ', data file: ' + DATA_FILE));

'use strict';
// «Деканат» — концепт кабинета студента. Данные каждого студента зашифрованы ключом из его пароля
// (PBKDF2-SHA256 → AES-GCM-256). Пароли нигде не хранятся: без верного пароля данные не расшифровать.
const $app = document.getElementById('app');
const te = new TextEncoder(), td = new TextDecoder();
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64 = (u) => btoa(String.fromCharCode(...new Uint8Array(u)));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sha = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s)))].map((b) => b.toString(16).padStart(2, '0')).join('');

const S = { data: null, key: null, uid: null, apps: [] };
const DOW = ['вс', 'пн', 'вт', 'ср', 'чт', 'пт', 'сб'];
const DOWF = ['воскресенье', 'понедельник', 'вторник', 'среда', 'четверг', 'пятница', 'суббота'];
const MON = ['января', 'февраля', 'марта', 'апреля', 'мая', 'июня', 'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря'];
const fmtD = (d) => `${d.getDate()} ${MON[d.getMonth()]}`;
const STATUS = { new: ['Принята', 'new'], work: ['В работе', 'work'], ready: ['Готова', 'ready'] };
const APP_TYPES = [
  ['Справка об обучении', 'Подтверждает, что вы студент. Обычно — 1 рабочий день.'],
  ['Справка для военкомата', 'Форма для военного комиссариата. До 3 рабочих дней.'],
  ['Справка о стипендии', 'Размер выплат за выбранный период.'],
  ['Заявление на академический отпуск', 'Рассматривает деканат, нужны подтверждающие документы.'],
  ['Заявление на тему курсовой', 'Согласуйте тему с научным руководителем заранее.'],
  ['Заявка на летнюю школу', 'Мотивационное письмо прикладывается позже.'],
];

// ---------- crypto ----------
async function deriveKey(pass, salt, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function seal(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, S.key, te.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function unseal(box, key = S.key) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct));
  return JSON.parse(td.decode(pt));
}
const store = {
  get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};

// ---------- session ----------
let vaultP = null;
const vault = () => (vaultP ||= fetch('data/vault.json', { cache: 'no-cache' }).then((r) => r.json()));
async function login(loginName, pass) {
  const v = await vault();
  const uid = await sha('dd:' + loginName.trim().toLowerCase());
  const rec = v.users[uid];
  // одинаковая работа для существующего и несуществующего логина — ответ не выдаёт, есть ли такой пользователь
  const salt = rec ? unb64(rec.salt) : crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(pass, salt, v.iter);
  if (!rec) throw new Error('bad');
  try { S.data = await unseal(rec, key); } catch { throw new Error('bad'); }
  S.key = key; S.uid = uid;
  try { sessionStorage.setItem('dd.s', JSON.stringify({ uid, k: await crypto.subtle.exportKey('jwk', key) })); } catch {}
  await loadApps();
}
async function restore() {
  let s; try { s = JSON.parse(sessionStorage.getItem('dd.s')); } catch {}
  if (!s) return false;
  try {
    const v = await vault(); const rec = v.users[s.uid]; if (!rec) return false;
    const key = await crypto.subtle.importKey('jwk', s.k, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    S.data = await unseal(rec, key); S.key = key; S.uid = s.uid; await loadApps(); return true;
  } catch { return false; }
}
function logout() { try { sessionStorage.removeItem('dd.s'); } catch {} S.data = S.key = S.uid = null; S.apps = []; location.hash = '#/'; render(); }
async function loadApps() {
  const box = store.get('dd.apps.' + S.uid);
  let mine = [];
  if (box) { try { mine = await unseal(box); } catch { mine = []; } }
  S.apps = [...mine, ...S.data.apps].sort((a, b) => b.created.localeCompare(a.created));
}
async function saveApp(a) {
  const box = store.get('dd.apps.' + S.uid);
  let mine = []; if (box) { try { mine = await unseal(box); } catch {} }
  mine.push(a); store.set('dd.apps.' + S.uid, await seal(mine)); await loadApps();
}
// Демо-движок деканата: заявка проходит этапы по времени (в реальной системе статус меняет сотрудник).
function status(a) {
  if (a.fixed) return a.fixed;
  const sec = (Date.now() - new Date(a.created).getTime()) / 1000;
  return sec < 45 ? 'new' : sec < 150 ? 'work' : 'ready';
}

// ---------- helpers ----------
const mark = (p) => p >= 86 ? ['отлично', 'g'] : p >= 70 ? ['хорошо', 'g'] : p >= 56 ? ['удовл.', 'a'] : ['неуд.', 'r'];
const seen = () => store.get('dd.seen.' + S.uid) || [];
const unreadCount = () => S.data.notices.filter((n) => !seen().includes(n[2])).length;
const toMin = (t) => { const [h, m] = t.split(':').map(Number); return h * 60 + m; };
const daysTo = (iso) => Math.ceil((new Date(iso + 'T00:00:00') - new Date(new Date().toDateString())) / 864e5);
const plural = (n, a, b, c) => { const m10 = n % 10, m100 = n % 100; return m10 === 1 && m100 !== 11 ? a : m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20) ? b : c; };
function lessonHTML(l, live) {
  const [s, e, title, kind, room, teacher, ch = {}] = l;
  const flags = [ch.cancelled && `<span class="flag r">${esc(ch.cancelled)}</span>`, ch.moved && `<span class="flag a">${esc(ch.moved)}</span>`, ch.room && `<span class="flag a">${esc(ch.room)}</span>`].filter(Boolean).join(' ');
  return `<div class="cls ${ch.cancelled ? 'off' : ''} ${live ? 'now' : ''}"><div class="t">${s}<small>${e}</small></div>
    <div><h3>${esc(title)}</h3><div class="meta">${esc(kind)}, ауд. ${esc(room)}, ${esc(teacher)}</div>${live ? '<span class="flag r">Идёт сейчас</span> ' : ''}${flags}</div></div>`;
}
const ICONS = {
  today: '<path d="M3 10h18M7 3v4M17 3v4M4 6h16v15H4z"/>',
  schedule: '<path d="M12 7v5l3 2"/><circle cx="12" cy="12" r="9"/>',
  grades: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  apps: '<path d="M7 3h8l4 4v14H7zM15 3v4h4M10 12h6M10 16h6"/>',
  profile: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/>',
};
const SEAL = `<svg class="seal" viewBox="0 0 40 40" aria-hidden="true"><circle cx="20" cy="20" r="18" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="20" cy="20" r="14" fill="none" stroke="currentColor" stroke-width=".8" stroke-dasharray="2 2"/><text x="20" y="26" text-anchor="middle" font-family="Prata,serif" font-size="18" fill="currentColor">Д</text></svg>`;

function shell(route, body) {
  const now = new Date(); const u = unreadCount();
  const tab = (r, label) => `<a href="#/${r}" ${route === r ? 'aria-current="page"' : ''}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ICONS[r]}</svg>${label}</a>`;
  return `<div class="wrap"><header class="mast"><a class="brand" href="#/today">${SEAL}<span><b>Деканат</b><small>кабинет студента</small></span></a>
    <a class="iconbtn" href="#/notices" aria-label="Уведомления, непрочитанных: ${u}"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M6 8a6 6 0 1 1 12 0c0 7 3 8 3 8H3s3-1 3-8M10 20a2 2 0 0 0 4 0"/></svg>${u ? `<span class="dot">${u}</span>` : ''}</a></header>
    <div class="dateline"><span>${DOWF[now.getDay()]}, ${fmtD(now)}</span><span>${esc(S.data.profile.group)}</span></div>
    <main>${body}</main></div>
    <nav class="tabs" aria-label="Разделы">${tab('today', 'Сегодня')}${tab('schedule', 'Расписание')}${tab('grades', 'Учёба')}${tab('apps', 'Заявки')}${tab('profile', 'Профиль')}</nav>`;
}

const TR={а:'A',б:'B',в:'V',г:'G',д:'D',е:'E',ё:'E',ж:'ZH',з:'Z',и:'I',й:'I',к:'K',л:'L',м:'M',н:'N',о:'O',п:'P',р:'R',с:'S',т:'T',у:'U',ф:'F',х:'KH',ц:'TS',ч:'CH',ш:'SH',щ:'SHCH',ъ:'',ы:'Y',ь:'',э:'E',ю:'IU',я:'IA'};
const lat=(s)=>[...String(s).toLowerCase()].map((c)=>TR[c]??(/[a-z0-9]/.test(c)?c.toUpperCase():'<')).join('');
function mrz(p){const [f,n]=p.name.split(' ');return esc((`STUD<RUS<${lat(f)}<<${lat(n)}<<${lat(p.group)}<${lat(p.record)}`+'<'.repeat(44)).slice(0,44)).replace(/</g,'&lt;');}

// ---------- views ----------
function vToday() {
  const d = S.data, now = new Date(), dow = now.getDay(), nm = now.getHours() * 60 + now.getMinutes();
  const today = (d.schedule[dow] || []);
  const active = today.filter((l) => !(l[6] || {}).cancelled);
  const next = active.find((l) => toMin(l[1]) > nm);
  const live = next && toMin(next[0]) <= nm;
  let headline, sub;
  if (!today.length || !active.length) {
    const tomorrow = d.schedule[(dow + 1) % 7] || [];
    headline = `${d.profile.short}, сегодня пар нет.`;
    sub = tomorrow.length ? `Завтра ${tomorrow.length} ${plural(tomorrow.length, 'пара', 'пары', 'пар')}, первая — в ${tomorrow[0][0]}, ${tomorrow[0][2]}.` : 'Завтра тоже свободно — хороший момент закрыть дедлайны.';
  } else if (!next) {
    headline = `${d.profile.short}, на сегодня всё.`; sub = `Было ${active.length} ${plural(active.length, 'занятие', 'занятия', 'занятий')}. Отдыхайте.`;
  } else {
    headline = live ? `Сейчас идёт ${next[2]}.` : `${d.profile.short}, следующая пара в ${next[0]}.`;
    sub = `${next[2]} · ауд. ${next[4]}. ${active.length} ${plural(active.length, 'занятие', 'занятия', 'занятий')} сегодня.`;
  }
  const changes = Object.entries(d.schedule).flatMap(([day, ls]) => ls.filter((l) => l[6]).map((l) => ({ day: +day, l })));
  const deadlines = d.notices.filter((n) => n[1] === 'deadline');
  const openApps = S.apps.slice(0, 2);
  const avg = Math.round(d.grades.reduce((s, g) => s + g.points, 0) / d.grades.length);
  const risk = d.grades.filter((g) => g.points < 60);
  return shell('today', `
    <section class="pass"><div class="who"><span>${esc(d.profile.name)}</span><span>${esc(d.profile.group)}</span></div>
      <div class="who" style="margin-top:2px;opacity:.65"><span>${DOWF[now.getDay()]}, ${fmtD(now)}</span><span>${d.profile.course} курс</span></div>
      <h1>${esc(headline)}</h1><p>${esc(sub)}</p>
      <div class="mrz">${mrz(d.profile)}</div></section>
    <section class="sec"><h2>Сегодня <a href="#/schedule">Вся неделя</a></h2><div class="card">${today.length ? today.map((l) => lessonHTML(l, l === next && live)).join('') : '<div class="empty">Свободный день</div>'}</div></section>
    ${changes.length ? `<section class="sec"><h2>Изменения на неделе</h2><div class="card">${changes.map((c) => `<div class="notice"><span class="ic change">↻</span><div><h3>${esc(c.l[2])}</h3><p>${DOWF[c.day]}, ${c.l[0]} — ${esc(Object.values(c.l[6])[0])}</p></div></div>`).join('')}</div></section>` : ''}
    <div class="grid2 sec">
      <a class="tile" href="#/grades"><small>Средний балл семестра</small><div class="big">${avg}</div><div class="hint">${risk.length ? `⚠ ${esc(risk[0].subject)}: ${risk[0].points} — есть риск` : 'Все дисциплины выше порога'}</div></a>
      <a class="tile" href="#/apps"><small>Мои заявки</small>${openApps.length ? openApps.map((a) => `<div style="display:flex;justify-content:space-between;gap:8px;margin-top:8px"><span>${esc(a.type)}</span><span class="stamp ${STATUS[status(a)][1]}">${STATUS[status(a)][0]}</span></div>`).join('') : '<div class="hint">Заявок пока нет</div>'}</a>
    </div>
    ${deadlines.length ? `<section class="sec"><h2>Дедлайны</h2><div class="card">${deadlines.map((n) => `<div class="notice"><span class="ic deadline">!</span><div><h3>${esc(n[2])}</h3><p>${esc(n[3])}</p></div></div>`).join('')}</div></section>` : ''}
  `);
}

let selDay = null;
function vSchedule() {
  const d = S.data, now = new Date();
  const monday = new Date(now); monday.setDate(now.getDate() - ((now.getDay() + 6) % 7));
  if (selDay == null) selDay = now.getDay() === 0 ? 1 : now.getDay();
  const btns = [1, 2, 3, 4, 5, 6].map((i) => {
    const dt = new Date(monday); dt.setDate(monday.getDate() + i - 1);
    const hasCh = (d.schedule[i] || []).some((l) => l[6]);
    return `<button data-day="${i}" aria-pressed="${i === selDay}"><small>${DOW[i]}</small><b>${dt.getDate()}</b>${hasCh ? '<span class="pip" title="Есть изменения"></span>' : ''}</button>`;
  }).join('');
  const ls = d.schedule[selDay] || [];
  return shell('schedule', `<section class="lead"><h1>Расписание</h1><p>Неделя ${fmtD(monday)} — изменения отмечены красной точкой.</p></section>
    <div class="days" role="group" aria-label="День недели">${btns}</div>
    <div class="card">${ls.length ? ls.map((l) => lessonHTML(l)).join('') : '<div class="empty">В этот день занятий нет</div>'}</div>`);
}

function vGrades() {
  const d = S.data;
  const avg = Math.round(d.grades.reduce((s, g) => s + g.points, 0) / d.grades.length);
  const [mk] = mark(avg);
  const scholarship = d.grades.every((g) => g.points >= 70);
  const rows = d.grades.map((g) => {
    const [m, c] = mark(g.points); const need = g.points < 70 ? 70 - g.points : g.points < 86 ? 86 - g.points : 0;
    return `<div class="subj"><div class="row"><h3>${esc(g.subject)}</h3><span class="pts">${g.points}</span></div>
      <div class="bar ${g.points < 60 ? 'low' : ''}"><i style="width:${g.points}%"></i></div>
      <div class="ticks"><span><span class="flag ${c}" style="margin:0">${m}</span> ${esc(g.kind)}</span><span>${need ? `до «${g.points < 70 ? 'хорошо' : 'отлично'}» ${need} ${plural(need, 'балл', 'балла', 'баллов')}` : 'максимальная оценка'}</span></div>
      <details><summary>Из чего сложилось</summary><table>${g.items.map((i) => `<tr><td>${esc(i[0])}</td><td>${i[1]} / ${i[2]}</td></tr>`).join('')}</table></details></div>`;
  }).join('');
  return shell('grades', `<section class="lead"><h1>Как у меня дела</h1><p>Средний балл ${avg} из 100 — это «${mk}». ${scholarship ? 'Вы проходите на стипендию.' : 'Для стипендии нужно «хорошо» по всем дисциплинам.'}</p></section>
    <section class="sec"><h2>Текущий семестр</h2><div class="card">${rows}</div></section>
    <section class="sec"><h2>Сессия</h2><div class="card">${d.session.map((s) => { const n = daysTo(s[0]); const dt = new Date(s[0] + 'T00:00:00'); return `<div class="notice"><span class="ic">✎</span><div><h3>${esc(s[1])}</h3><p>${fmtD(dt)}, ${esc(s[2])}, ауд. ${esc(s[3])}</p><small>через ${n} ${plural(n, 'день', 'дня', 'дней')}</small></div></div>`; }).join('')}</div></section>`);
}

function vApps() {
  return shell('apps', `<section class="lead"><h1>Заявки и справки</h1><p>Закажите справку или подайте заявление — без очереди в деканат.</p></section>
    <a class="btn w" href="#/apps/new">+ Новая заявка</a>
    <section class="sec"><h2>История</h2><div class="card">${S.apps.length ? S.apps.map((a) => { const [l, c] = STATUS[status(a)]; return `<a class="app" href="#/apps/${encodeURIComponent(a.id)}"><div><h3>${esc(a.type)}</h3><small>№ ${esc(a.id)}, ${fmtD(new Date(a.created))}</small></div><span class="stamp ${c}">${l}</span></a>`; }).join('') : '<div class="empty">Здесь появятся ваши заявки</div>'}</div></section>`);
}

function vNewApp() {
  return shell('apps', `<a class="back" href="#/apps">← Заявки</a><section class="lead"><h1>Новая заявка</h1></section>
    <form id="appf" class="card pad" novalidate>
      <label class="f">Что нужно<select name="type" required>${APP_TYPES.map((t) => `<option>${esc(t[0])}</option>`).join('')}</select></label>
      <div class="hint" id="thint">${esc(APP_TYPES[0][1])}</div>
      <label class="f">Куда предоставить<input name="target" maxlength="120" placeholder="Например: по месту работы родителей"></label>
      <div class="f" style="margin-top:14px"><span style="font-size:13px;color:var(--ink2);font-weight:500">Формат</span><div class="chips">
        <label><input type="radio" name="format" value="Электронная с подписью" checked>Электронная с подписью</label>
        <label><input type="radio" name="format" value="Бумажная, забрать в деканате">Бумажная</label></div></div>
      <label class="f">Комментарий для деканата<textarea name="note" rows="3" maxlength="500"></textarea></label>
      <div class="err" id="ferr"></div>
      <button class="btn w" type="submit">Отправить в деканат</button>
    </form>`);
}

function vAppDetail(id) {
  const a = S.apps.find((x) => x.id === id);
  if (!a) return shell('apps', `<a class="back" href="#/apps">← Заявки</a><div class="empty" style="padding-top:60px"><h2>Заявка не найдена</h2><p>Её нет среди ваших заявок. Чужие заявки недоступны.</p></div>`);
  const st = status(a); const [l, c] = STATUS[st];
  const steps = [['new', 'Заявка принята', 'Номер присвоен, деканат получил уведомление'], ['work', 'В работе', 'Специалист готовит документ'], ['ready', 'Готово', a.format?.startsWith('Бумажная') ? 'Заберите в деканате, окно 3, с паспортом' : 'Документ с электронной подписью — в профиле и на почте']];
  const order = ['new', 'work', 'ready'];
  return shell('apps', `<a class="back" href="#/apps">← Заявки</a>
    <section class="lead"><small style="color:var(--muted)">№ ${esc(a.id)} от ${fmtD(new Date(a.created))}</small><h1>${esc(a.type)}</h1><span class="stamp huge ${c}">${l}</span></section>
    <div class="card pad"><dl class="kv"><dt>Куда</dt><dd>${esc(a.target || '—')}</dd><dt>Формат</dt><dd>${esc(a.format || 'Электронная с подписью')}</dd>${a.note ? `<dt>Комментарий</dt><dd>${esc(a.note)}</dd>` : ''}</dl>
    <ol class="tl">${steps.map((s) => `<li class="${order.indexOf(s[0]) <= order.indexOf(st) ? 'done' : ''}"><b>${s[1]}</b><small>${s[2]}</small></li>`).join('')}</ol></div>
    ${!a.fixed && st !== 'ready' ? '<p class="hint">Демо-режим: заявка сама проходит этапы за пару минут — в реальной системе статус меняет сотрудник деканата.</p>' : ''}`);
}

function vNotices() {
  const s = seen();
  const html = shell('notices', `<section class="lead"><h1>Уведомления</h1><p>Новости деканата, дедлайны и изменения расписания.</p></section>
    <div class="card">${S.data.notices.map((n) => `<div class="notice ${s.includes(n[2]) ? '' : 'unread'}"><span class="ic ${n[1]}">${n[1] === 'change' ? '↻' : n[1] === 'deadline' ? '!' : '✉'}</span><div><h3>${esc(n[2])}</h3><p>${esc(n[3])}</p><small>${fmtD(new Date(n[0] + 'T12:00:00'))}</small></div></div>`).join('')}</div>`);
  store.set('dd.seen.' + S.uid, S.data.notices.map((n) => n[2]));
  return html;
}

function vProfile() {
  const p = S.data.profile;
  return shell('profile', `<section class="lead"><h1>${esc(p.name)}</h1><p>${esc(p.program)}, ${p.course} курс</p></section>
    <div class="card pad"><dl class="kv"><dt>Факультет</dt><dd>${esc(p.faculty)}</dd><dt>Направление</dt><dd>${esc(p.program)}</dd><dt>Курс</dt><dd>${p.course}</dd><dt>Группа</dt><dd>${esc(p.group)}</dd><dt>Зачётная книжка</dt><dd>${esc(p.record)}</dd><dt>Почта</dt><dd>${esc(p.email)}</dd><dt>Куратор</dt><dd>${esc(p.advisor)}</dd></dl></div>
    <section class="sec"><h2>Безопасность</h2><div class="card pad"><p style="margin:0">Ваши данные зашифрованы ключом, который получается из вашего пароля. Пароль нигде не хранится, а без него данные не прочитать — даже зная адрес.</p></div></section>
    <div class="sec" style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn ghost" id="theme">Сменить тему</button><button class="btn" id="out">Выйти</button></div>`);
}

function vLogin() {
  return `<div class="login"><div class="box"><section class="pass"><div class="who"><span>Студенческий кабинет</span><span>концепт</span></div>
    <h1>Деканат, который на вашей стороне</h1><p>Расписание, оценки, справки и новости деканата в одном месте.</p>
    <div class="mrz">DEKANAT&lt;&lt;STUDENT&lt;&lt;ACCESS&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;</div></section><form id="lf" novalidate>
    <label class="f">Логин<input name="l" autocomplete="username" autocapitalize="none" required></label>
    <label class="f">Пароль<input name="p" type="password" autocomplete="current-password" required></label>
    <div class="err" id="lerr" role="alert"></div>
    <button class="btn w" type="submit" id="lbtn">Войти</button>
    <div class="demo">Тестовые аккаунты для жюри: <button type="button" data-l="vetrova" data-p="Depesha-2026">vetrova</button> · <button type="button" data-l="kravets" data-p="Rotunda-2026">kravets</button><br>Концепт для конкурса. Все люди и данные вымышлены.</div>
  </form></div></div>`;
}

// ---------- router ----------
function render() {
  const h = location.hash.replace(/^#\/?/, '');
  if (!S.data) { $app.innerHTML = vLogin(); bindLogin(); return; }
  const [r, sub] = h.split('/');
  const v = { today: vToday, schedule: vSchedule, grades: vGrades, apps: sub === 'new' ? vNewApp : sub ? () => vAppDetail(decodeURIComponent(sub)) : vApps, notices: vNotices, profile: vProfile }[r] || vToday;
  $app.innerHTML = v(); bind(r, sub); window.scrollTo(0, 0);
}
function toast(t) { const el = document.createElement('div'); el.className = 'toast'; el.textContent = t; document.body.append(el); setTimeout(() => el.remove(), 2600); }
function bindLogin() {
  const f = document.getElementById('lf');
  f.querySelectorAll('[data-l]').forEach((b) => b.onclick = () => { f.l.value = b.dataset.l; f.p.value = b.dataset.p; });
  f.onsubmit = async (e) => {
    e.preventDefault(); const err = document.getElementById('lerr'), btn = document.getElementById('lbtn');
    if (!f.l.value.trim() || !f.p.value) { err.textContent = 'Введите логин и пароль'; return; }
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Проверяем…'; err.textContent = '';
    try { await login(f.l.value, f.p.value); location.hash = '#/today'; render(); }
    catch { err.textContent = 'Неверный логин или пароль'; btn.disabled = false; btn.textContent = 'Войти'; }
  };
}
function bind(r, sub) {
  if (r === 'schedule' || (!r)) document.querySelectorAll('[data-day]').forEach((b) => b.onclick = () => { selDay = +b.dataset.day; render(); });
  if (r === 'profile') {
    document.getElementById('out').onclick = logout;
    document.getElementById('theme').onclick = () => { const dark = matchMedia('(prefers-color-scheme: dark)').matches; const cur = document.documentElement.dataset.theme || (dark ? 'dark' : 'light'); const nx = cur === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = nx; store.set('dd.theme', nx); };
  }
  if (r === 'apps' && sub === 'new') {
    const f = document.getElementById('appf');
    f.type.onchange = () => { document.getElementById('thint').textContent = APP_TYPES.find((t) => t[0] === f.type.value)[1]; };
    f.onsubmit = async (e) => {
      e.preventDefault(); const btn = f.querySelector('button[type=submit]'); btn.disabled = true;
      const now = new Date(); const pad = (n) => String(n).padStart(2, '0');
      const a = { id: `Z-${pad(now.getDate())}${pad(now.getMonth() + 1)}-${String(Math.floor(Math.random() * 900) + 100)}`, type: f.type.value, target: f.target.value.trim(), format: f.format.value, note: f.note.value.trim(), created: now.toISOString() };
      try { await saveApp(a); toast('Заявка отправлена в деканат'); location.hash = '#/apps/' + encodeURIComponent(a.id); }
      catch { document.getElementById('ferr').textContent = 'Не удалось сохранить заявку. Попробуйте ещё раз.'; btn.disabled = false; }
    };
  }
}
(() => { const t = store.get('dd.theme'); if (t) document.documentElement.dataset.theme = t; })();
window.addEventListener('hashchange', render);
setInterval(() => { if (S.data && /^#\/(apps|today)/.test(location.hash) && !document.querySelector('form')) render(); }, 15000);
restore().then(render);

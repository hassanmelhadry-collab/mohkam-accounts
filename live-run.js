import { scenario } from './scenario.js';
const C = window.ACC_CLOUD || { url: 'https://mltyzkaxfdkbqcfxbrkv.supabase.co', key: 'sb_publishable_7VlBCqOaVLHgmyD4qh2TVw_K0YyZGoJ' };
const CODE = window.__code || 'demo', PW = 'Demo@Mohkam2026';
const S = window.__demo = { log: [], done: false, err: null };
const H = (tok) => ({ apikey: C.key, 'Content-Type': 'application/json', Authorization: 'Bearer ' + (tok || C.key) });
const raw = async (fn, p, tok) => { const r = await fetch(C.url + '/rest/v1/rpc/' + fn, { method: 'POST', headers: H(tok), body: JSON.stringify({ p: p || {} }) }); const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; } if (!r.ok) throw new Error((j && j.message) || t); return j; };
const toks = {}; let cur = Promise.resolve(); let tok = null;
const login = async (u) => { if (toks[u]) return toks[u]; const email = await raw('login_email', { code: CODE, username: u }); const r = await fetch(C.url + '/auth/v1/token?grant_type=password', { method: 'POST', headers: H(), body: JSON.stringify({ email, password: PW }) }); const j = await r.json(); if (!j.access_token) throw new Error('login ' + u + ': ' + JSON.stringify(j)); return (toks[u] = j.access_token); };
const as = (u) => { cur = cur.then(async () => { tok = await login(u); }); return cur; };
const rpc = async (fn, p) => { await cur; return raw(fn, p, tok); };
const users = ['acct:محاسب عام:acct', 'chief:رئيس الحسابات:chief', 'gm:المدير العام:gm', 'ar:محاسب عملاء:ar', 'ap:محاسب موردين:ap', 'cashier:أمين الصندوق:cashier', 'auditor:المراجع:auditor', 'emp:موظف تجريبي:employee'].map(s => { const [username, display, role] = s.split(':'); return { username, display, name: display, role, password: PW }; });
(async () => {
  try {
    S.log.push('register: ' + JSON.stringify(await raw('register_company', { code: CODE, name: 'مجموعة الشرق (تجريبية)', username: 'owner', display: 'المالك', password: PW, template: 'general' })).slice(0, 120));
    await as('owner');
    await scenario({ rpc, as, log: (...a) => S.log.push(a.join(' ')), y: new Date().getFullYear(), close: false, users });
    S.done = true;
  } catch (e) { S.err = String(e.message || e); S.done = true; }
})();

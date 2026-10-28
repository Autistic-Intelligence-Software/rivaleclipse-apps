// Perpetual Helper — paywall gate, account pages, and API proxy for
// the /Market-Tracker/ subtree (Shane's order 2026-10-28).
//
// The tracker is a paid product now: $9.99/mo, a $0.99 1-week paid
// trial, a 1-hour free trial on sign-up, and single-use promo codes
// (1-week / 1-month / lifetime). Accounts live in a STANDALONE system
// on the auth service (https://auth.rivaleclipse.dev/api/perp-acct/*)
// — completely separate from the Rival Eclipse hub/bot accounts.
//
// How it works:
//  - The browser never sees the account JWT. The /acct/* API routes
//    below proxy to the auth service; on login/register the returned
//    token is stored in an HttpOnly cookie ('perp_acct') scoped to
//    /Market-Tracker on this origin.
//  - Page gate: /Market-Tracker/ and /Market-Tracker/learn/ validate
//    the cookie server-to-server via GET /api/perp-acct/me (30s
//    in-function cache). Entitled -> the real page is served via
//    context.next(). Expired -> the paywall page. Anonymous/invalid
//    -> the sign-in page. The tracker HTML is never served to a
//    non-entitled visitor.
//  - API proxy: /Market-Tracker/api/perp/* forwards to the auth
//    service with the cookie's token injected as a Bearer header.
//    No cookie -> 401 JSON, upstream is never called.
//  - Everything else in the subtree (the Perp Alerts APK, assets)
//    falls through to static serving, untouched and public — the
//    Android app enforces its own login.

const DEFAULT_AUTH_ORIGIN = 'https://auth.rivaleclipse.dev';
const COOKIE_NAME = 'perp_acct';
const COOKIE_PATH = '/Market-Tracker';
const ME_TTL_MS = 30_000;
const COOKIE_MAX_AGE_S = 30 * 24 * 3600; // 30 days; the JWT itself is validated per gate check

const meCache = new Map(); // tokenKey -> { at, result }
export function _resetCaches() { meCache.clear(); }

function authOrigin(context) {
  const o = (context.env && context.env.PERP_AUTH_ORIGIN) || DEFAULT_AUTH_ORIGIN;
  return o.replace(/\/$/, '');
}

function tokenKey(token) {
  // Cheap non-crypto fingerprint for the validation cache key.
  let h = 5381;
  for (let i = 0; i < token.length; i++) h = ((h * 33) ^ token.charCodeAt(i)) >>> 0;
  return token.length + ':' + h.toString(36);
}

function parseCookies(request) {
  const out = {};
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (k) out[k] = part.slice(i + 1).trim();
  }
  return out;
}

function sessionCookie(token) {
  return COOKIE_NAME + '=' + token + '; Path=' + COOKIE_PATH +
    '; Max-Age=' + COOKIE_MAX_AGE_S + '; HttpOnly; Secure; SameSite=Lax';
}

function clearedCookie() {
  return COOKIE_NAME + '=; Path=' + COOKIE_PATH +
    '; Max-Age=0; HttpOnly; Secure; SameSite=Lax';
}

function jsonRes(obj, status, extraHeaders) {
  const headers = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
  if (extraHeaders) Object.assign(headers, extraHeaders);
  return new Response(JSON.stringify(obj), { status: status || 200, headers });
}

function htmlRes(html, status, extraHeaders) {
  const headers = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' };
  if (extraHeaders) Object.assign(headers, extraHeaders);
  return new Response(html, { status: status || 200, headers });
}

/* ---------------- session validation (the gate) ------------------ */

async function validateSession(context, token) {
  if (!token) return { kind: 'anon' };
  const key = tokenKey(token);
  const hit = meCache.get(key);
  if (hit && Date.now() - hit.at < ME_TTL_MS) return hit.result;
  let result;
  try {
    const r = await fetch(authOrigin(context) + '/api/perp-acct/me', {
      headers: { Authorization: 'Bearer ' + token },
    });
    if (r.status === 401) {
      result = { kind: 'invalid' };
    } else if (r.ok) {
      const j = await r.json().catch(() => null);
      const ent = j && j.entitlement;
      result = ent && ent.access
        ? { kind: 'entitled', me: j }
        : { kind: 'expired', me: j };
    } else {
      result = { kind: 'anon' }; // upstream trouble: fail closed
    }
  } catch (e) {
    result = { kind: 'anon' }; // unreachable auth service: fail closed
  }
  meCache.set(key, { at: Date.now(), result });
  return result;
}

async function gatePage(context, token) {
  const v = await validateSession(context, token);
  if (v.kind === 'entitled') return context.next();
  if (v.kind === 'expired') return htmlRes(accountPage());
  const extra = v.kind === 'invalid' ? { 'Set-Cookie': clearedCookie() } : null;
  return htmlRes(signInPage(), 200, extra);
}

/* ---------------- API proxy (/Market-Tracker/api/perp/*) -------- */

async function proxyApi(context, request, url, rest) {
  const token = parseCookies(request)[COOKIE_NAME];
  if (!token) return jsonRes({ error: 'unauthorized' }, 401);
  const headers = { Authorization: 'Bearer ' + token };
  const ct = request.headers.get('content-type');
  if (ct) headers['Content-Type'] = ct;
  const init = { method: request.method, headers };
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = request.body;
    init.duplex = 'half';
  }
  let r;
  try {
    r = await fetch(authOrigin(context) + rest + url.search, init);
  } catch (e) {
    return jsonRes({ error: 'upstream_unavailable' }, 502);
  }
  const out = new Headers(r.headers);
  out.delete('set-cookie');
  return new Response(r.body, { status: r.status, statusText: r.statusText, headers: out });
}

/* ------------- market-data proxy (WEB12, Shane 2026-10-28) -------
   The tracker's market-mimic presets pull the CHOSEN market's own
   numbers, not a local reconstruction:
   - /api/pm/crypto-price?symbol=BTC&start=<epochSec>&variant=fifteen
     forwards to Polymarket's own crypto-price endpoint — the same
     one its up/down pages use. openPrice is the market's official
     "price to beat" for the window opening at `start` (Chainlink
     TWAP-60 for the 5m/15m/4h variants, the Binance candle open for
     the hourly variant); closePrice is its live/final price.
   - /api/kalshi/markets?series=KXBTC15M returns the open markets of
     a Kalshi series (slimmed): floor_strike is the market's official
     target for its window, set by Kalshi at the open.
   Both require an entitled perp-acct session, same as the tracker. */

const PM_VARIANTS = new Set(['fiveminute', 'fifteen', 'hourly', 'fourhour', 'daily']);

async function requireEntitled(context, request) {
  const token = parseCookies(request)[COOKIE_NAME];
  if (!token) return null;
  const v = await validateSession(context, token);
  return v.kind === 'entitled' ? v : null;
}

async function pmPriceRoute(context, request, url) {
  if (request.method !== 'GET') return jsonRes({ error: 'method_not_allowed' }, 405);
  if (!(await requireEntitled(context, request))) return jsonRes({ error: 'unauthorized' }, 401);
  const symbol = (url.searchParams.get('symbol') || '').toUpperCase();
  const start = Number(url.searchParams.get('start'));
  const variant = url.searchParams.get('variant') || '';
  const nowS = Math.floor(Date.now() / 1000);
  if (!/^[A-Z0-9]{2,10}$/.test(symbol) ||
      !Number.isInteger(start) || start < nowS - 2 * 86400 || start > nowS + 86400 ||
      !PM_VARIANTS.has(variant)) {
    return jsonRes({ error: 'bad_params' }, 400);
  }
  const up = 'https://polymarket.com/api/crypto/crypto-price?symbol=' +
    encodeURIComponent(symbol) + '&eventStartTime=' + start + '&variant=' + encodeURIComponent(variant);
  let r;
  try {
    r = await fetch(up, { headers: { Accept: 'application/json' } });
  } catch (e) {
    return jsonRes({ error: 'upstream_unavailable' }, 502);
  }
  const text = await r.text();
  return new Response(text, {
    status: r.status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

async function kalshiRoute(context, request, url) {
  if (request.method !== 'GET') return jsonRes({ error: 'method_not_allowed' }, 405);
  if (!(await requireEntitled(context, request))) return jsonRes({ error: 'unauthorized' }, 401);
  const series = (url.searchParams.get('series') || '').toUpperCase();
  if (!/^KX[A-Z0-9]{2,20}$/.test(series)) return jsonRes({ error: 'bad_params' }, 400);
  const up = 'https://api.elections.kalshi.com/trade-api/v2/markets?status=open&limit=10&series_ticker=' +
    encodeURIComponent(series);
  let r;
  try {
    r = await fetch(up, { headers: { Accept: 'application/json' } });
  } catch (e) {
    return jsonRes({ error: 'upstream_unavailable' }, 502);
  }
  if (!r.ok) return jsonRes({ error: 'upstream_error' }, 502);
  let j;
  try { j = await r.json(); } catch (e) { return jsonRes({ error: 'upstream_error' }, 502); }
  const markets = (Array.isArray(j.markets) ? j.markets : []).map(m => ({
    ticker: m.ticker, floor_strike: m.floor_strike,
    open_time: m.open_time, close_time: m.close_time,
  }));
  return jsonRes({ markets }, 200, { 'Cache-Control': 'no-store' });
}

/* ---------------- account API (/Market-Tracker/acct/*) ---------- */

const ACCT_ACTIONS = {
  'login':              { method: 'POST', upstream: '/api/perp-acct/login',              public: true },
  'register':           { method: 'POST', upstream: '/api/perp-acct/register',           public: true },
  'forgot':             { method: 'POST', upstream: '/api/perp-acct/forgot',             public: true },
  'reset':              { method: 'POST', upstream: '/api/perp-acct/reset',              public: true },
  'logout':             { method: 'POST', upstream: '/api/perp-acct/logout' },
  'me':                 { method: 'GET',  upstream: '/api/perp-acct/me' },
  'redeem':             { method: 'POST', upstream: '/api/perp-acct/redeem' },
  'checkout-subscribe': { method: 'POST', upstream: '/api/perp-acct/checkout/subscribe' },
  'checkout-trial':     { method: 'POST', upstream: '/api/perp-acct/checkout/trial' },
  'portal':             { method: 'POST', upstream: '/api/perp-acct/portal' },
};

async function acctApi(context, request, action, spec) {
  const token = parseCookies(request)[COOKIE_NAME];
  if (!spec.public && !token) return jsonRes({ error: 'unauthorized' }, 401);

  let bodyText = null;
  if (spec.method === 'POST') {
    bodyText = await request.text().catch(() => null);
  }

  // Logout is best-effort upstream; the local session dies regardless.
  if (action === 'logout') {
    try {
      await fetch(authOrigin(context) + spec.upstream, {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: bodyText || '{}',
      });
    } catch (e) { /* ignore — clearing the cookie is the point */ }
    return jsonRes({ ok: true }, 200, { 'Set-Cookie': clearedCookie() });
  }

  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  let r;
  try {
    r = await fetch(authOrigin(context) + spec.upstream, {
      method: spec.method, headers, body: bodyText == null ? undefined : bodyText,
    });
  } catch (e) {
    return jsonRes({ error: 'upstream_unavailable' }, 502);
  }
  const text = await r.text().catch(() => '');
  let j = null;
  try { j = text ? JSON.parse(text) : null; } catch (e) { j = null; }
  if (!j || typeof j !== 'object') j = { error: 'upstream_error' };

  const extra = {};
  if ((action === 'login' || action === 'register') && r.ok && j.token) {
    extra['Set-Cookie'] = sessionCookie(j.token);
    delete j.token; // the JWT never reaches browser JS
  }
  return jsonRes(j, r.status, extra);
}

/* ---------------- pages ------------------------------------------ */

function shell(title, bodyHtml, scriptText) {
  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '<title>' + title + ' — Perpetual Helper</title>\n<style>\n' +
    ':root{--bg:#050510;--panel:#0a0a12;--panel2:#10101c;--line:#23233a;--txt:#eceaf4;' +
    '--mut:#9a97ad;--gold:#c9a227;--gold2:#e8c95a;--violet:#7c5cff;--err:#ff6b81;--ok:#3ddc97}\n' +
    '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);' +
    'font:16px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;' +
    'min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:28px 16px 56px}\n' +
    '.wm{font-size:30px;font-weight:800;letter-spacing:.5px;margin:6px 0 2px}\n' +
    '.wm .e{color:var(--gold)}.prod{color:var(--mut);font-size:14px;margin-bottom:22px;text-align:center}\n' +
    '.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;' +
    'padding:22px 20px;width:100%;max-width:430px;margin-bottom:16px}\n' +
    '.card.wide{max-width:560px}h1{font-size:21px;margin:0 0 6px}h2{font-size:17px;margin:0 0 8px}\n' +
    'p{margin:8px 0}.mut{color:var(--mut)}.small{font-size:13px}\n' +
    'label{display:block;font-size:13px;color:var(--mut);margin:14px 0 5px}\n' +
    'input{width:100%;padding:12px 13px;border-radius:10px;border:1px solid var(--line);' +
    'background:var(--panel2);color:var(--txt);font-size:16px}\n' +
    'input:focus{outline:2px solid var(--violet);border-color:transparent}\n' +
    '.btn{display:block;width:100%;padding:13px;border:0;border-radius:12px;margin-top:16px;' +
    'background:linear-gradient(90deg,var(--gold2),var(--gold));color:#14100a;font-size:16px;' +
    'font-weight:700;cursor:pointer;text-align:center;text-decoration:none}\n' +
    '.btn.violet{background:var(--violet);color:#fff}.btn.ghost{background:transparent;' +
    'border:1px solid var(--line);color:var(--txt);font-weight:600}\n' +
    '.btn:disabled{opacity:.55;cursor:wait}\n' +
    '.msg{margin-top:14px;font-size:14px;min-height:20px}.msg.err{color:var(--err)}.msg.ok{color:var(--ok)}\n' +
    '.links{margin-top:16px;font-size:14px;color:var(--mut);text-align:center}\n' +
    'a{color:var(--gold2)}.plans{display:grid;gap:12px}@media(min-width:520px){.plans{grid-template-columns:1fr 1fr}}\n' +
    '.plan{border:1px solid var(--line);border-radius:14px;padding:16px;background:var(--panel2)}\n' +
    '.price{font-size:26px;font-weight:800;color:var(--gold2)}.per{color:var(--mut);font-size:13px}\n' +
    '.state{font-size:18px;font-weight:700}.pill{display:inline-block;padding:2px 10px;border-radius:99px;' +
    'background:#1c1c30;border:1px solid var(--line);font-size:12px;color:var(--gold2);margin-left:8px}\n' +
    '.count{font-variant-numeric:tabular-nums;color:var(--gold2);font-weight:700}\n' +
    'footer{margin-top:auto;color:var(--mut);font-size:12px;text-align:center;padding-top:26px}\n' +
    '</style>\n</head>\n<body>\n' +
    '<div class="wm">Rıval <span class="e">Eclıpse</span></div>\n' +
    '<div class="prod">Perpetual Helper · Market Tracker</div>\n' +
    bodyHtml +
    '<footer>Perpetual Helper is a product of Rival Eclipse. Predictions are probabilities, not guarantees — not financial advice.</footer>\n' +
    (scriptText ? '<script>\n' + scriptText + '\n</script>\n' : '') +
    '</body>\n</html>';
}

// Shared browser-side helper: POST JSON to an /acct/* route.
const HELPER_JS =
  'async function postJSON(path, body){\n' +
  '  const r = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json"},\n' +
  '    body: JSON.stringify(body || {})});\n' +
  '  const j = await r.json().catch(() => null);\n' +
  '  return {status: r.status, ok: r.ok, j: j || {}};\n' +
  '}\n' +
  'function setMsg(id, text, ok){\n' +
  '  const m = document.getElementById(id); if (!m) return;\n' +
  '  m.textContent = text || ""; m.className = "msg " + (ok ? "ok" : "err");\n' +
  '}\n' +
  'function errText(j, fallback){\n' +
  '  return (j && (j.error || j.message)) || fallback;\n' +
  '}\n' +
  'function afterAuth(){\n' +
  '  const next = new URLSearchParams(location.search).get("next");\n' +
  '  if (next && next.indexOf("/Market-Tracker") === 0) { location.href = next; return; }\n' +
  '  if (location.pathname.indexOf("/Market-Tracker/acct") === 0) { location.href = "/Market-Tracker/"; return; }\n' +
  '  location.href = "/Market-Tracker/";\n' +
  '}\n';

function signInPage() {
  const body =
    '<div class="card"><h1>Sign in</h1>' +
    '<p class="mut small">The Market Tracker is members-only now. Sign in to open it.</p>' +
    '<form id="f"><label for="email">Email</label>' +
    '<input id="email" type="email" autocomplete="email" required>' +
    '<label for="pw">Password</label>' +
    '<input id="pw" type="password" autocomplete="current-password" required>' +
    '<button class="btn" id="go" type="submit">Sign in</button></form>' +
    '<div class="msg" id="msg"></div>' +
    '<div class="links">New here? <a href="/Market-Tracker/acct/sign-up">Create an account</a>' +
    ' — your first hour is free.<br><a href="/Market-Tracker/acct/forgot">Forgot your password?</a></div></div>';
  const script = HELPER_JS +
    'document.getElementById("f").addEventListener("submit", async (ev) => {\n' +
    '  ev.preventDefault();\n' +
    '  const btn = document.getElementById("go"); btn.disabled = true;\n' +
    '  setMsg("msg", "");\n' +
    '  try {\n' +
    '    const r = await postJSON("/Market-Tracker/acct/login", {\n' +
    '      email: document.getElementById("email").value.trim(),\n' +
    '      password: document.getElementById("pw").value });\n' +
    '    if (r.ok) { afterAuth(); return; }\n' +
    '    setMsg("msg", errText(r.j, "Sign-in failed — check your email and password."), false);\n' +
    '  } catch (e) { setMsg("msg", "Could not reach the sign-in service — try again in a moment.", false); }\n' +
    '  btn.disabled = false;\n' +
    '});\n';
  return shell('Sign in', body, script);
}

function signUpPage() {
  const body =
    '<div class="card"><h1>Create your account</h1>' +
    '<p><b>Your 1-hour free trial starts now</b> — the moment your account is created, ' +
    'the full tracker unlocks for one hour. No card required.</p>' +
    '<form id="f"><label for="email">Email</label>' +
    '<input id="email" type="email" autocomplete="email" required>' +
    '<label for="pw">Password (minimum 10 characters)</label>' +
    '<input id="pw" type="password" autocomplete="new-password" minlength="10" required>' +
    '<button class="btn" id="go" type="submit">Create account &amp; start free hour</button></form>' +
    '<div class="msg" id="msg"></div>' +
    '<p class="mut small">After the free hour: keep full access with a $0.99 1-week trial, ' +
    'then $9.99/month — or redeem a promo code. Cancel anytime.</p>' +
    '<div class="links">Already have an account? <a href="/Market-Tracker/acct/sign-in">Sign in</a></div></div>';
  const script = HELPER_JS +
    'document.getElementById("f").addEventListener("submit", async (ev) => {\n' +
    '  ev.preventDefault();\n' +
    '  const pw = document.getElementById("pw").value;\n' +
    '  if (pw.length < 10) { setMsg("msg", "Password must be at least 10 characters.", false); return; }\n' +
    '  const btn = document.getElementById("go"); btn.disabled = true;\n' +
    '  setMsg("msg", "");\n' +
    '  try {\n' +
    '    const r = await postJSON("/Market-Tracker/acct/register", {\n' +
    '      email: document.getElementById("email").value.trim(), password: pw });\n' +
    '    if (r.ok) { afterAuth(); return; }\n' +
    '    setMsg("msg", errText(r.j, "Could not create the account — that email may already be registered."), false);\n' +
    '  } catch (e) { setMsg("msg", "Could not reach the account service — try again in a moment.", false); }\n' +
    '  btn.disabled = false;\n' +
    '});\n';
  return shell('Create account', body, script);
}

function forgotPage() {
  const body =
    '<div class="card"><h1>Forgot your password?</h1>' +
    '<p class="mut small">Enter your account email and we will send a reset link.</p>' +
    '<form id="f"><label for="email">Email</label>' +
    '<input id="email" type="email" autocomplete="email" required>' +
    '<button class="btn" id="go" type="submit">Send reset link</button></form>' +
    '<div class="msg" id="msg"></div>' +
    '<div class="links"><a href="/Market-Tracker/acct/sign-in">Back to sign in</a></div></div>';
  const script = HELPER_JS +
    'document.getElementById("f").addEventListener("submit", async (ev) => {\n' +
    '  ev.preventDefault();\n' +
    '  const btn = document.getElementById("go"); btn.disabled = true;\n' +
    '  try {\n' +
    '    await postJSON("/Market-Tracker/acct/forgot", {\n' +
    '      email: document.getElementById("email").value.trim() });\n' +
    '  } catch (e) { /* same message either way */ }\n' +
    '  setMsg("msg", "If that email has an account, a reset link is on its way.", true);\n' +
    '  btn.disabled = false;\n' +
    '});\n';
  return shell('Forgot password', body, script);
}

function resetPage() {
  const body =
    '<div class="card"><h1>Set a new password</h1>' +
    '<form id="f"><label for="pw">New password (minimum 10 characters)</label>' +
    '<input id="pw" type="password" autocomplete="new-password" minlength="10" required>' +
    '<button class="btn" id="go" type="submit">Set new password</button></form>' +
    '<div class="msg" id="msg"></div>' +
    '<div class="links"><a href="/Market-Tracker/acct/sign-in">Back to sign in</a></div></div>';
  const script = HELPER_JS +
    'const TOKEN = new URLSearchParams(location.search).get("token") || "";\n' +
    'if (!TOKEN) setMsg("msg", "This reset link is missing its token — request a fresh link from the forgot-password page.", false);\n' +
    'document.getElementById("f").addEventListener("submit", async (ev) => {\n' +
    '  ev.preventDefault();\n' +
    '  const pw = document.getElementById("pw").value;\n' +
    '  if (!TOKEN) { setMsg("msg", "This reset link is missing its token.", false); return; }\n' +
    '  if (pw.length < 10) { setMsg("msg", "Password must be at least 10 characters.", false); return; }\n' +
    '  const btn = document.getElementById("go"); btn.disabled = true;\n' +
    '  try {\n' +
    '    const r = await postJSON("/Market-Tracker/acct/reset", { token: TOKEN, password: pw });\n' +
    '    if (r.ok) { setMsg("msg", "Password updated — taking you to sign in…", true);\n' +
    '      setTimeout(() => { location.href = "/Market-Tracker/acct/sign-in"; }, 900); return; }\n' +
    '    setMsg("msg", errText(r.j, "That reset link did not work — it may have expired. Request a fresh one."), false);\n' +
    '  } catch (e) { setMsg("msg", "Could not reach the account service — try again in a moment.", false); }\n' +
    '  btn.disabled = false;\n' +
    '});\n';
  return shell('Reset password', body, script);
}

function accountPage() {
  const body =
    '<div class="card wide"><h1>Your access</h1>' +
    '<div id="stateBox"><p class="mut">Loading your account…</p></div>' +
    '<div class="msg" id="stateMsg"></div></div>' +
    '<div class="card wide"><h2>Plans</h2>' +
    '<div id="payNote" class="msg" style="display:none"></div>' +
    '<div class="plans">' +
    '<div class="plan"><div class="price">$0.99</div><div class="per">1-week trial, then $9.99/month</div>' +
    '<p class="small mut">A full week of the complete tracker for under a dollar. Renews at $9.99/month unless you cancel.</p>' +
    '<button class="btn" id="btnTrial" type="button">Start 1-week trial — $0.99</button></div>' +
    '<div class="plan"><div class="price">$9.99<span class="per">/month</span></div><div class="per">Full access, billed monthly</div>' +
    '<p class="small mut">Every coin, every horizon, alerts and forecast schedules. Cancel anytime.</p>' +
    '<button class="btn violet" id="btnSub" type="button">Subscribe — $9.99/mo</button></div>' +
    '</div>' +
    '<button class="btn ghost" id="btnPortal" type="button" style="display:none">Manage subscription / payment method</button>' +
    '</div>' +
    '<div class="card wide"><h2>Have a promo code?</h2>' +
    '<p class="mut small">Promo codes unlock a free week, a free month, or lifetime access — no card needed to redeem.</p>' +
    '<form id="promoForm"><label for="code">Promo code</label>' +
    '<input id="code" type="text" autocomplete="off" autocapitalize="characters" required>' +
    '<button class="btn" id="btnRedeem" type="submit">Redeem code</button></form>' +
    '<div class="msg" id="promoMsg"></div></div>' +
    '<div class="card wide"><button class="btn ghost" id="btnOut" type="button">Sign out</button>' +
    '<div class="links"><a href="/Market-Tracker/">Back to the tracker</a></div></div>';
  const script = HELPER_JS +
    'const STATE_LABEL = { lifetime: "Lifetime access", subscribed: "Monthly subscription",\n' +
    '  trial_paid: "1-week paid trial", promo: "Promo access", trial_free: "Free trial hour", expired: "Access ended" };\n' +
    'let countdownTimer = null;\n' +
    'function fmtDate(ms){ try { return new Date(ms).toLocaleString(); } catch (e) { return ""; } }\n' +
    'function render(me){\n' +
    '  const ent = (me && me.entitlement) || {};\n' +
    '  const box = document.getElementById("stateBox");\n' +
    '  const label = STATE_LABEL[ent.state] || ent.state || "No access";\n' +
    '  let html = "<p class=\\"state\\">" + label + (ent.access ? "<span class=\\"pill\\">ACTIVE</span>" : "<span class=\\"pill\\">ENDED</span>") + "</p>";\n' +
    '  html += "<p class=\\"mut small\\">Signed in as " + (me.email || "") + "</p>";\n' +
    '  if (ent.state === "lifetime") html += "<p>Free forever — this account never expires and never needs a card.</p>";\n' +
    '  else if (ent.access && ent.access_until) html += "<p>Access until <b>" + fmtDate(ent.access_until) + "</b></p>";\n' +
    '  else if (!ent.access) html += "<p>Your access has ended. Pick a plan below or redeem a promo code to get back in — your account and settings are saved.</p>";\n' +
    '  if (ent.state === "trial_free" && ent.access && ent.access_until) {\n' +
    '    html += "<p>Free trial time left: <span class=\\"count\\" id=\\"cd\\"></span></p>";\n' +
    '  }\n' +
    '  box.innerHTML = html;\n' +
    '  const portal = document.getElementById("btnPortal");\n' +
    '  portal.style.display = (ent.state === "subscribed" || ent.state === "trial_paid") ? "block" : "none";\n' +
    '  if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }\n' +
    '  const cd = document.getElementById("cd");\n' +
    '  if (cd) {\n' +
    '    const until = ent.access_until;\n' +
    '    const tick = () => { const left = until - Date.now();\n' +
    '      if (left <= 0) { cd.textContent = "0:00 — reloading…"; location.reload(); return; }\n' +
    '      const s = Math.ceil(left / 1000), m = Math.floor(s / 60), ss = s % 60;\n' +
    '      cd.textContent = (m > 59 ? Math.floor(m / 60) + "h " + (m % 60) + "m" : m + ":" + String(ss).padStart(2, "0")); };\n' +
    '    tick(); countdownTimer = setInterval(tick, 1000);\n' +
    '  }\n' +
    '}\n' +
    'async function loadMe(){\n' +
    '  try {\n' +
    '    const r = await fetch("/Market-Tracker/acct/me", { headers: { Accept: "application/json" } });\n' +
    '    if (r.status === 401) { location.href = "/Market-Tracker/acct/sign-in"; return; }\n' +
    '    const j = await r.json().catch(() => null);\n' +
    '    if (j) render(j);\n' +
    '    else setMsg("stateMsg", "Could not load your account state — refresh to retry.", false);\n' +
    '  } catch (e) { setMsg("stateMsg", "Could not load your account state — refresh to retry.", false); }\n' +
    '}\n' +
    'async function startCheckout(path){\n' +
    '  const note = document.getElementById("payNote"); note.style.display = "none";\n' +
    '  const r = await postJSON(path, {});\n' +
    '  if (r.ok && r.j && r.j.url) { location.href = r.j.url; return; }\n' +
    '  if (r.status === 503 || (r.j && r.j.error === "payments_not_configured")) {\n' +
    '    note.textContent = "Payments are being activated — promo codes and free trials work now, check back shortly.";\n' +
    '    note.className = "msg ok"; note.style.display = "block"; return;\n' +
    '  }\n' +
    '  note.textContent = errText(r.j, "Checkout did not start — try again in a moment.");\n' +
    '  note.className = "msg err"; note.style.display = "block";\n' +
    '}\n' +
    'document.getElementById("btnTrial").addEventListener("click", () => startCheckout("/Market-Tracker/acct/checkout-trial"));\n' +
    'document.getElementById("btnSub").addEventListener("click", () => startCheckout("/Market-Tracker/acct/checkout-subscribe"));\n' +
    'document.getElementById("btnPortal").addEventListener("click", async () => {\n' +
    '  const r = await postJSON("/Market-Tracker/acct/portal", {});\n' +
    '  if (r.ok && r.j && r.j.url) { location.href = r.j.url; return; }\n' +
    '  if (r.status === 503 || (r.j && r.j.error === "payments_not_configured")) {\n' +
    '    const note = document.getElementById("payNote");\n' +
    '    note.textContent = "Payments are being activated — promo codes and free trials work now, check back shortly.";\n' +
    '    note.className = "msg ok"; note.style.display = "block"; return;\n' +
    '  }\n' +
    '  setMsg("stateMsg", errText(r.j, "Could not open subscription management."), false);\n' +
    '});\n' +
    'document.getElementById("promoForm").addEventListener("submit", async (ev) => {\n' +
    '  ev.preventDefault();\n' +
    '  const btn = document.getElementById("btnRedeem"); btn.disabled = true;\n' +
    '  const r = await postJSON("/Market-Tracker/acct/redeem", {\n' +
    '    code: document.getElementById("code").value.trim() });\n' +
    '  btn.disabled = false;\n' +
    '  if (r.ok) { setMsg("promoMsg", "Code redeemed — your access is updated below.", true); loadMe(); return; }\n' +
    '  setMsg("promoMsg", errText(r.j, "That code did not redeem — check it and try again."), false);\n' +
    '});\n' +
    'document.getElementById("btnOut").addEventListener("click", async () => {\n' +
    '  try { await postJSON("/Market-Tracker/acct/logout", {}); } catch (e) {}\n' +
    '  location.href = "/Market-Tracker/";\n' +
    '});\n' +
    'loadMe();\n';
  return shell('Your access', body, script);
}

/* ---------------- routing ---------------------------------------- */

function acctRoute(context, request, rest) {
  // rest is '/acct', '/acct/', or '/acct/<thing>'
  const sub = rest.slice('/acct'.length).replace(/^\//, '');
  if (sub === '') {
    const token = parseCookies(request)[COOKIE_NAME];
    if (!token) {
      return new Response(null, {
        status: 302,
        headers: { Location: '/Market-Tracker/acct/sign-in', 'Cache-Control': 'no-store' },
      });
    }
    return htmlRes(accountPage());
  }
  const spec = ACCT_ACTIONS[sub];
  if (spec && request.method === spec.method) {
    return acctApi(context, request, sub, spec);
  }
  // 'forgot' and 'reset' are BOTH POST actions and GET pages.
  if (request.method === 'GET') {
    if (sub === 'sign-in') return htmlRes(signInPage());
    if (sub === 'sign-up') return htmlRes(signUpPage());
    if (sub === 'forgot') return htmlRes(forgotPage());
    if (sub === 'reset') return htmlRes(resetPage());
  }
  if (spec) return jsonRes({ error: 'method_not_allowed' }, 405);
  return htmlRes(shell('Not found', '<div class="card"><h1>Not found</h1>' +
    '<p class="mut">That account page does not exist.</p>' +
    '<div class="links"><a href="/Market-Tracker/acct/sign-in">Sign in</a></div></div>'), 404);
}

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const rest = url.pathname.slice('/Market-Tracker'.length);

  // API proxy — the tracker's data plane.
  if (rest === '/api/perp' || rest.startsWith('/api/perp/')) {
    return proxyApi(context, request, url, rest);
  }
  // Market-data proxy (WEB12): the chosen market's own targets/feed.
  if (rest === '/api/pm/crypto-price') {
    return pmPriceRoute(context, request, url);
  }
  if (rest === '/api/kalshi/markets') {
    return kalshiRoute(context, request, url);
  }
  if (rest === '/api' || rest.startsWith('/api/')) {
    return jsonRes({ error: 'not_found' }, 404);
  }

  // Account pages + account API.
  if (rest === '/acct' || rest.startsWith('/acct/')) {
    return acctRoute(context, request, rest);
  }

  // Bare /reset and /forgot: the password-reset email link points at
  // /Market-Tracker/reset?token=... — redirect to the canonical acct page
  // (query preserved) so emailed links land on the real form.
  if (rest === '/reset' || rest === '/forgot') {
    return new Response(null, {
      status: 302,
      headers: { Location: '/Market-Tracker/acct' + rest + url.search, 'Cache-Control': 'no-store' },
    });
  }

  // Page gate — the tracker and the Learn page are the product.
  if (rest === '' || rest === '/' || rest === '/index.html' ||
      rest === '/learn' || rest === '/learn/' || rest === '/learn/index.html') {
    const token = parseCookies(request)[COOKIE_NAME];
    return gatePage(context, token);
  }

  // Everything else (perp-alerts.apk, assets) stays public static.
  return context.next();
}

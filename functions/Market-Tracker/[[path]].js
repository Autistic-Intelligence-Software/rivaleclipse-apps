// Perpetual Helper — paywall gate, account pages, and API proxy for
// the /Market-Tracker/ subtree (Shane's order 2026-10-28).
//
// The tracker is a paid product now: $9.99/mo, a $0.99 1-week paid
// trial, a 1-hour free trial on sign-up, and single-use promo codes
// (1-week / 1-month / lifetime). Accounts live in a STANDALONE system
// on the auth service (https://auth.rivaleclipse.dev/api/perp-acct/*)
// — completely separate from the Rival Eclipse hub/bot accounts.
//
// Host split (Phase A host separation):
//  - Core (authOrigin, env PERP_AUTH_ORIGIN, default
//    https://auth.rivaleclipse.dev): the account API
//    (/api/perp-acct/*) AND gate validation (GET /api/perp-acct/me).
//  - Engine (engineOrigin, env PERP_ENGINE_ORIGIN, default
//    https://rival-eclipse-perp-engine.fly.dev): ONLY the tracker
//    data proxy (/api/perp/*). Account calls and gate validation
//    never go to the engine host. The default is the Fly hostname
//    (works the moment the Fly app exists, no DNS dependency); it
//    moves to https://perp.rivaleclipse.dev once that subdomain's
//    DNS/cert verify — set PERP_ENGINE_ORIGIN to make the switch
//    without a code change.
//
// How it works:
//  - The browser never sees the account JWT. The /acct/* API routes
//    below proxy to the auth (Core) service; on login/register the
//    returned token is stored in an HttpOnly cookie ('perp_acct')
//    scoped to /Market-Tracker on this origin.
//  - Page gate: /Market-Tracker/ and /Market-Tracker/learn/ validate
//    the cookie server-to-server via GET /api/perp-acct/me on Core
//    (30s in-function cache). Entitled -> the real page is served via
//    context.next(). Expired -> the paywall page. Anonymous/invalid
//    -> the sign-in page. The tracker HTML is never served to a
//    non-entitled visitor.
//  - API proxy: /Market-Tracker/api/perp/* forwards to the engine
//    service with the cookie's token injected as a Bearer header.
//    No cookie -> 401 JSON, upstream is never called.
//  - Everything else in the subtree (the Perp Alerts APK, assets)
//    falls through to static serving, untouched and public — the
//    Android app enforces its own login.

const DEFAULT_AUTH_ORIGIN = 'https://auth.rivaleclipse.dev';
// Default is the Fly hostname on purpose: no Cloudflare DNS for
// perp.rivaleclipse.dev exists until a dashboard step at cutover, and
// the fly.dev name works as soon as the app does. Once the
// perp.rivaleclipse.dev DNS/cert verify, this default moves to
// https://perp.rivaleclipse.dev (or PERP_ENGINE_ORIGIN is set to it).
const DEFAULT_ENGINE_ORIGIN = 'https://rival-eclipse-perp-engine.fly.dev';
const COOKIE_NAME = 'perp_acct';
const COOKIE_PATH = '/Market-Tracker';
const ME_TTL_MS = 30_000;
const COOKIE_MAX_AGE_S = 30 * 24 * 3600; // 30 days; the JWT itself is validated per gate check

const meCache = new Map(); // tokenKey -> { at, result }
export function _resetCaches() {
  meCache.clear();
  // WEB53 pm cache maps are declared with the PM route below;
  // module load completes before any test calls this.
  try { pmCache.clear(); pmInflight.clear(); } catch (e) { /* not yet initialized */ }
}

/* Bounded upstream waits (2026-11-01): the auth service stalls
   periodically under engine load (blackouts up to ~80s measured).
   An unbounded fetch here used to hang the whole request — on the
   sign-in route that stranded the page's button disabled forever.
   Every upstream fetch below carries a deadline; a timeout on the
   account API answers 504 service_slow so the page can say what
   happened and re-enable its button. Env overrides exist for the
   test harness; production uses the defaults. */
const UPSTREAM_TIMEOUT_MS = 20_000; // account API calls
const ME_TIMEOUT_MS = 10_000;       // session validation at the gate
const PROXY_TIMEOUT_MS = 25_000;    // tracker data plane

function envTimeoutMs(context, name, dflt) {
  const v = Number(context && context.env && context.env[name]);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : dflt;
}
function timeoutSignal(ms) {
  try {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
      return AbortSignal.timeout(ms);
    }
  } catch (e) { /* fall through: no signal */ }
  return undefined;
}
function isTimeoutErr(e) {
  return !!e && (e.name === 'TimeoutError' || e.name === 'AbortError');
}

function authOrigin(context) {
  const o = (context.env && context.env.PERP_AUTH_ORIGIN) || DEFAULT_AUTH_ORIGIN;
  return o.replace(/\/$/, '');
}

function engineOrigin(context) {
  const o = (context.env && context.env.PERP_ENGINE_ORIGIN) || DEFAULT_ENGINE_ORIGIN;
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

/* Validation outcomes. 'entitled' / 'expired' / 'invalid' are
   DEFINITIVE answers from Core's /api/perp-acct/me. 'trouble' means
   validation could not complete (timeout, network error, non-401
   upstream status) — it is NOT a session verdict, and callers must
   not treat it as one (WEB51, 2026-11-01: during auth-service
   stalls this used to collapse into 'anon', so the market-data
   proxy answered 401 for entitled users and the page bounced them
   to sign-in). Trouble results are cached only briefly so one
   hiccup cannot poison a full ME_TTL window of reads. */
const TROUBLE_TTL_MS = 2_000;

async function validateSession(context, token) {
  if (!token) return { kind: 'anon' };
  const key = tokenKey(token);
  const hit = meCache.get(key);
  if (hit && Date.now() - hit.at < hit.ttl) return hit.result;
  let result;
  try {
    const r = await fetch(authOrigin(context) + '/api/perp-acct/me', {
      headers: { Authorization: 'Bearer ' + token },
      signal: timeoutSignal(envTimeoutMs(context, 'PERP_ME_TIMEOUT_MS', ME_TIMEOUT_MS)),
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
      result = { kind: 'trouble' }; // upstream trouble: not a verdict
    }
  } catch (e) {
    result = { kind: 'trouble' }; // unreachable auth service: not a verdict
  }
  meCache.set(key, {
    at: Date.now(),
    ttl: result.kind === 'trouble' ? TROUBLE_TTL_MS : ME_TTL_MS,
    result,
  });
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
  init.signal = timeoutSignal(envTimeoutMs(context, 'PERP_PROXY_TIMEOUT_MS', PROXY_TIMEOUT_MS));
  let r;
  try {
    r = await fetch(engineOrigin(context) + rest + url.search, init);
  } catch (e) {
    return jsonRes({ error: isTimeoutErr(e) ? 'upstream_slow' : 'upstream_unavailable' }, 502);
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
   Kalshi used to be proxied here too, but the Pages edge cannot
   reach Kalshi's hosts reliably (intermittent edge 502s) — the
   engine service serves its strikes at GET /api/perp/kalshi
   instead, carried by the standard /api/perp/* API proxy.
   The PM route requires an entitled perp-acct session, same as
   the tracker. */

const PM_VARIANTS = new Set(['fiveminute', 'fifteen', 'hourly', 'fourhour', 'daily']);

/* WEB53 (2026-11-01): per-key response cache + in-flight coalescing
   for the PM proxy — the 429 mitigation. Polymarket rate-limited
   279 of 690 crypto-price reads in one verification window because
   every page pass re-fetched windows whose values cannot change:
   a COMPLETED window's open/close are the market's settled record
   (immutable), so a completed response is cached indefinitely; an
   in-progress window's response is cached only PM_LIVE_TTL_MS so
   convergence reads stay fresh to a few seconds. Errors and 429s
   are NEVER cached. Identical requests already in flight share
   one upstream fetch. This changes only how often upstream is
   asked — never which value is returned, and no finality rule in
   the page or engine is touched. State is per-isolate (a Map),
   matching the meCache pattern above; isolates are recycled by
   the platform, which only ever shortens a cache entry's life. */
const PM_LIVE_TTL_MS = 4_000;
const PM_CACHE_MAX = 512;
const pmCache = new Map();    // key -> { at, ttlMs, text }
const pmInflight = new Map(); // key -> Promise<{status, text}>
export function _resetPmCache() { pmCache.clear(); pmInflight.clear(); }

function pmCacheGet(key) {
  const hit = pmCache.get(key);
  if (!hit) return null;
  if (hit.ttlMs !== Infinity && Date.now() - hit.at >= hit.ttlMs) {
    pmCache.delete(key);
    return null;
  }
  return hit.text;
}
function pmCachePut(key, text) {
  let completed = false;
  try { completed = JSON.parse(text).completed === true; } catch (e) { completed = false; }
  if (pmCache.size >= PM_CACHE_MAX) pmCache.delete(pmCache.keys().next().value);
  pmCache.set(key, { at: Date.now(), ttlMs: completed ? Infinity : PM_LIVE_TTL_MS, text });
}

async function requireEntitled(context, request) {
  const token = parseCookies(request)[COOKIE_NAME];
  if (!token) return { kind: 'anon' };
  return validateSession(context, token);
}

async function pmPriceRoute(context, request, url) {
  if (request.method !== 'GET') return jsonRes({ error: 'method_not_allowed' }, 405);
  const v = await requireEntitled(context, request);
  if (v.kind === 'trouble') {
    // WEB51 fix: validation could not complete — that is not a
    // session verdict. A 401 here reads to the page as session
    // death; answer the transient-service signal instead (the page
    // treats it as a failed read and retries on the next pass).
    return jsonRes({ error: 'service_slow' }, 503);
  }
  if (v.kind !== 'entitled') return jsonRes({ error: 'unauthorized' }, 401);
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
  // WEB53: serve a cached copy when one is live for this exact
  // (symbol, start, variant); coalesce concurrent identical reads.
  const cacheKey = symbol + '|' + start + '|' + variant;
  const cached = pmCacheGet(cacheKey);
  if (cached != null) {
    return new Response(cached, {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  }
  let flight = pmInflight.get(cacheKey);
  if (!flight) {
    flight = (async () => {
      const r = await fetch(up, {
        headers: { Accept: 'application/json' },
        signal: timeoutSignal(envTimeoutMs(context, 'PERP_PROXY_TIMEOUT_MS', PROXY_TIMEOUT_MS)),
      });
      return { status: r.status, text: await r.text() };
    })();
    pmInflight.set(cacheKey, flight);
  }
  let out;
  try {
    out = await flight;
  } catch (e) {
    return jsonRes({ error: isTimeoutErr(e) ? 'upstream_slow' : 'upstream_unavailable' }, 502);
  } finally {
    if (pmInflight.get(cacheKey) === flight) pmInflight.delete(cacheKey);
  }
  if (out.status === 200) pmCachePut(cacheKey, out.text); // errors/429s never cached
  return new Response(out.text, {
    status: out.status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
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
        signal: timeoutSignal(envTimeoutMs(context, 'PERP_UPSTREAM_TIMEOUT_MS', UPSTREAM_TIMEOUT_MS)),
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
      signal: timeoutSignal(envTimeoutMs(context, 'PERP_UPSTREAM_TIMEOUT_MS', UPSTREAM_TIMEOUT_MS)),
    });
  } catch (e) {
    if (isTimeoutErr(e)) {
      // The auth service is stalled, not down: say so distinctly so
      // the page can show "answering slowly" instead of a dead end.
      // Status is 503, NOT 504: a 504 returned by this Function is
      // replaced at the edge by Cloudflare's plain-text error page
      // (verified live 2026-11-01 — body "error code: 504", no JSON
      // ever reached the browser), which would defeat the message.
      return jsonRes({ error: 'service_slow' }, 503);
    }
    return jsonRes({ error: 'upstream_unavailable' }, 502);
  }
  const text = await r.text().catch(() => '');
  let j = null;
  try { j = text ? JSON.parse(text) : null; } catch (e) { j = null; }
  if (!j || typeof j !== 'object') j = { error: 'upstream_error' };
  // A non-JSON 5xx from upstream is an edge error page (the auth
  // service's own Cloudflare answering for a stalled origin), not
  // an API answer: translate it to the same slow-service signal.
  // (A real API 503 like payments_not_configured carries a JSON
  // error field and passes through untouched.)
  if (r.status >= 500 && j.error === 'upstream_error') {
    return jsonRes({ error: 'service_slow' }, 503);
  }

  const extra = {};
  if ((action === 'login' || action === 'register') && r.ok && j.token) {
    extra['Set-Cookie'] = sessionCookie(j.token);
    delete j.token; // the JWT never reaches browser JS
  }
  return jsonRes(j, r.status, extra);
}

/* ---------------- pages ------------------------------------------ */

// Discord/social embed for the canonical tracker URL (Shane's order
// 2026-11-05): the sign-in page is what an unauthenticated fetcher —
// including Discord's crawler — receives at /Market-Tracker/, so it
// carries the Open Graph block. og:image is the animated ad GIF:
// Discord autoplays GIF embeds inline as the chat scrolls; og:video
// is deliberately omitted (it renders click-to-play and can displace
// the GIF). Public figures only.
const PROMO_HEAD =
  '<meta property="og:title" content="Rival Eclipse — Perpetual Helper">\n' +
  '<meta property="og:description" content="67.7% across 93,385 graded calls. Every call locked at the open, graded against the market\'s own posted close — the scoreboard is public. 1-hour free trial · $0.99 first week · $14.99/mo.">\n' +
  '<meta property="og:type" content="website">\n' +
  '<meta property="og:url" content="https://app.rivaleclipse.dev/Market-Tracker/">\n' +
  '<meta property="og:image" content="https://app.rivaleclipse.dev/Market-Tracker/promo.gif">\n' +
  '<meta property="og:image:type" content="image/gif">\n' +
  '<meta property="og:image:width" content="720">\n' +
  '<meta property="og:image:height" content="720">\n' +
  '<meta name="theme-color" content="#c9a227">\n' +
  '<meta name="twitter:card" content="summary_large_image">\n' +
  '<meta name="twitter:title" content="Rival Eclipse — Perpetual Helper">\n' +
  '<meta name="twitter:description" content="67.7% across 93,385 graded calls. Every call locked at the open, graded against the market\'s own posted close — the scoreboard is public. 1-hour free trial · $0.99 first week · $14.99/mo.">\n' +
  '<meta name="twitter:image" content="https://app.rivaleclipse.dev/Market-Tracker/promo.gif">\n';

function shell(title, bodyHtml, scriptText, headExtra) {
  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '<title>' + title + ' — Perpetual Helper</title>\n' + (headExtra || '') +
    '<style>\n' +
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
// Bounded (2026-11-01): the call used to wait forever when the
// sign-in service stalled, which stranded submit buttons in their
// disabled state with no message. Now every call carries a hard
// deadline (default 30s — the Function gives up on the upstream at
// 20s and answers service_slow first) and a stall comes back as a
// normal {ok:false, j:{error:"service_slow"}} result instead of a
// hang or a throw, so every caller's error path runs and every
// button recovers.
const HELPER_JS =
  'async function postJSON(path, body, timeoutMs){\n' +
  '  const ms = timeoutMs || 30000;\n' +
  '  let ctl = null, timer = null;\n' +
  '  try {\n' +
  '    const opts = {method:"POST", headers:{"Content-Type":"application/json"},\n' +
  '      body: JSON.stringify(body || {})};\n' +
  '    if (typeof AbortController === "function") {\n' +
  '      ctl = new AbortController(); opts.signal = ctl.signal;\n' +
  '      timer = setTimeout(() => { try { ctl.abort(); } catch (e) {} }, ms);\n' +
  '    }\n' +
  '    const r = await fetch(path, opts);\n' +
  '    const j = await r.json().catch(() => null);\n' +
  '    return {status: r.status, ok: r.ok, j: j || {}};\n' +
  '  } catch (e) {\n' +
  '    const timedOut = !!(ctl && ctl.signal && ctl.signal.aborted);\n' +
  '    return {status: 0, ok: false, j: {error: timedOut ? "service_slow" : "network_error"}};\n' +
  '  } finally { if (timer != null) clearTimeout(timer); }\n' +
  '}\n' +
  'function setMsg(id, text, ok){\n' +
  '  const m = document.getElementById(id); if (!m) return;\n' +
  '  m.textContent = text || ""; m.className = "msg " + (ok ? "ok" : "err");\n' +
  '}\n' +
  'const SLOW_TEXT = "The sign-in service is answering slowly right now — wait a moment and try again.";\n' +
  'function errText(j, fallback){\n' +
  '  const e = j && j.error;\n' +
  '  if (e === "service_slow" || e === "upstream_slow" || e === "upstream_unavailable") return SLOW_TEXT;\n' +
  '  if (e === "network_error") return "Could not reach the sign-in service — check your connection and try again.";\n' +
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
    '  const btn = document.getElementById("go");\n' +
    '  if (btn.disabled) return;\n' +
    '  btn.disabled = true;\n' +
    '  const oldLabel = btn.textContent; btn.textContent = "Signing in…";\n' +
    '  setMsg("msg", "");\n' +
    // If the service stalls, say so while still waiting — never
    // leave a silently dimmed button (the 2026-11-01 bug).
    '  const slowTimer = setTimeout(() => {\n' +
    '    setMsg("msg", "Still trying — the sign-in service is answering slowly right now…", true);\n' +
    '  }, 7000);\n' +
    '  let navigated = false;\n' +
    '  try {\n' +
    '    const r = await postJSON("/Market-Tracker/acct/login", {\n' +
    '      email: document.getElementById("email").value.trim(),\n' +
    '      password: document.getElementById("pw").value });\n' +
    '    if (r.ok) { navigated = true; afterAuth(); return; }\n' +
    '    setMsg("msg", errText(r.j, "Sign-in failed — check your email and password."), false);\n' +
    '  } catch (e) { setMsg("msg", "Could not reach the sign-in service — try again in a moment.", false); }\n' +
    '  finally {\n' +
    '    clearTimeout(slowTimer);\n' +
    // The button ALWAYS recovers unless we are navigating away.
    '    if (!navigated) { btn.disabled = false; btn.textContent = oldLabel; }\n' +
    '  }\n' +
    '});\n';
  return shell('Sign in', body, script, PROMO_HEAD);
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
    'then $14.99/month — or redeem a promo code. Cancel anytime.</p>' +
    '<div class="links">Already have an account? <a href="/Market-Tracker/acct/sign-in">Sign in</a></div></div>';
  const script = HELPER_JS +
    'document.getElementById("f").addEventListener("submit", async (ev) => {\n' +
    '  ev.preventDefault();\n' +
    '  const pw = document.getElementById("pw").value;\n' +
    '  if (pw.length < 10) { setMsg("msg", "Password must be at least 10 characters.", false); return; }\n' +
    '  const btn = document.getElementById("go");\n' +
    '  if (btn.disabled) return;\n' +
    '  btn.disabled = true;\n' +
    '  setMsg("msg", "");\n' +
    '  let navigated = false;\n' +
    '  try {\n' +
    '    const r = await postJSON("/Market-Tracker/acct/register", {\n' +
    '      email: document.getElementById("email").value.trim(), password: pw });\n' +
    '    if (r.ok) { navigated = true; afterAuth(); return; }\n' +
    '    setMsg("msg", errText(r.j, "Could not create the account — that email may already be registered."), false);\n' +
    '  } catch (e) { setMsg("msg", "Could not reach the account service — try again in a moment.", false); }\n' +
    '  finally { if (!navigated) btn.disabled = false; }\n' +
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
    '  const btn = document.getElementById("go");\n' +
    '  if (btn.disabled) return;\n' +
    '  btn.disabled = true;\n' +
    '  let navigated = false;\n' +
    '  try {\n' +
    '    const r = await postJSON("/Market-Tracker/acct/reset", { token: TOKEN, password: pw });\n' +
    '    if (r.ok) { navigated = true; setMsg("msg", "Password updated — taking you to sign in…", true);\n' +
    '      setTimeout(() => { location.href = "/Market-Tracker/acct/sign-in"; }, 900); return; }\n' +
    '    setMsg("msg", errText(r.j, "That reset link did not work — it may have expired. Request a fresh one."), false);\n' +
    '  } catch (e) { setMsg("msg", "Could not reach the account service — try again in a moment.", false); }\n' +
    '  finally { if (!navigated) btn.disabled = false; }\n' +
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
    '<div class="plan"><div class="price">$0.99</div><div class="per">1-week trial, then $14.99/month</div>' +
    '<p class="small mut">A full week of the complete tracker for under a dollar. Renews at $14.99/month unless you cancel.</p>' +
    '<button class="btn" id="btnTrial" type="button">Start 1-week trial — $0.99</button>' +
    '<p class="small mut" style="margin:6px 0 0">All <a href="https://auth.rivaleclipse.dev/acct/no-refunds-policy">sales are final</a>.</p></div>' +
    '<div class="plan"><div class="price">$14.99<span class="per">/month</span></div><div class="per">Full access, billed monthly</div>' +
    '<p class="small mut">Every coin, every horizon, alerts and forecast schedules. Cancel anytime.</p>' +
    '<button class="btn violet" id="btnSub" type="button">Subscribe — $14.99/mo</button>' +
    '<p class="small mut" style="margin:6px 0 0">All <a href="https://auth.rivaleclipse.dev/acct/no-refunds-policy">sales are final</a>.</p></div>' +
    '</div>' +
    '<button class="btn ghost" id="btnPortal" type="button" style="display:none">Manage subscription / payment method</button>' +
    '</div>' +
    '<div class="card wide"><h2>Have a promo or referral code?</h2>' +
    '<p class="mut small">Promo codes unlock a free week, a free month, or lifetime access — no card needed to redeem. A referral code gives you a free month.</p>' +
    '<form id="promoForm"><label for="code">Promo or referral code</label>' +
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
  // Kalshi is NOT proxied here: the Pages edge cannot reach Kalshi's
  // hosts reliably (intermittent edge-generated 502s, verified
  // 2026-10-28). The engine service serves GET /api/perp/kalshi
  // instead, which rides the standard /api/perp/* proxy above.
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

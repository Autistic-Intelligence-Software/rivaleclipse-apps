// GIF-2-QR proxy — serves the GIF-to-QR converter under
// app.rivaleclipse.dev/GIF-2-QR/ WITHOUT moving its project.
//
// The converter stays in its own Cloudflare Pages project
// (gif-to-qr-converter, canonical origin https://customqr.rivaleclipse.dev,
// which keeps working untouched). This function forwards every
// /GIF-2-QR/* request to the same path on the converter origin and
// rewrites any redirect Location that points back at the converter
// origin so the visitor stays under /GIF-2-QR/.
//
// The converter page talks to its entitlement worker
// (qr-converter-entitlement.workers.dev) directly from the browser, so
// that worker's PAGES_ORIGIN allowlist includes
// https://app.rivaleclipse.dev (added via the Cloudflare API when this
// route launched — that is the origin-trust mechanism, no header
// spoofing is involved anywhere in this proxy).
const UPSTREAM = 'https://customqr.rivaleclipse.dev';

export async function onRequest(context) {
  const { request, params } = context;
  const url = new URL(request.url);
  let rest = params.path || '';
  if (Array.isArray(rest)) rest = rest.join('/');
  const target = UPSTREAM + (rest ? '/' + rest : '/') + url.search;

  const headers = new Headers(request.headers);
  headers.set('host', 'customqr.rivaleclipse.dev');
  headers.set('x-forwarded-host', url.host);
  headers.set('x-forwarded-proto', 'https');

  const init = { method: request.method, headers, redirect: 'manual' };
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = request.body;
    init.duplex = 'half';
  }

  const res = await fetch(target, init);

  const out = new Headers(res.headers);
  const loc = out.get('location');
  if (loc) {
    try {
      const l = new URL(loc, target);
      if (l.origin === UPSTREAM) {
        l.protocol = 'https:';
        l.host = url.host;
        l.pathname = '/GIF-2-QR' + (l.pathname === '/' ? '/' : l.pathname);
        out.set('location', l.toString());
      }
    } catch { /* leave the header as-is */ }
  }
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: out,
  });
}

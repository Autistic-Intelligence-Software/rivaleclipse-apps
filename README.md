# rivaleclipse-apps

Source for **app.rivaleclipse.dev** (Cloudflare Pages, git-connected to this repo).

- `index.html` — the web-apps landing page (portal style).
- `Market-Tracker/` — the Perpetual Helper web app. Built by
  `~/workspace/crypto-perp-helper/web/build_web.py` and pushed here by
  `push_apps.py` in that folder (the pipeline moved off the demos repo
  on 2026-10-27). `perpetual-helper.apk` sits beside it.
- `GIF-2-QR` — no static files: `functions/GIF-2-QR/[[path]].js` proxies
  to the converter's own Pages project (customqr.rivaleclipse.dev,
  which keeps working as an alias). The entitlement worker's
  `PAGES_ORIGIN` allowlist includes https://app.rivaleclipse.dev.
- `_redirects` — lowercase → capitalized path redirects
  (/market-tracker → /Market-Tracker, /gif-2-qr → /GIF-2-QR) and the
  converter's root /terms + /privacy links.

<!-- deploy trigger: project created 2026-10-27 -->

<!-- deploy note 2026-10-28: Market-Tracker Android download is now perp-alerts.apk (Perp Alerts & Forecasts); the old tracker APK was removed. -->

<!-- WEB10 redeploy trigger 2026-10-28 -->

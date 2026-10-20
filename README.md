# HAR Sanitizer (Chrome extension + CLI)

Local-first HAR redaction. No network, no host permissions, only `storage` (your settings).

## Load the extension
chrome://extensions → Developer mode → Load unpacked → select this folder.
- First install opens a welcome page (3-step guide). Toolbar icon → full-tab sanitizer (drop a .har, or try the built-in sample).
- DevTools → "HAR Sanitizer" tab → capture-time redaction. Click a row to review values (Keep / Always redact), then **Share-ready ✓**: stop, leak-check, verdict, download.
- Over-redaction slider (Readable / Balanced / Thorough) in the panel and the app. Balanced skips random-string guessing inside fonts, images, CSS and JS.
- Site profiles remember preset, level and rules per website; WordPress and Stripe starter rules are suggested automatically.
- Memory limit (25/50/100/200 MB, default 50) with a live size meter; recording stops at the limit.
- `app/local.html` = "Prove it's local" page (permissions, CSP `connect-src 'none'`, live blocked-request test).

## CLI (same engine)
    node bin/har-sanitize.mjs in.har -p strict --report r.txt --fail-on-leak
    HAR_SANITIZER_PASSPHRASE=… node bin/har-sanitize.mjs in.har --mapping map.enc.json
Exit codes: 0 ok · 1 error · 2 leak check found leftovers (with --fail-on-leak) · 64 bad usage.

## Layout
- `src/engine.js`  pure engine (also Node) · `src/worker.js` per-file worker · `src/capture.js` live capture
- `src/restore.js` encrypted mapping + restore · `src/summary.js` Markdown/curl/fetch/audit
- `app/` full-tab UI (review, diff, safety verdict) · `devtools/` panel · `bin/` CLI
- `tests/` → `node tests/run.mjs` (54 tests, planted-secrets corpus)
- `npm run package` → `dist/har-sanitizer-extension-v<version>.zip` (extension files only)

## Links
Outbound links live in `src/brand.js` (`SITE`, `HAR_VIEWER_URL`, `SOURCE_URL`). Plain links only: no analytics, no query strings.

## Not done yet
Store listing, privacy policy, screenshots (Phase 6); Release 3 linking. Real-Chrome DevTools panel test is manual (automated tests use a mocked DevTools API).

## License
MIT (see `LICENSE`). `vendor/fflate.js` is [fflate](https://github.com/101arrowz/fflate) by Arjun Barrett, also MIT.

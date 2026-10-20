# Chrome Web Store listing: HAR Sanitizer

**Name:** HAR Sanitizer — Redact Secrets Locally
**Category:** Developer Tools
**Short description (≤132 chars, this is the manifest text):**
Redact cookies, tokens, passwords and personal data from HAR files before you share them. 100% local — nothing is ever uploaded.

## Detailed description
Sharing a HAR file with support, a vendor or a forum usually means sharing your session cookies, API tokens and passwords with it. HAR Sanitizer removes them first, on your device.

**Record and redact in DevTools.** Open DevTools, click the "HAR Sanitizer" tab and use the page. Requests appear already redacted; the raw values are never saved. Click any request to see what was redacted and choose Keep or Always redact. Then press "Share-ready": it stops recording, re-scans the result for leftover secrets, shows a clear verdict and downloads the file.

**Or sanitize a file you already have.** Click the toolbar icon, drop in a .har file and download the cleaned version, plus an optional report, summary and audit log.

**What it redacts:** cookies, Authorization and API-key headers, URL parameters, form and JSON body fields, JWTs, cloud and payment keys, card numbers, emails, IP addresses, URL credentials, and random-looking tokens.

**You control the trade-off.** An over-redaction slider (Readable, Balanced, Thorough) decides how hard it guesses. Balanced leaves fonts, images, CSS and JS readable instead of blanking build hashes.

**Built for repeat use:** per-site profiles, WordPress and Stripe starter rules, shareable team rules, restorable encrypted mappings.

**Local only, and provably so.** One permission (storage, for your settings). No website access. The browser itself blocks every outgoing connection from the extension. The "Prove it's local" page shows this live.

## Keywords to work into the text
HAR sanitizer, redact HAR file, remove cookies from HAR, HAR file privacy, sanitize network log, DevTools HAR, HAR secrets, HAR redaction, share HAR safely

## Single-purpose statement
Redacts sensitive data from HAR (network recording) files, either as requests are recorded in DevTools or from a file the user opens.

## Permission justifications
- **storage:** saves the user's settings (preset, level, rules, site profiles, panel size limit) on their device. HAR contents are never written to storage.
- **devtools_page (not a permission, but declare it):** adds the "HAR Sanitizer" panel to DevTools to redact requests as they are recorded.
- **Host permissions:** none requested. **Remote code:** none. **Data collection:** none.

## Privacy practices tab
Data collected: none. Check all three certifications (no sale, no unrelated use, no creditworthiness use). Privacy policy URL: host `PRIVACY.md` as a page on your site and paste the URL.

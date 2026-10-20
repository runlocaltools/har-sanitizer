import { SOURCE_URL } from '../src/brand.js';
const $ = (id) => document.getElementById(id);
const m = chrome.runtime.getManifest();
const WHY = { storage: 'Saves your settings (preset, level, rules, site profiles) on this device. HAR contents are never written to storage.' };
const perms = (m.permissions || []).concat(m.optional_permissions || []);
const hosts = (m.host_permissions || []).concat(m.optional_host_permissions || []);
$('permCount').textContent = String(perms.length + hosts.length);
$('hostPerm').textContent = hosts.length ? 'Host access: ' + hosts.join(', ') : 'Host access: none. It cannot read or change any website.';
const tb = $('permTable');
const row = (a, b) => { const tr = document.createElement('tr'); [a, b].forEach((t) => { const td = document.createElement('td'); td.textContent = t; tr.append(td); }); tb.append(tr); };
perms.forEach((p) => row(p, WHY[p] || 'Declared in manifest.json'));
hosts.forEach((h) => row(h, 'Host permission'));
if (!perms.length && !hosts.length) row('(none)', '');
row('DevTools page', 'Adds the “HAR Sanitizer” tab to DevTools. The recorded requests stay in that panel’s memory.');
const ext = performance.getEntriesByType('resource').filter((r) => !/^(chrome-extension|moz-extension|blob|data):/.test(r.name));
$('extCount').textContent = String(ext.length);
const csp = (m.content_security_policy && m.content_security_policy.extension_pages) || '';
$('csp').textContent = csp || '(default)';
$('blocked').textContent = /connect-src\s+'none'/.test(csp) ? '0' : '?';
$('probe').addEventListener('click', async () => {
  $('probeOut').textContent = 'Trying…';
  try { await fetch('https://example.com/', { mode: 'no-cors', cache: 'no-store' }); $('probeOut').textContent = '⚠ The request was NOT blocked. Please report this.'; }
  catch (e) { $('probeOut').textContent = '✓ Blocked by the browser (' + (e && e.name || 'error') + '). Nothing was sent.'; }
});
if (SOURCE_URL) { const s = $('source'); s.hidden = false; const a = document.createElement('a'); a.href = SOURCE_URL; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = 'View the source ↗'; s.append(a); }

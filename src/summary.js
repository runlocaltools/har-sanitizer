// Shareable outputs built from a SANITIZED log: Markdown summary, curl, fetch.
const SKIP_HDR = new Set(['content-length', 'host', 'connection', 'accept-encoding', 'priority', 'te', 'upgrade']);
const q = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
const hdrs = (e) => (e.request.headers || []).filter((h) => h && h.name && !String(h.name).startsWith(':') && !SKIP_HDR.has(String(h.name).toLowerCase()));

export function toCurl(e) {
  const r = e.request, m = (r.method || 'GET').toUpperCase();
  const lines = ['curl' + (m !== 'GET' ? ' -X ' + m : '') + ' ' + q(r.url)];
  hdrs(e).forEach((h) => lines.push('-H ' + q(h.name + ': ' + h.value)));
  if (r.postData && typeof r.postData.text === 'string' && r.postData.text) lines.push('--data-raw ' + q(r.postData.text));
  return lines.join(' \\\n  ');
}
export function toFetch(e) {
  const r = e.request, init = { method: (r.method || 'GET').toUpperCase() };
  const h = {}; hdrs(e).forEach((x) => { h[x.name] = x.value; });
  if (Object.keys(h).length) init.headers = h;
  if (r.postData && typeof r.postData.text === 'string' && r.postData.text) init.body = r.postData.text;
  return 'await fetch(' + JSON.stringify(r.url) + ', ' + JSON.stringify(init, null, 2) + ');';
}

const pathOf = (u) => { try { const x = new URL(u); return x.host + x.pathname + (x.search ? '?…' : ''); } catch { return String(u).slice(0, 80); } };
const ms = (n) => (n >= 1000 ? (n / 1000).toFixed(2) + ' s' : Math.round(n) + ' ms');
const kb = (n) => (n > 0 ? (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB') : '—');

export function toMarkdownSummary(log, info = {}) {
  const E = log.entries || [];
  const L = ['# Network capture summary', '', '_Sanitized HAR — secrets and personal data redacted locally._', ''];
  const total = E.reduce((a, e) => a + Math.max(0, e.time || 0), 0);
  const bytes = E.reduce((a, e) => a + Math.max(0, (e.response && e.response.content && e.response.content.size) || 0), 0);
  L.push(`- **Requests:** ${E.length}`, `- **Total time (sum):** ${ms(total)}`, `- **Response bytes:** ${kb(bytes)}`);
  if (info.stats) { const n = Object.values(info.stats).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0); if (n) L.push(`- **Values redacted:** ${n}`); }
  const byStatus = {}; E.forEach((e) => { const k = e.response && e.response.status ? String(Math.floor(e.response.status / 100)) + 'xx' : 'failed'; byStatus[k] = (byStatus[k] || 0) + 1; });
  L.push(`- **By status:** ${Object.entries(byStatus).map(([k, v]) => k + ' × ' + v).join(', ')}`, '');
  const bad = E.map((e, i) => ({ e, i })).filter(({ e }) => !e.response || !e.response.status || e.response.status >= 400);
  L.push('## Failed or error responses', '');
  if (!bad.length) L.push('None.', '');
  else { L.push('| # | Method | Status | URL |', '|---|---|---|---|'); bad.slice(0, 50).forEach(({ e, i }) => L.push(`| ${i + 1} | ${e.request.method} | ${e.response.status || 'failed'} ${e.response.statusText || ''} | \`${pathOf(e.request.url)}\` |`)); if (bad.length > 50) L.push(`\n…and ${bad.length - 50} more.`); L.push(''); }
  const slow = E.map((e, i) => ({ e, i })).sort((a, b) => (b.e.time || 0) - (a.e.time || 0)).slice(0, 10);
  L.push('## Slowest requests', '', '| # | Time | Method | URL |', '|---|---|---|---|');
  slow.forEach(({ e, i }) => L.push(`| ${i + 1} | ${ms(e.time || 0)} | ${e.request.method} | \`${pathOf(e.request.url)}\` |`));
  const hosts = {}; E.forEach((e) => { try { const h = new URL(e.request.url).host; hosts[h] = (hosts[h] || 0) + 1; } catch { /* ignore */ } });
  L.push('', '## Hosts', '', ...Object.entries(hosts).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([h, n]) => `- \`${h}\` — ${n}`), '');
  return L.join('\n');
}

/** Audit record: proves what was done without containing any values. */
export async function auditRecord(info, cfg, inputBytes, outputBytes) {
  const hex = async (u8) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', u8))].map((b) => b.toString(16).padStart(2, '0')).join('');
  const clean = JSON.parse(JSON.stringify(cfg)); delete clean.keepValues;
  return { tool: 'HAR Sanitizer', version: '0.1', time: new Date().toISOString(), file: info.name,
    inputSha256: inputBytes ? await hex(inputBytes) : null, outputSha256: outputBytes ? await hex(outputBytes) : null,
    entries: { before: info.entriesBefore, after: info.entriesAfter }, redactions: info.stats, dropped: info.dropped || {},
    leakCheck: info.residual ? { remaining: info.residual.total } : null, preset: cfg.preset, style: cfg.style,
    settingsSha256: await hex(new TextEncoder().encode(JSON.stringify(clean))), valuesKeptByUser: String(cfg.keepValues || '').split(/\r?\n/).filter(Boolean).length,
    note: 'Contains counts and hashes only — no secret values.' };
}

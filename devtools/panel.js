import { createCapture } from '../src/capture.js';
import { DEF } from '../src/engine.js';
import { evaluateSafety } from '../app/safety.js';
import { flattenEntry, annotate, mask } from '../src/inspect.js';
import { LEVELS, LEVEL_INFO, levelIndex, addRule, matchStarter, STARTERS, mergePatch, effectiveCfg, withProfile, withoutProfile, siteKey, limitState, LIMIT_CHOICES_MB, DEFAULT_LIMIT_MB, fmtBytes } from '../src/rules.js';
import { makeSampleHar } from '../src/sample.js';
import { HAR_VIEWER_URL } from '../src/brand.js';

const $ = (id) => document.getElementById(id);
const net = chrome.devtools.network;
const MAX_ROWS = 300;
const S = { cap: null, recording: true, global: {}, profiles: {}, host: '', cfg: {}, limitMB: DEFAULT_LIMIT_MB, verdictVer: null, verdictAt: 0, stopped: '', skipped: 0, dismissed: [], selected: -1, capCfgJson: '', busy: false };
const tbody = document.querySelector('#list tbody');

/* ---------- state from storage ---------- */
async function loadState() {
  try {
    const r = await chrome.storage.local.get(['cfg', 'profiles', 'panelLimitMB']);
    S.global = r.cfg || {}; S.profiles = r.profiles || {}; if (LIMIT_CHOICES_MB.includes(r.panelLimitMB)) S.limitMB = r.panelLimitMB;
  } catch { /* defaults */ }
  recompute();
}
const hasProfile = () => !!(S.host && S.profiles[siteKey(S.host)]);
function recompute() { S.cfg = effectiveCfg(S.global, S.profiles, S.host); drawCfg(); }
async function persist(cfgNew, scope, starterId) {
  if (scope === 'site' && S.host) { S.profiles = withProfile(S.profiles, S.host, cfgNew, starterId); await chrome.storage.local.set({ profiles: S.profiles }); }
  else { S.global = cfgNew; await chrome.storage.local.set({ cfg: cfgNew }); }
  recompute(); checkReapply();
}
function inspectedHost() {
  return new Promise((res) => { try { chrome.devtools.inspectedWindow.eval('location.hostname', (r, ex) => res(ex || typeof r !== 'string' ? '' : r)); } catch { res(''); } });
}
async function refreshHost() { S.host = await inspectedHost(); recompute(); }

/* ---------- capture ---------- */
const scopeHosts = () => $('scope').value.split(/[,\s]+/).map((s) => s.trim().toLowerCase().replace(/^\*?\./, '')).filter(Boolean);
function inScope(url) {
  const hs = scopeHosts(); if (!hs.length) return true;
  let h = ''; try { h = new URL(url).hostname.toLowerCase(); } catch { return false; }
  return hs.some((s) => h === s || h.endsWith('.' + s));
}
function newCapture() {
  S.cap = createCapture(S.cfg); S.capCfgJson = JSON.stringify(S.cap.cfg);
  S.verdictVer = null; S.selected = -1; S.stopped = ''; S.skipped = 0;
  tbody.textContent = ''; $('verdict').hidden = true; $('detail').hidden = true; drawBanner(); render();
}
function addRow(e, n, idx) {
  const tr = document.createElement('tr'); tr.dataset.i = idx;
  const cell = (t, cls) => { const td = document.createElement('td'); td.textContent = t; if (cls) td.className = cls; tr.append(td); return td; };
  cell(e.request.method || ''); cell(String(e.response.status || ''), e.response.status >= 400 || !e.response.status ? 'err' : '');
  const u = cell(e.request.url || '', 'url'); u.title = e.request.url || '';
  cell(n ? String(n) : '—', n ? 'hit' : '');
  tr.addEventListener('click', () => select(idx));
  tbody.prepend(tr);
  while (tbody.rows.length > MAX_ROWS) tbody.deleteRow(tbody.rows.length - 1);
}
function ingest(raw, rawSize) {
  const before = S.cap.redactions;
  const e = S.cap.add(raw, rawSize);
  if (e) addRow(e, S.cap.redactions - before, S.cap.count - 1);
  if (S.cap.version !== S.verdictVer) markStale();
  checkLimit(); suggestStarter(raw && raw.request && raw.request.url); render();
}
function handle(req) {
  if (!S.recording || !req || !req.request || !inScope(req.request.url)) return;
  if (S.stopped) { S.skipped++; render(); return; }
  const text = JSON.stringify(req), raw = JSON.parse(text); // plain copy; the live Request object is never retained
  const finish = (body, enc) => {
    let size = text.length;
    if (typeof body === 'string') { raw.response = raw.response || {}; raw.response.content = Object.assign({}, raw.response.content, { text: body }); if (enc) raw.response.content.encoding = enc; size += body.length; }
    ingest(raw, size);
  };
  try { req.getContent((body, enc) => finish(body, enc)); } catch { finish(null); }
}
net.onRequestFinished.addListener(handle);
net.onNavigated.addListener(async () => { await refreshHost(); if (!$('keep').checked || !S.cap.count) newCapture(); else checkReapply(); });

function importExisting() {
  net.getHAR((log) => {
    (log.entries || []).forEach((en) => {
      if (!inScope(en.request && en.request.url) || S.stopped) return;
      const text = JSON.stringify(en), raw = JSON.parse(text);
      const done = (body, enc) => { let size = text.length; if (typeof body === 'string') { raw.response.content = Object.assign({}, raw.response.content, { text: body }); if (enc) raw.response.content.encoding = enc; size += body.length; } ingest(raw, size); };
      if (typeof en.getContent === 'function') en.getContent(done); else done(null);
    });
  });
}

/* ---------- limits ---------- */
function checkLimit() {
  const st = limitState(S.cap.bytes, S.limitMB);
  if (st === 'full' && !S.stopped) { S.stopped = 'limit'; S.recording = false; syncRec(); }
  drawBanner();
}

/* ---------- drawing ---------- */
function render() {
  const c = S.cap; if (!c) return;
  $('nCap').textContent = c.count; $('nRed').textContent = c.redactions;
  $('nDrop').textContent = Object.values(c.dropped).reduce((a, b) => a + b, 0);
  $('size').textContent = fmtBytes(c.bytes);
  const pct = Math.min(100, (c.bytes / (S.limitMB * 1048576)) * 100), st = limitState(c.bytes, S.limitMB);
  $('meterFill').style.width = pct + '%'; $('meterFill').parentElement.className = 'm-' + st;
  $('share').disabled = c.count === 0 || S.busy; $('empty').hidden = c.count > 0;
}
function drawCfg() {
  const l = S.cfg.level || DEF.level;
  $('level').value = levelIndex(l); $('levelName').textContent = LEVEL_INFO[l].label; $('levelHint').textContent = LEVEL_INFO[l].hint;
  const h = siteKey(S.host);
  $('site').textContent = !h ? 'Site: unknown' : hasProfile() ? 'Profile: ' + h : 'Site: ' + h + ' (no profile)';
  $('site').className = 'pill' + (hasProfile() ? ' ok' : '');
  $('saveProfile').hidden = !h; $('saveProfile').textContent = hasProfile() ? 'Update site profile' : 'Save site profile';
  $('delProfile').hidden = !hasProfile();
}
function syncRec() {
  $('rec').classList.toggle('on', S.recording); $('rec').setAttribute('aria-pressed', String(S.recording));
  $('recLabel').textContent = S.recording ? 'Recording' : (S.stopped ? 'Stopped (limit)' : 'Paused');
}
function banner(kind, text, actions) {
  const b = $('banner'); b.hidden = false; b.className = 'banner ' + kind; b.textContent = '';
  const t = document.createElement('span'); t.textContent = text; b.append(t);
  (actions || []).forEach(([label, fn]) => { const x = document.createElement('button'); x.textContent = label; x.addEventListener('click', fn); b.append(x); });
}
function drawBanner() {
  const st = S.cap ? limitState(S.cap.bytes, S.limitMB) : 'ok';
  if (S.stopped === 'limit') return banner('bad', 'Recording stopped: the capture reached ' + S.limitMB + ' MB' + (S.skipped ? ' (' + S.skipped + ' later request(s) were not captured)' : '') + '. Share it now, or Clear and continue. You can raise the limit above.', [['Share-ready ✓', shareReady]]);
  if (st === 'warn') return banner('warn', 'The capture is at ' + fmtBytes(S.cap.bytes) + ', close to the ' + S.limitMB + ' MB limit. Recording will stop automatically at the limit.');
  if (S.needReapply) return banner('info', S.reapplyMsg || 'Settings changed. They apply to new requests; re-apply to redo what is already captured.', [['Re-apply', reapply]]);
  if (S.suggest) return banner('info', 'Looks like ' + S.suggest.label + '. Add starter rules for it to this site’s profile?', [['Add starter rules', applyStarter], ['Not now', () => { S.dismissed.push(S.suggest.id); S.suggest = null; drawBanner(); }]]);
  $('banner').hidden = true;
}
function checkReapply() {
  if (!S.cap) return;
  const differs = JSON.stringify(effectiveCfg(S.global, S.profiles, S.host)) !== JSON.stringify(S.cap.cfg);
  if (differs && !S.cap.count) { newCapture(); return; }
  S.needReapply = differs; drawBanner();
}
async function reapply() {
  S.needReapply = false; S.reapplyMsg = ''; newCapture(); S.recording = true; syncRec(); importExisting();
}

/* ---------- live leak-check bar ---------- */
function markStale() {
  const v = $('verdict'); if (v.hidden || v.dataset.stale === '1') return;
  v.dataset.stale = '1'; v.className = 'verdict stale';
  v.textContent = 'Leak check is out of date: new requests arrived after it ran. ';
  const b = document.createElement('button'); b.textContent = 'Re-check'; b.addEventListener('click', () => runCheck(false)); v.append(b);
}
function showVerdict(safety, out) {
  const v = $('verdict'); v.hidden = false; v.dataset.stale = ''; S.verdictVer = S.cap.version;
  v.className = 'verdict ' + (safety.level === 'good' ? 'ok' : safety.level === 'bad' ? 'bad' : 'warn'); v.textContent = '';
  const head = document.createElement('b'); head.textContent = (safety.level === 'good' ? '✓ ' : safety.level === 'bad' ? '⚠ ' : '● ') + safety.label;
  const left = out.residual.total;
  const sub = document.createElement('span'); sub.textContent = ' — ' + S.cap.redactions + ' value(s) redacted in ' + S.cap.count + ' request(s)' + (left ? '; ' + left + ' possible leftover(s) found' : '; the re-scan found nothing high-confidence') + '.';
  v.append(head, sub);
  if (safety.reasons.length) { const ul = document.createElement('ul'); ul.className = 'why'; safety.reasons.forEach((r) => { const li = document.createElement('li'); li.className = r.l; li.textContent = r.t; ul.append(li); }); v.append(ul); }
  return v;
}
function download(text) {
  const d = new Date(), p = (n) => String(n).padStart(2, '0');
  const stamp = d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes());
  const site = S.cfg.hosts && S.cfg.hosts.mode === 'pseudo' ? 'capture' : (siteKey(S.host).replace(/[^a-z0-9.-]/g, '_') || 'capture'); // masked hosts must not leak into the file name
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  a.download = site + '-' + stamp + '.sanitized.har'; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}
async function runCheck(doDownload) {
  if (S.busy || !S.cap.count) return;
  S.busy = true; render(); $('verdict').hidden = false; $('verdict').className = 'verdict stale'; $('verdict').textContent = 'Checking for leftover secrets…';
  try {
    const out = await S.cap.finish();
    const safety = evaluateSafety(S.cap.cfg, out.info);
    const v = showVerdict(safety, out);
    const dl = (label) => { const b = document.createElement('button'); b.textContent = label; b.className = 'primary'; b.addEventListener('click', () => { download(out.text); }); v.append(' ', b); };
    if (doDownload) {
      if (safety.level === 'bad') { const m = document.createElement('p'); m.textContent = 'Not downloaded automatically. Review the leftovers (or raise the over-redaction level and Re-apply) first.'; v.append(m); dl('Download anyway'); }
      else { download(out.text); const m = document.createElement('span'); m.textContent = ' Downloaded. '; v.append(m); }
      const a = document.createElement('a'); a.href = HAR_VIEWER_URL; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = 'Open in HAR Viewer ↗'; a.title = 'Opens in a new tab. Drag the downloaded file into it.'; v.append(' ', a);
    }
  } catch (e) { $('verdict').className = 'verdict bad'; $('verdict').textContent = 'Check failed: ' + (e && e.message || e); }
  S.busy = false; render();
}
function shareReady() { S.recording = false; syncRec(); runCheck(true); }

/* ---------- row review + redact-by-example ---------- */
function select(i) {
  S.selected = i; [...tbody.rows].forEach((r) => r.classList.toggle('sel', +r.dataset.i === i));
  const e = S.cap.entryAt(i); if (!e) return;
  $('detail').hidden = false; $('dTitle').textContent = (e.request.method || '') + ' ' + String(e.request.url || '').slice(0, 120);
  drawDetail();
}
function drawDetail() {
  const e = S.cap.entryAt(S.selected); if (!e) return;
  const q = $('dFilter').value.toLowerCase(), only = $('dOnly').checked;
  const rows = annotate(flattenEntry(e), S.cap.recsOf(S.selected)).filter((r) => (!only || r.redacted) && (!q || (r.w + ' ' + r.n + ' ' + r.v).toLowerCase().includes(q)));
  const box = $('dList'); box.textContent = '';
  rows.sort((a, b) => b.redacted - a.redacted).slice(0, 200).forEach((r) => {
    const row = document.createElement('div'); row.className = 'vrow' + (r.redacted ? ' red' : '');
    const w = document.createElement('span'); w.className = 'w'; w.textContent = r.w + ' · ' + r.n; w.title = r.w + ' · ' + r.n;
    const v = document.createElement('code'); v.textContent = r.v.length > 120 ? r.v.slice(0, 120) + '…' : r.v; v.title = r.v;
    row.append(w, v);
    if (r.redacted) {
      const o = document.createElement('span'); o.className = 'orig'; o.textContent = 'was ' + r.originals.map(mask).join(', '); row.append(o);
      const b = document.createElement('button'); b.textContent = 'Keep'; b.title = 'Never redact this value'; b.addEventListener('click', () => saveRule('never', r.originals)); row.append(b);
    } else {
      const b = document.createElement('button'); b.textContent = 'Always redact'; b.addEventListener('click', () => saveRule('always', [r.v])); row.append(b);
    }
    box.append(row);
  });
  if (!rows.length) { const p = document.createElement('p'); p.className = 'hint'; p.textContent = only ? 'Nothing was redacted in this request.' : 'No values match.'; box.append(p); }
}
async function saveRule(kind, values) {
  let cfgNew = effectiveCfg(S.global, S.profiles, S.host), last = '';
  for (const v of values) { const r = addRule(cfgNew, kind, v); if (!r.ok) { banner('warn', r.msg); return; } cfgNew = r.cfg; last = r.msg; }
  await persist(cfgNew, $('dScope').value === 'site' && S.host ? 'site' : 'all');
  S.needReapply = true; S.reapplyMsg = 'Rule saved. ' + last + ' Re-apply redoes the requests DevTools still holds.'; drawBanner();
}

/* ---------- levels, profiles, starters ---------- */
$('level').addEventListener('input', () => { const l = LEVELS[+$('level').value]; $('levelName').textContent = LEVEL_INFO[l].label; $('levelHint').textContent = LEVEL_INFO[l].hint; });
$('level').addEventListener('change', async () => {
  const l = LEVELS[+$('level').value]; const c = Object.assign({}, effectiveCfg(S.global, S.profiles, S.host), { level: l });
  await persist(c, hasProfile() ? 'site' : 'all'); S.needReapply = !!S.cap.count; S.reapplyMsg = 'Level set to ' + LEVEL_INFO[l].label + '. Re-apply to redo what is already captured.'; drawBanner();
});
$('saveProfile').addEventListener('click', async () => { await persist(effectiveCfg(S.global, S.profiles, S.host), 'site'); banner('info', 'Saved a profile for ' + siteKey(S.host) + ': preset, level and rules will load automatically when you open DevTools on this site.'); });
$('delProfile').addEventListener('click', async () => { S.profiles = withoutProfile(S.profiles, S.host); await chrome.storage.local.set({ profiles: S.profiles }); recompute(); checkReapply(); });
function suggestStarter(url) {
  if (S.suggest || !S.host) return;
  const p = S.profiles[siteKey(S.host)]; const s = matchStarter(url, S.dismissed.concat((p && p.starters) || []));
  if (s) { S.suggest = s; drawBanner(); }
}
async function applyStarter() {
  const s = S.suggest; S.suggest = null; if (!s) return;
  const merged = mergePatch(effectiveCfg(S.global, S.profiles, S.host), s.patch);
  await persist(merged, 'site', s.id); S.needReapply = !!S.cap.count; S.reapplyMsg = s.label + ' starter rules saved to this site’s profile. Re-apply to redo what is already captured.'; drawBanner();
}

/* ---------- wiring ---------- */
LIMIT_CHOICES_MB.forEach((m) => { const o = document.createElement('option'); o.value = m; o.textContent = m + ' MB'; $('limit').append(o); });
$('limit').addEventListener('change', async () => {
  S.limitMB = +$('limit').value; try { await chrome.storage.local.set({ panelLimitMB: S.limitMB }); } catch { /* ignore */ }
  if (S.stopped === 'limit' && limitState(S.cap.bytes, S.limitMB) !== 'full') { S.stopped = ''; S.recording = true; syncRec(); }
  drawBanner(); render();
});
$('rec').addEventListener('click', () => { if (S.stopped) { S.stopped = ''; } S.recording = !S.recording; if (S.recording && S.cap && limitState(S.cap.bytes, S.limitMB) === 'full') { S.recording = false; S.stopped = 'limit'; } syncRec(); drawBanner(); });
$('clear').addEventListener('click', async () => { await loadState(); newCapture(); S.recording = true; syncRec(); });
$('import').addEventListener('click', importExisting);
$('share').addEventListener('click', shareReady);
$('sample').addEventListener('click', () => makeSampleHar().log.entries.forEach((en) => ingest(JSON.parse(JSON.stringify(en)), JSON.stringify(en).length)));
$('settings').addEventListener('click', () => window.open(chrome.runtime.getURL('app/app.html'), '_blank'));
$('dClose').addEventListener('click', () => { $('detail').hidden = true; S.selected = -1; [...tbody.rows].forEach((r) => r.classList.remove('sel')); });
$('dFilter').addEventListener('input', drawDetail); $('dOnly').addEventListener('change', drawDetail);
chrome.storage.onChanged.addListener((ch, area) => {
  if (area !== 'local' || !(ch.cfg || ch.profiles)) return;
  if (ch.cfg) S.global = ch.cfg.newValue || {}; if (ch.profiles) S.profiles = ch.profiles.newValue || {};
  recompute(); if (S.cap) { const d = JSON.stringify(effectiveCfg(S.global, S.profiles, S.host)) !== JSON.stringify(S.cap.cfg); if (d && S.cap.count) { S.needReapply = true; S.reapplyMsg = 'Settings changed. Re-apply to redo what is already captured.'; drawBanner(); } else checkReapply(); }
});

(async function boot() { await Promise.all([loadState(), refreshHost()]); $('limit').value = S.limitMB; newCapture(); syncRec(); })();

import { zipSync, strToU8 } from '../vendor/fflate.js';
import { engine, DEF, PRESETS, CATS, deepMerge, deepClone, sumStats } from '../src/engine.js';
import { createReview } from './review.js';
import { evaluateSafety } from './safety.js';
import { encryptMapping, decryptMapping, restoreHar } from '../src/restore.js';
import { LEVELS, LEVEL_INFO, levelIndex } from '../src/rules.js';
import { makeSampleHar } from '../src/sample.js';
import { HAR_VIEWER_URL } from '../src/brand.js';

const AUTO_MAX = 8 * 1024 * 1024;
const $ = (id) => document.getElementById(id);
const el = (tag, attrs, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
  }
  kids.flat().forEach((c) => c != null && n.append(c.nodeType ? c : document.createTextNode(c)));
  return n;
};
const fmtBytes = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
const baseName = (n) => String(n || 'capture').replace(/\.(har|json)$/i, '').replace(/[\\/:*?"<>|]/g, '_') || 'capture';

/* ---------- storage (settings only; HAR contents are never persisted) ---------- */
const store = {
  async get() { try { const r = await chrome.storage.local.get('cfg'); return r.cfg || {}; } catch { try { return JSON.parse(localStorage.getItem('cfg') || '{}'); } catch { return {}; } } },
  async set(v) { try { await chrome.storage.local.set({ cfg: v }); } catch { try { localStorage.setItem('cfg', JSON.stringify(v)); } catch { /* ignore */ } } }
};

/* ---------- settings schema ---------- */
const C = (p, label, hint) => ({ t: 'chk', p, label, hint });
const S = (p, label, opts) => ({ t: 'sel', p, label, opts });
const T = (p, label, ph, rows) => ({ t: 'txt', p, label, ph, rows });
const N = (p, label, min, max, step) => ({ t: 'num', p, label, min, max, step });
const SECTIONS = [
  ['1 · Credentials', true, [
    C('cookies.on', 'Cookie values', 'request/response cookies, Cookie and Set-Cookie headers'),
    S('cookies.mode', 'Cookie handling', [['redact', 'Redact the value (keep the name)'], ['remove', 'Remove cookies entirely']]),
    T('cookies.keep', 'Cookie names to keep (one per line)', '_ga\nlang'),
    C('headers.on', 'Sensitive headers', 'Authorization, X-API-Key, CSRF, signatures…'),
    C('headers.heur', 'Also catch headers whose name looks sensitive'),
    T('headers.names', 'Extra header names to redact', 'x-company-session'), T('headers.keep', 'Header names to keep', 'x-request-id'),
    C('params.on', 'URL query parameters', 'token, key, signature, password, OAuth, AWS X-Amz-*…'),
    C('params.heur', 'Also catch parameter names that look sensitive'),
    C('params.frag', 'Treat #fragment as parameters', 'OAuth implicit-flow tokens'),
    T('params.names', 'Extra parameter names to redact', 'ticket_id'), T('params.keep', 'Parameter names to keep', 'code\nstate'),
    C('creds', 'URL credentials', 'user:password@ in URLs'),
    C('body.keys', 'Sensitive fields in bodies', 'JSON, form-encoded and multipart, by field name'),
    C('body.heur', 'Also catch field names that look sensitive'),
    C('body.pii', 'Also redact personal fields', 'email, phone, names, address, DOB, username…'),
    T('body.extra', 'Extra field names to redact (any depth)', 'loyalty_number'),
    T('body.paths', 'Key paths to redact', 'user.profile.nick\norders.*.card\n**.internalNote')]],
  ['2 · Pattern detectors', false, [
    C('det.jwt', 'JWTs'), C('det.apikeys', 'Cloud / API keys', 'AWS, GitHub, Slack, Stripe, Google, OpenAI…'), C('det.pem', 'Private keys (PEM)'),
    C('det.bearer', 'Bearer / Basic credentials'), C('det.card', 'Card numbers', 'Luhn-checked'), C('det.email', 'Email addresses'),
    C('det.ipv4', 'IPv4 addresses'), C('det.ipv6', 'IPv6 addresses'), C('det.phone', 'Phone numbers'), C('det.ssn', 'SSN-style numbers'),
    C('det.ids', 'Account / resource IDs', 'UUIDs, Stripe-style ids (cus_…), AWS account numbers in ARNs'),
    C('det.keepPrivate', 'Keep private / loopback IPs'),
    C('det.entropy', 'High-entropy strings (heuristic)', 'long random-looking values — may over-redact'),
    N('det.entropyMin', 'Entropy threshold (lower = more aggressive)', 3, 6, 0.1),
    C('body.embed', 'Clean URLs found inside text bodies')]],
  ['3 · Hosts and entries', false, [
    S('hosts.mode', 'Hostnames', [['keep', 'Keep hostnames'], ['pseudo', 'Mask hostnames (host-1.invalid…)']]),
    T('hosts.keep', 'Hosts to keep unmasked', 'api.mycompany.com'), T('hosts.drop', 'Drop all entries to these hosts', 'ads.example.net'),
    C('hosts.trackers', 'Drop known tracker / analytics hosts'),
    C('filt.options', 'Drop OPTIONS (CORS preflight) entries'), C('filt.failed', 'Drop failed / aborted requests'),
    C('filt.dropImages', 'Drop image entries'), C('filt.dropFonts', 'Drop font entries'), C('filt.dropMedia', 'Drop audio / video entries'),
    T('filt.urlSubs', 'Drop entries whose URL contains…', '/internal/\nhealthcheck')]],
  ['4 · Bodies and files', false, [
    C('body.dropReq', 'Remove ALL request bodies'), C('body.dropUploads', 'Remove uploaded file contents'),
    C('body.dropTypes.images', 'Remove image bodies'), C('body.dropTypes.fonts', 'Remove font bodies'),
    C('body.dropTypes.media', 'Remove audio / video bodies'), C('body.dropTypes.binary', 'Remove other binary bodies'),
    C('body.dropTypes.all', 'Remove ALL response bodies', 'keeps timings, headers and status')]],
  ['5 · Metadata cleanup', false, [
    C('meta.serverIp', 'Remove server IP addresses'), C('meta.connection', 'Remove connection IDs'), C('meta.creator', 'Replace browser / creator info'),
    C('meta.pageTitles', 'Anonymise page titles'), C('meta.comments', 'Remove comment fields'), C('meta.vendor', 'Remove browser-specific "_" fields'),
    C('meta.ua', 'Redact User-Agent headers'), C('meta.dataUris', 'Shorten large data: URIs'),
    C('meta.shift', 'Shift all timestamps by one random offset', 'relative timing preserved')]],
  ['6 · Your own rules', false, [
    T('literals', 'Text to redact everywhere (one per line, case-insensitive)', 'Acme Corporation\njsmith', 4),
    T('regexes', 'Regular expressions (one per line, optional /pattern/flags)', 'ORD-\\d{6}\n/employee[_-]?id=\\w+/i', 4),
    { t: 'problems' },
    T('keepValues', 'Values to KEEP (never redact, one per line)', 'support@mycompany.com\npk_test_public123', 3)]],
  ['7 · Output', false, [C('pretty', 'Pretty-print the sanitized .har', 'larger file, easier to read')]]
];
const PRESET_LIST = [['support', 'Support'], ['strict', 'Strict'], ['secrets', 'Secrets only'], ['pub', 'Public']];
const PRESET_HINT = {
  support: 'Balanced: removes credentials and secrets, keeps hostnames so engineers can debug.',
  strict: 'Maximum privacy: masks hosts, removes cookies, PII, binary bodies and metadata.',
  secrets: 'Only credentials and keys. Keeps emails, IPs and hosts as they are.',
  pub: 'For posting publicly: masks hosts and PII, drops media and trackers.'
};
const STYLE_LIST = [['placeholder', '[EMAIL_1]'], ['hash', '[EMAIL:a1b2]'], ['fixed', '[REDACTED]']];

const getP = (o, p) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
const setP = (o, p, v) => { const ks = p.split('.'); let a = o; ks.slice(0, -1).forEach((k) => { a = a[k] = a[k] || {}; }); a[ks[ks.length - 1]] = v; };

/* ---------- state ---------- */
let cfg = deepMerge(DEF, {});
const files = [];
let seq = 0, runTimer = null, saveTimer = null;

function saveSoon() { clearTimeout(saveTimer); saveTimer = setTimeout(() => store.set(cfg), 300); }

/* ---------- settings UI ---------- */
function renderSettings() {
  const root = $('settings'); root.textContent = '';
  for (const [title, open, ctls] of SECTIONS) {
    const d = el('details', { class: 'sec' }, el('summary', { text: title }));
    if (open) d.open = true;
    for (const c of ctls) {
      if (c.t === 'problems') { d.append(el('div', { class: 'problems', id: 'problems' })); continue; }
      const val = getP(cfg, c.p);
      if (c.t === 'chk') {
        const i = el('input', { type: 'checkbox' }); i.checked = !!val;
        i.addEventListener('change', () => { setP(cfg, c.p, i.checked); changed(); });
        d.append(el('div', { class: 'ctl' }, el('label', {}, i, el('span', {}, c.label, c.hint ? el('div', { class: 'h', text: c.hint }) : null))));
      } else if (c.t === 'sel') {
        const s = el('select', {}, c.opts.map(([v, l]) => el('option', { value: v, text: l }))); s.value = val;
        s.addEventListener('change', () => { setP(cfg, c.p, s.value); changed(); });
        d.append(el('div', { class: 'field' }, el('label', { text: c.label }), s));
      } else if (c.t === 'txt') {
        const a = el('textarea', { rows: c.rows || 2, spellcheck: 'false', placeholder: c.ph || '' }); a.value = val || '';
        a.addEventListener('input', () => { setP(cfg, c.p, a.value); changed(); });
        d.append(el('div', { class: 'field' }, el('label', { text: c.label }), a));
      } else if (c.t === 'num') {
        const n = el('input', { type: 'number', min: c.min, max: c.max, step: c.step }); n.value = val;
        n.addEventListener('input', () => { const v = parseFloat(n.value); if (!isNaN(v)) { setP(cfg, c.p, v); changed(); } });
        d.append(el('div', { class: 'field' }, el('label', { text: c.label }), n));
      }
    }
    root.append(d);
  }
  updateProblems();
}
function renderSegs() {
  const mk = (mount, list, current, onPick) => {
    mount.textContent = '';
    list.forEach(([v, l]) => { const b = el('button', { type: 'button', 'aria-pressed': String(v === current), text: l }); b.addEventListener('click', () => onPick(v)); mount.append(b); });
  };
  mk($('presets'), PRESET_LIST, cfg.preset, applyPreset);
  mk($('styles'), STYLE_LIST, cfg.style, (v) => { cfg.style = v; renderSegs(); changed(); });
  $('presetHint').textContent = PRESET_HINT[cfg.preset] || '';
  renderLevel();
}
function renderLevel() {
  $('level').value = levelIndex(cfg.level); $('levelHint').textContent = LEVEL_INFO[LEVELS[levelIndex(cfg.level)]].hint;
}
$('level').addEventListener('input', () => { cfg.level = LEVELS[+$('level').value]; renderLevel(); changed(); });
function applyPreset(name) {
  const keep = { literals: cfg.literals, regexes: cfg.regexes, style: cfg.style, pretty: cfg.pretty };
  cfg = deepMerge(deepMerge(DEF, PRESETS[name] || {}), keep); cfg.preset = name;
  renderSegs(); renderSettings(); changed();
}
function updateProblems() {
  const box = $('problems'); if (!box) return;
  const r = engine.parseCustomRegexes(cfg.regexes || '');
  box.textContent = r.problems.map((p) => 'Line ' + p.line + ': ' + p.msg).join('\n');
  box.style.whiteSpace = 'pre-wrap';
}
function changed() { updateProblems(); saveSoon(); scheduleRun(); }

/* ---------- file cards ---------- */
function addCard(rec) {
  const status = el('div', { class: 'meta', text: 'Queued…' });
  const bar = el('div', { class: 'bar' }, el('i'));
  rec.ui = { card: el('div', { class: 'card' }), status, bar, body: el('div') };
  const rm = el('button', { class: 'x', title: 'Remove', 'aria-label': 'Remove file', text: '×' });
  rm.addEventListener('click', () => { rec.worker.terminate(); files.splice(files.indexOf(rec), 1); rec.ui.card.remove(); refreshZip(); });
  rec.ui.card.append(el('div', { class: 'row' }, el('div', {}, el('div', { class: 'fname', text: rec.name }), el('div', { class: 'meta', text: fmtBytes(rec.size) })), rm), status, bar, rec.ui.body);
  $('files').prepend(rec.ui.card);
}
function setStatus(rec, text, pct) {
  rec.ui.status.textContent = text;
  rec.ui.bar.hidden = pct == null;
  if (pct != null) rec.ui.bar.firstChild.style.width = Math.round(pct * 100) + '%';
}
const chip = (label, n) => el('span', { class: 'chip' }, label, el('b', { text: String(n) }));
function download(blob, name) {
  const a = el('a', { href: URL.createObjectURL(blob), download: name }); document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

const toast = (msg) => { const n = $('note'); n.hidden = false; n.textContent = msg; clearTimeout(toast.t); toast.t = setTimeout(() => { n.hidden = true; }, 3500); };
const keptSet = () => new Set(String(cfg.keepValues || '').split(/\r?\n/).map((x) => x.trim()).filter(Boolean));
function setKept(set) { cfg.keepValues = [...set].join('\n'); renderSettings(); changed(); }
const reviewHelpers = {
  cats: CATS, toast, getCfg: () => deepClone(cfg), getKept: keptSet,
  keep: (v) => { const k = keptSet(); k.add(v); setKept(k); },
  unkeep: (v) => { const k = keptSet(); k.delete(v); k.delete(String(v).toLowerCase()); setKept(k); }
};
async function gzipBlob(blob) {
  if (typeof CompressionStream === 'undefined') throw new Error('Compression is not supported in this browser.');
  return new Response(blob.stream().pipeThrough(new CompressionStream('gzip'))).blob();
}
function workerCall(rec, type, reply) { return new Promise((res) => { rec.on[reply] = (m) => { delete rec.on[reply]; res(m); }; rec.worker.postMessage({ type }); }); }

function renderResult(rec, msg) {
  const { info, mapping, report, blob } = msg;
  rec.result = { info, mapping, report, blob };
  const body = rec.ui.body; body.textContent = '';
  const total = sumStats(info.stats);
  const chips = el('div', { class: 'chips' });
  CATS.forEach((c) => { const n = info.stats[c[0]] || 0; if (n) chips.append(chip(c[1], n)); });
  [['kept', 'Kept by you'], ['hosts', 'Hostnames masked'], ['ua', 'User-Agents'], ['uploads', 'Uploads removed'], ['bodiesDropped', 'Response bodies removed'], ['reqBodiesDropped', 'Request bodies removed'], ['dataUris', 'data: URIs shortened']]
    .forEach(([k, l]) => { const n = info.stats[k] || 0; if (n) chips.append(chip(l, n)); });
  if (info.staticSkipped) chips.append(el('span', { class: 'chip', title: 'Fonts, images, CSS and JS: random-string guessing was skipped so they stay readable' }, 'Static files left readable', el('b', { text: String(info.staticSkipped) })));
  Object.keys(info.dropped || {}).forEach((k) => chips.append(chip('Entries dropped (' + k + ')', info.dropped[k])));
  if (!chips.childNodes.length) chips.append(el('span', { class: 'meta', text: 'Nothing matched — check that the preset fits this file.' }));

  const left = info.residual ? info.residual.total : 0;
  rec.ui.card.classList.toggle('leak', left > 0);
  const safety = evaluateSafety(cfg, info);
  const verdict = el('div', { class: 'verdict ' + (safety.level === 'good' ? 'ok' : safety.level === 'bad' ? 'bad' : 'warn') },
    el('b', { text: (safety.level === 'good' ? '✓ ' : safety.level === 'bad' ? '⚠ ' : '● ') + safety.label }),
    el('span', { text: ' — ' + total + ' value(s) redacted' + (left ? '; ' + left + ' possible leftover(s)' : '; leak check re-scanned the output and found nothing high-confidence') + '.' }),
    safety.reasons.length ? el('ul', { class: 'why' }, safety.reasons.map((r) => el('li', { class: r.l, text: r.t }))) : null);

  const actions = el('div', { class: 'actions' });
  const dl = el('button', { class: 'primary', style: 'width:auto;margin:0', text: 'Download sanitized .har (' + fmtBytes(info.sizeAfter) + ')' });
  dl.addEventListener('click', () => download(blob, baseName(rec.name) + '.sanitized.har'));
  const mk = (label, fn) => { const b = el('button', { type: 'button', text: label }); b.addEventListener('click', async () => { try { await fn(); } catch (e) { toast(e.message || String(e)); } }); return b; };
  const gz = mk('.har.gz', async () => download(await gzipBlob(blob), baseName(rec.name) + '.sanitized.har.gz'));
  const rp = mk('Report', () => download(new Blob([report], { type: 'text/plain' }), baseName(rec.name) + '.report.txt'));
  const sm = mk('Summary (.md)', async () => { const m = await workerCall(rec, 'summary', 'summary'); download(new Blob([m.text], { type: 'text/markdown' }), baseName(rec.name) + '.summary.md'); });
  const au = mk('Audit log', async () => { const m = await workerCall(rec, 'audit', 'audit'); download(new Blob([JSON.stringify(m.record, null, 2)], { type: 'application/json' }), baseName(rec.name) + '.audit.json'); });
  const mapBox = el('div', { class: 'mapbox', hidden: '' });
  const pass = el('input', { type: 'password', placeholder: 'Passphrase (8+ characters)', autocomplete: 'new-password' });
  const go = mk('Encrypt & download', async () => {
    const f = await encryptMapping(mapping, pass.value, { file: rec.name });
    download(new Blob([f], { type: 'application/json' }), baseName(rec.name) + '.mapping.enc.json'); pass.value = ''; mapBox.hidden = true;
  });
  mapBox.append(el('div', { class: 'hint', text: 'The mapping holds the REAL secrets next to their placeholders. It is encrypted with your passphrase (AES-256-GCM). Keep it private; lose the passphrase and it cannot be recovered.' }), el('div', { class: 'actions' }, pass, go));
  const mp = mk('Restorable mapping…', () => { if (!mapping.length) throw new Error('No mapping to export — the "[REDACTED]" style does not keep one.'); mapBox.hidden = !mapBox.hidden; });
  const vw = el('a', { class: 'btnlink', href: HAR_VIEWER_URL, target: '_blank', rel: 'noopener noreferrer', text: 'Open in HAR Viewer ↗', title: 'Opens in a new tab. Download the file first, then drag it into the viewer.' });
  vw.addEventListener('click', () => toast('Drag the downloaded .sanitized.har file into the viewer. Files cannot be passed through a link.'));
  actions.append(dl, gz, rp, sm, au, mp, vw);

  const ta = el('textarea', { rows: 3, spellcheck: 'false', placeholder: 'Paste known secrets here (one per line)…' });
  const out = el('div', { class: 'meta' });
  const chk = el('button', { text: 'Check output' });
  chk.addEventListener('click', () => {
    const secrets = ta.value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
    if (!secrets.length) return;
    out.textContent = 'Checking…'; rec.pendingCheck = (results) => {
      const bad = results.filter((r) => r.count > 0);
      out.textContent = bad.length ? '⚠ ' + bad.length + ' of ' + results.length + ' still present — first at: ' + bad.map((b) => b.where).join(', ') : '✓ None of the ' + results.length + ' pasted value(s) appear in the sanitized file.';
    };
    rec.worker.postMessage({ type: 'check', secrets });
  });
  const ver = el('details', { class: 'verify' }, el('summary', { text: 'Verify: is a specific secret still in the output?' }), ta, el('div', { class: 'actions' }, chk), out);

  const wasOpen = !!(rec.review && rec.review.open);
  rec.review = createReview(rec, reviewHelpers);
  if (wasOpen) rec.review.open = true;
  body.append(chips, verdict, actions, mapBox, rec.review, ver);
  setStatus(rec, info.entriesBefore + ' → ' + info.entriesAfter + ' entries · ' + fmtBytes(info.sizeBefore) + ' → ' + fmtBytes(info.sizeAfter), null);
  refreshZip();
}

/* ---------- processing ---------- */
function startFile(file) {
  const rec = { id: ++seq, name: file.name || 'capture.har', size: file.size, result: null, on: {} };
  rec.worker = new Worker(new URL('../src/worker.js', import.meta.url), { type: 'module' });
  files.push(rec); addCard(rec);
  rec.worker.onmessage = (ev) => {
    const m = ev.data;
    if (m.type === 'progress') setStatus(rec, m.label, m.pct);
    else if (m.type === 'done') renderResult(rec, m);
    else if (m.type === 'checked') rec.pendingCheck && rec.pendingCheck(m.results);
    else if (rec.on[m.type]) rec.on[m.type](m);
    else if (m.type === 'error') { setStatus(rec, 'Could not process this file.', null); rec.ui.body.textContent = ''; rec.ui.body.append(el('div', { class: 'err', text: m.message })); }
  };
  rec.worker.onerror = (e) => { setStatus(rec, 'Worker failed.', null); rec.ui.body.append(el('div', { class: 'err', text: e.message || 'Unexpected error' })); };
  rec.worker.postMessage({ type: 'load', file, cfg: deepClone(cfg) });
}
function scheduleRun() {
  clearTimeout(runTimer);
  runTimer = setTimeout(() => {
    files.forEach((rec) => {
      if (rec.size > AUTO_MAX && rec.result) { setStatus(rec, 'Settings changed — click Re-run to apply (large file).', null); addRerun(rec); }
      else rec.worker.postMessage({ type: 'run', cfg: deepClone(cfg) });
    });
  }, 450);
}
function addRerun(rec) {
  if (rec.ui.rerun) return;
  rec.ui.rerun = el('button', { text: 'Re-run' });
  rec.ui.rerun.addEventListener('click', () => { rec.ui.rerun.remove(); rec.ui.rerun = null; rec.worker.postMessage({ type: 'run', cfg: deepClone(cfg) }); });
  rec.ui.card.append(rec.ui.rerun);
}
function refreshZip() { $('zip').disabled = !files.some((f) => f.result); }

async function addFiles(list) {
  const arr = Array.from(list);
  if (files.length + arr.length > 12) { const n = $('note'); n.hidden = false; n.textContent = 'Many files at once can use a lot of memory — consider processing in batches.'; }
  arr.forEach(startFile);
}

/* ---------- wiring ---------- */
const dz = $('dz'), input = $('file');
dz.addEventListener('click', () => input.click());
dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
input.addEventListener('change', () => { addFiles(input.files); input.value = ''; });
['dragenter', 'dragover'].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.add('over'); }));
['dragleave', 'drop'].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.remove('over'); }));
dz.addEventListener('drop', (e) => addFiles(e.dataTransfer.files));
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => { e.preventDefault(); if (!dz.contains(e.target)) addFiles(e.dataTransfer.files); });

$('zip').addEventListener('click', () => {
  const entries = {};
  Promise.all(files.filter((f) => f.result).map(async (f) => {
    const b = baseName(f.name);
    entries[b + '.sanitized.har'] = new Uint8Array(await f.result.blob.arrayBuffer());
    entries[b + '.report.txt'] = strToU8(f.result.report);
  })).then(() => download(new Blob([zipSync(entries, { level: 6 })], { type: 'application/zip' }), 'sanitized-hars.zip'));
});
$('reset').addEventListener('click', async () => { cfg = deepMerge(DEF, {}); await store.set(cfg); renderSegs(); renderSettings(); changed(); });

/* ---------- restore originals ---------- */
$('restoreGo').addEventListener('click', async () => {
  const out = $('restoreOut'); out.textContent = '';
  try {
    const mf = $('restoreMap').files[0], hf = $('restoreHar').files[0];
    if (!mf || !hf) throw new Error('Choose both the encrypted mapping file and the sanitized HAR.');
    const { mappings } = await decryptMapping(await mf.text(), $('restorePass').value);
    const har = JSON.parse(await hf.text());
    download(new Blob([JSON.stringify(restoreHar(har, mappings))], { type: 'application/json' }), baseName(hf.name).replace(/\.sanitized$/, '') + '.restored.har');
    out.textContent = '✓ Restored ' + mappings.length + ' value(s). Handle the result as sensitive — it contains the original secrets again.';
  } catch (e) { out.textContent = '⚠ ' + (e.message || e); }
});

/* ---------- share / import rules ---------- */
$('rulesExport').addEventListener('click', () => {
  const r = deepClone(cfg); delete r.keepValues; // kept values are specific data, not rules
  download(new Blob([JSON.stringify({ format: 'har-sanitizer-rules', v: 1, rules: r }, null, 2)], { type: 'application/json' }), 'har-sanitizer-rules.json');
});
$('rulesImport').addEventListener('change', async (e) => {
  try {
    const j = JSON.parse(await e.target.files[0].text());
    if (!j || j.format !== 'har-sanitizer-rules' || typeof j.rules !== 'object') throw new Error('Not a HAR Sanitizer rules file.');
    const keep = cfg.keepValues; cfg = deepMerge(DEF, j.rules); cfg.keepValues = keep;
    if (!PRESETS[cfg.preset]) cfg.preset = 'support';
    renderSegs(); renderSettings(); changed(); toast('Rules imported.');
  } catch (err) { toast(err.message || 'Could not import rules.'); }
  e.target.value = '';
});

function loadSample() { const f = new File([JSON.stringify(makeSampleHar())], 'sample-with-fake-secrets.har', { type: 'application/json' }); startFile(f); }
$('sample').addEventListener('click', loadSample);

(async function boot() {
  cfg = deepMerge(DEF, await store.get());
  if (!PRESETS[cfg.preset]) cfg.preset = 'support';
  renderSegs(); renderSettings();
  if (/[?&]sample=1\b/.test(location.search)) loadSample();
})();

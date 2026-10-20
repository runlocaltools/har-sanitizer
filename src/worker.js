// One worker per file. Holds the parsed HAR so re-runs (after a settings change) don't re-parse.
import { runEngine, scanCfg, residualCfg, sumStats, checkSecrets, buildReport, DEF, CATS, deepMerge } from './engine.js';
import { toMarkdownSummary, auditRecord } from './summary.js';

let fileRef = null, lastRun = null, lastInfo = null, lastBlob = null, lastCfg = null, latestCfg = null, har = null, name = 'capture.har', size = 0, token = 0, lastLog = null;
const post = (m) => self.postMessage(m);

function parseHar(text) {
  const t = String(text).replace(/^﻿/, '');
  if (!t.trim()) throw new Error('This file is empty.');
  let j;
  try { j = JSON.parse(t); } catch (e) { throw new Error('This is not valid JSON (' + e.message + '). HAR files are JSON.'); }
  if (!j || typeof j !== 'object' || !j.log || typeof j.log !== 'object') throw new Error('This JSON has no "log" object, so it does not look like a HAR file.');
  if (!Array.isArray(j.log.entries)) throw new Error('This HAR has no "log.entries" list.');
  return j;
}

function randomSalt() {
  const r = new Uint32Array(2); crypto.getRandomValues(r);
  return { salt: r[0] | 0, shiftMs: -Math.floor((30 + (r[1] / 4294967296) * 335) * 86400000) };
}
const SALTS = randomSalt();

async function run(cfgIn) {
  const my = ++token, cancelled = () => token !== my;
  const cfg = deepMerge(DEF, cfgIn || {});
  const bar = (label) => (n, total) => post({ type: 'progress', label: label + ' ' + n + ' / ' + total, pct: total ? n / total : 0 });
  post({ type: 'progress', label: 'Sanitizing…', pct: 0 });
  const rr = await runEngine(har.log.entries, har.log, cfg, { salt: SALTS.salt, shiftMs: SALTS.shiftMs, onProgress: bar('Sanitizing'), isCancelled: cancelled });
  if (!rr) return;
  post({ type: 'progress', label: 'Checking result…', pct: 0 });
  const rs = await runEngine(rr.log.entries, rr.log, residualCfg(cfg), { collect: true, salt: SALTS.salt, onProgress: bar('Checking'), isCancelled: cancelled });
  if (!rs) return;
  lastLog = rr.log; lastRun = rr; lastCfg = cfg;
  const outText = JSON.stringify(Object.assign({}, har, { log: rr.log }), null, cfg.pretty ? 2 : 0);
  const blob = new Blob([outText], { type: 'application/json' }); lastBlob = blob;
  const residual = { total: sumStats(rs.ctx.stats), stats: rs.ctx.stats };
  const info = { name, entriesBefore: har.log.entries.length, entriesAfter: rr.log.entries.length, sizeBefore: size, sizeAfter: blob.size,
    style: cfg.style, stats: rr.ctx.stats, dropped: rr.dropped, residual, staticSkipped: rr.ctx.staticSkipped || 0 };
  lastInfo = info;
  post({ type: 'done', blob, info, mapping: rr.ctx.mapping, report: buildReport(info) });
}

self.onmessage = async (ev) => {
  const m = ev.data;
  try {
    if (m.type === 'load') {
      fileRef = m.file; name = m.file.name || 'capture.har'; size = m.file.size; latestCfg = m.cfg;
      post({ type: 'progress', label: 'Reading file…', pct: null });
      har = parseHar(await m.file.text());
      post({ type: 'loaded', entries: har.log.entries.length });
      await run(latestCfg);
    } else if (m.type === 'run') {
      latestCfg = m.cfg;
      if (har) await run(latestCfg); // if still loading, the load handler runs with the newest settings
    } else if (m.type === 'findings') {
      const cfg = deepMerge(DEF, m.cfg || latestCfg || {});
      const sr = await runEngine(har.log.entries, har.log, scanCfg(cfg), { findings: true, collect: false, salt: SALTS.salt });
      const data = {};
      CATS.forEach(([k]) => { const mp = sr.ctx.findings && sr.ctx.findings[k]; if (mp && mp.size) data[k] = [...mp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 60); });
      post({ type: 'findings', data });
    } else if (m.type === 'rows') {
      if (!lastRun) return;
      const rows = lastLog.entries.map((e, i) => {
        const raw = har.log.entries[lastRun.outIdx[i]];
        const a = JSON.stringify(raw), b = JSON.stringify(e);
        let n = 0; if (a !== b) { const mm = b.match(/\[(?:REDACTED|[A-Z]+[_:-][A-Za-z0-9]+)\]/g); n = mm ? mm.length : 1; }
        return { i, m: (e.request && e.request.method) || '', s: (e.response && e.response.status) || 0, u: String((e.request && e.request.url) || '').slice(0, 300), n, c: a !== b };
      });
      post({ type: 'rows', rows });
    } else if (m.type === 'entry') {
      if (!lastRun) return;
      const raw = har.log.entries[lastRun.outIdx[m.i]], out = lastLog.entries[m.i];
      post({ type: 'entry', i: m.i, before: JSON.stringify(raw, null, 2), after: JSON.stringify(out, null, 2), sanitized: out });
    } else if (m.type === 'summary') {
      post({ type: 'summary', text: toMarkdownSummary(lastLog, lastInfo || {}) });
    } else if (m.type === 'audit') {
      const inB = fileRef ? new Uint8Array(await fileRef.arrayBuffer()) : null, outB = lastBlob ? new Uint8Array(await lastBlob.arrayBuffer()) : null;
      post({ type: 'audit', record: await auditRecord(lastInfo || { name }, lastCfg || deepMerge(DEF, {}), inB, outB) });
    } else if (m.type === 'check') {
      const secrets = (m.secrets || []).filter(Boolean);
      post({ type: 'checked', results: lastLog ? await checkSecrets(lastLog, secrets) : [] });
    }
  } catch (e) {
    post({ type: 'error', message: (e && e.message) || String(e) });
  }
};

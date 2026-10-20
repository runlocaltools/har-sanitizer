// Capture-time redaction: raw entries go in, only sanitized entries are ever stored.
import { engine, DEF, deepMerge, residualCfg, runEngine, sumStats, buildReport } from './engine.js';

export function createCapture(cfgIn, opts = {}) {
  const maxBody = opts.maxBody == null ? 5 * 1024 * 1024 : opts.maxBody;
  let cfg, ctx, entries, metas, dropped, rawSeen, truncated, bytes, rawBytes, version;
  const rnd = () => { const r = new Uint32Array(2); (globalThis.crypto || {}).getRandomValues?.(r); return { salt: r[0] | 0, shiftMs: -Math.floor((30 + (r[1] / 4294967296) * 335) * 86400000) }; };
  let salts = rnd();

  function reset(newCfg) {
    cfg = deepMerge(DEF, newCfg || cfg || {});
    ctx = engine.makeCtx(cfg, { collect: false, salt: salts.salt, shiftMs: salts.shiftMs });
    entries = []; metas = []; dropped = {}; rawSeen = 0; truncated = 0; bytes = 0; rawBytes = 0; version = 0;
  }
  reset(cfgIn);

  /** Redact one entry as it arrives. rawSize = size of the entry before redaction (for honest before/after numbers).
   *  Returns the sanitized entry (or null if dropped by a rule). */
  function add(raw, rawSize) {
    rawSeen++; version++;
    const reason = engine.entryDropReason(raw, ctx.c);
    if (reason) { dropped[reason] = (dropped[reason] || 0) + 1; return null; }
    const clone = engine.cloneEntry(raw);
    delete clone.pageref;
    const ct = clone.response && clone.response.content;
    if (ct && typeof ct.text === 'string' && ct.text.length > maxBody) { ct.text = ''; ct.comment = 'body omitted: larger than ' + Math.round(maxBody / 1048576) + ' MB'; truncated++; }
    ctx.rec = [];
    try { engine.processEntry(clone, ctx); } finally { var recs = ctx.rec; ctx.rec = null; }
    const size = JSON.stringify(clone).length;
    bytes += size; rawBytes += typeof rawSize === 'number' && rawSize > 0 ? rawSize : size;
    entries.push(clone); metas.push({ recs, size });
    return clone;
  }

  function buildLog(creatorName) {
    const sorted = entries.slice().sort((a, b) => String(a.startedDateTime).localeCompare(String(b.startedDateTime)));
    return engine.processLog({ version: '1.2', creator: { name: creatorName || 'HAR Sanitizer', version: '0.2' }, pages: [], entries: sorted }, sorted, ctx);
  }

  /** Re-scan the finished output for anything that still looks like a secret. */
  async function leakCheck() {
    const log = buildLog();
    const rs = await runEngine(log.entries, log, residualCfg(cfg), { collect: true, salt: salts.salt });
    return { total: sumStats(rs.ctx.stats), stats: rs.ctx.stats };
  }

  async function finish(name) {
    const log = buildLog();
    const residual = await leakCheck();
    const text = JSON.stringify({ log }, null, cfg.pretty ? 2 : 0);
    const info = { name: name || 'devtools-capture.har', entriesBefore: rawSeen, entriesAfter: log.entries.length, sizeBefore: rawBytes, sizeAfter: text.length,
      style: cfg.style, stats: ctx.stats, dropped, residual, staticSkipped: ctx.staticSkipped || 0 };
    return { text, info, report: buildReport(info), residual, mapping: ctx.mapping };
  }
  return { add, reset, finish, leakCheck, recsOf: (i) => (metas[i] ? metas[i].recs : []), entryAt: (i) => entries[i],
    get count() { return entries.length; }, get seen() { return rawSeen; }, get dropped() { return dropped; }, get bytes() { return bytes; }, get rawBytes() { return rawBytes; },
    get version() { return version; }, get stats() { return ctx.stats; }, get redactions() { return sumStats(ctx.stats); }, get truncated() { return truncated; },
    get staticSkipped() { return ctx.staticSkipped || 0; }, get entries() { return entries; }, get cfg() { return cfg; } };
}

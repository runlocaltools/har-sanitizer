#!/usr/bin/env node
// HAR Sanitizer CLI — same engine as the extension. Fully offline.
import { readFile, writeFile } from 'node:fs/promises';
import { engine, runEngine, residualCfg, sumStats, buildReport, DEF, PRESETS, deepMerge } from '../src/engine.js';
import { encryptMapping } from '../src/restore.js';

const HELP = `har-sanitize <input.har> [options]

  -o, --out <file>         Output path (default: <input>.sanitized.har)
  -p, --preset <name>      support | strict | secrets | pub   (default: support)
  -s, --style <name>       placeholder | hash | fixed          (default: placeholder)
      --rules <file>       Rules JSON exported from the extension
      --keep <value>       Never redact this value (repeatable)
      --pretty             Pretty-print output
      --report <file>      Write a redaction report (counts only)
      --mapping <file>     Write an ENCRYPTED mapping (needs HAR_SANITIZER_PASSPHRASE)
      --fail-on-leak       Exit with code 2 if the leak check finds leftovers
  -q, --quiet              No summary output
  -h, --help`;

const args = process.argv.slice(2), opt = { keep: [] }; let input = null;
for (let i = 0; i < args.length; i++) {
  const a = args[i], nx = () => args[++i];
  if (a === '-h' || a === '--help') { console.log(HELP); process.exit(0); }
  else if (a === '-o' || a === '--out') opt.out = nx(); else if (a === '-p' || a === '--preset') opt.preset = nx();
  else if (a === '-s' || a === '--style') opt.style = nx(); else if (a === '--rules') opt.rules = nx(); else if (a === '--keep') opt.keep.push(nx());
  else if (a === '--pretty') opt.pretty = true; else if (a === '--report') opt.report = nx(); else if (a === '--mapping') opt.mapping = nx();
  else if (a === '--fail-on-leak') opt.fail = true; else if (a === '-q' || a === '--quiet') opt.quiet = true;
  else if (a.startsWith('-')) { console.error('Unknown option: ' + a + '\n\n' + HELP); process.exit(64); }
  else input = a;
}
if (!input) { console.error(HELP); process.exit(64); }
const die = (m, c = 1) => { console.error('har-sanitize: ' + m); process.exit(c); };

let cfg;
if (opt.rules) { try { cfg = deepMerge(DEF, JSON.parse(await readFile(opt.rules, 'utf8')).rules || {}); } catch (e) { die('cannot read rules: ' + e.message); } }
else {
  const p = opt.preset || 'support'; if (!PRESETS[p]) die('unknown preset "' + p + '"', 64);
  cfg = deepMerge(DEF, PRESETS[p]); cfg.preset = p;
}
if (opt.style) { if (!['placeholder', 'hash', 'fixed'].includes(opt.style)) die('unknown style', 64); cfg.style = opt.style; }
if (opt.pretty) cfg.pretty = true;
if (opt.keep.length) cfg.keepValues = [cfg.keepValues, ...opt.keep].filter(Boolean).join('\n');

let har;
try { har = JSON.parse((await readFile(input, 'utf8')).replace(/^﻿/, '')); } catch (e) { die('cannot read ' + input + ': ' + e.message); }
if (!har || !har.log || !Array.isArray(har.log.entries)) die('this does not look like a HAR file (no log.entries)');

const r32 = crypto.getRandomValues(new Uint32Array(2));
const salt = r32[0] | 0, shiftMs = -Math.floor((30 + (r32[1] / 4294967296) * 335) * 86400000);
const rr = await runEngine(har.log.entries, har.log, cfg, { salt, shiftMs });
const rs = await runEngine(rr.log.entries, rr.log, residualCfg(cfg), { collect: true, salt });
const residual = { total: sumStats(rs.ctx.stats), stats: rs.ctx.stats };
const text = JSON.stringify({ ...har, log: rr.log }, null, cfg.pretty ? 2 : 0);
const out = opt.out || input.replace(/\.(har|json)$/i, '') + '.sanitized.har';
await writeFile(out, text);
const info = { name: input, entriesBefore: har.log.entries.length, entriesAfter: rr.log.entries.length, sizeBefore: 0, sizeAfter: text.length, style: cfg.style, stats: rr.ctx.stats, dropped: rr.dropped, residual };
if (opt.report) await writeFile(opt.report, buildReport(info));
if (opt.mapping) {
  const pw = process.env.HAR_SANITIZER_PASSPHRASE; if (!pw) die('set HAR_SANITIZER_PASSPHRASE to write an encrypted mapping', 64);
  await writeFile(opt.mapping, await encryptMapping(rr.ctx.mapping, pw, { file: input }));
}
if (!opt.quiet) console.error(`Sanitized ${info.entriesBefore} → ${info.entriesAfter} entries, ${sumStats(rr.ctx.stats)} value(s) redacted → ${out}\nLeak check: ${residual.total ? residual.total + ' possible leftover(s)' : 'clean'}`);
process.exit(opt.fail && residual.total ? 2 : 0);

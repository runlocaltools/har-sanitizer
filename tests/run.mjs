import assert from 'node:assert/strict';
import { engine, runEngine, scanCfg, residualCfg, sumStats, checkSecrets, buildReport, DEF, PRESETS, deepMerge } from '../src/engine.js';
import { makeHar, SECRETS } from './corpus.mjs';

let pass = 0, fail = 0;
const t = async (name, fn) => { try { await fn(); pass++; console.log('  ok  ' + name); } catch (e) { fail++; console.log('FAIL  ' + name + '\n      ' + e.message); } };

const secretsList = Object.values(SECRETS);
for (const [pname, style] of [['support', 'placeholder'], ['strict', 'placeholder'], ['secrets', 'placeholder'], ['pub', 'hash'], ['support', 'fixed']]) {
  await t(`no planted secret survives: preset=${pname} style=${style}`, async () => {
    const har = makeHar();
    const cfg = deepMerge(DEF, PRESETS[pname]); cfg.style = style;
    const r = await runEngine(har.log.entries, har.log, cfg, { salt: 1 });
    const res = await checkSecrets(r.log, secretsList);
    // 'secrets' preset intentionally keeps emails and 'strict'/'pub' handle PII; email/card checked in all but 'secrets' for email
    const leaked = res.filter(x => x.count > 0 && !(pname === 'secrets' && x.secret === SECRETS.email)).map(x => x.secret + ' @ ' + x.where);
    assert.deepEqual(leaked, []);
  });
}
await t('input HAR is not mutated', async () => {
  const har = makeHar(); const before = JSON.stringify(har);
  await runEngine(har.log.entries, har.log, deepMerge(DEF, {}), { salt: 1 });
  assert.equal(JSON.stringify(har), before);
});
await t('structure preserved (entry count, methods, statuses)', async () => {
  const har = makeHar();
  const r = await runEngine(har.log.entries, har.log, deepMerge(DEF, {}), { salt: 1 });
  assert.equal(r.log.entries.length, har.log.entries.length);
  assert.deepEqual(r.log.entries.map(e => e.request.method), har.log.entries.map(e => e.request.method));
  assert.deepEqual(r.log.entries.map(e => e.response.status), har.log.entries.map(e => e.response.status));
});
await t('non-secret values are kept (page=2, lang=en, Accept header)', async () => {
  const har = makeHar();
  const r = await runEngine(har.log.entries, har.log, deepMerge(DEF, {}), { salt: 1 });
  const s = JSON.stringify(r.log);
  assert.ok(s.includes('page=2')); assert.ok(s.includes('"lang"')); assert.ok(s.includes('application/json'));
});
await t('same secret gets the same placeholder everywhere', async () => {
  const har = makeHar();
  const r = await runEngine(har.log.entries, har.log, deepMerge(DEF, {}), { salt: 1 });
  const e = r.log.entries[0];
  const inHeader = /session=(\[[A-Z_0-9]+\])/.exec(e.request.headers[0].value)[1];
  const inCookies = e.request.cookies[0].value;
  const inSetCookie = /session=(\[[A-Z_0-9]+\])/.exec(e.response.headers[0].value)[1];
  assert.equal(inHeader, inCookies); assert.equal(inHeader, inSetCookie);
});
await t('mapping lists originals (for the private mapping file)', async () => {
  const har = makeHar();
  const r = await runEngine(har.log.entries, har.log, deepMerge(DEF, {}), { salt: 1 });
  assert.ok(r.ctx.mapping.some(m => m.original === SECRETS.cookie));
});
await t('residual check on clean output finds nothing; on raw input finds leaks', async () => {
  const cfg = deepMerge(DEF, {});
  const har = makeHar();
  const raw = await runEngine(har.log.entries, har.log, residualCfg(cfg), { collect: true, salt: 1 });
  assert.ok(sumStats(raw.ctx.stats) > 5, 'raw leaks detected: ' + sumStats(raw.ctx.stats));
  const out = await runEngine(har.log.entries, har.log, cfg, { salt: 1 });
  const again = await runEngine(out.log.entries, out.log, residualCfg(cfg), { collect: true, salt: 1 });
  assert.equal(sumStats(again.ctx.stats), 0);
});
await t('custom literal and regex rules', async () => {
  const har = makeHar();
  har.log.entries[0].response.content.text = 'Acme internal ORD-123456 tenant-4411';
  const cfg = deepMerge(DEF, { literals: 'tenant-4411', regexes: 'ORD-\\d{6}' });
  const r = await runEngine(har.log.entries, har.log, cfg, { salt: 1 });
  const s = JSON.stringify(r.log);
  assert.ok(!s.includes('tenant-4411') && !s.includes('ORD-123456'));
});
await t('risky regex is rejected (ReDoS guard)', () => {
  const r = engine.parseCustomRegexes('(a+)+$');
  assert.equal(r.rules.length, 0); assert.equal(r.problems.length, 1);
});
await t('report contains counts and no secret values', async () => {
  const har = makeHar(); const cfg = deepMerge(DEF, {});
  const r = await runEngine(har.log.entries, har.log, cfg, { salt: 1 });
  const rep = buildReport({ name: 't.har', entriesBefore: 6, entriesAfter: r.log.entries.length, sizeBefore: 1, sizeAfter: 1, style: 'placeholder', stats: r.ctx.stats, dropped: r.dropped, residual: null });
  for (const s of secretsList) assert.ok(!rep.includes(s));
});
await t('hostname masking (strict) removes real hosts', async () => {
  const har = makeHar(); const cfg = deepMerge(DEF, PRESETS.strict);
  const r = await runEngine(har.log.entries, har.log, cfg, { salt: 1 });
  assert.ok(!JSON.stringify(r.log).includes('acmecorp.com'));
});
await t('tolerates malformed entries without throwing', async () => {
  const log = { version: '1.2', entries: [null, {}, { request: null }, { request: { url: 5, headers: 'x' }, response: {} }] };
  await runEngine(log.entries, log, deepMerge(DEF, {}), { salt: 1 });
});
// ---- capture-time redaction ----
const { createCapture } = await import('../src/capture.js');
await t('capture: streaming entries are sanitized on arrival, no secret ever stored', async () => {
  const cap = createCapture({});
  makeHar().log.entries.forEach((e) => { e.pageref = 'page_1'; cap.add(e); });
  assert.equal(cap.count, 6);
  assert.ok(cap.entries.every((e) => !('pageref' in e)));
  const res = await checkSecrets({ entries: cap.entries }, secretsList);
  assert.deepEqual(res.filter((x) => x.count > 0), []);
});
await t('capture: finish() gives valid HAR, clean leak check, report without secrets', async () => {
  const cap = createCapture({});
  makeHar().log.entries.forEach((e) => cap.add(e));
  const out = await cap.finish('x.har');
  const j = JSON.parse(out.text);
  assert.equal(j.log.entries.length, 6); assert.equal(out.residual.total, 0);
  for (const s of secretsList) assert.ok(!out.text.includes(s) && !out.report.includes(s));
});
await t('capture: rules drop entries (hosts.drop) and count them', async () => {
  const cap = createCapture({ hosts: { drop: 'cdn.acmecorp.com' } });
  makeHar().log.entries.forEach((e) => cap.add(e));
  assert.equal(cap.count, 5); assert.equal(cap.dropped.host, 1);
});
await t('capture: oversize bodies are omitted, not stored', async () => {
  const cap = createCapture({}, { maxBody: 100 });
  const e = makeHar().log.entries[0]; e.response.content.text = 'x'.repeat(500);
  cap.add(e);
  assert.equal(cap.entries[0].response.content.text, ''); assert.equal(cap.truncated, 1);
});
await t('capture: entries with functions (DevTools Request objects) are cloned safely', () => {
  const cap = createCapture({}); const e = makeHar().log.entries[0]; e.getContent = () => {};
  cap.add(e); assert.equal(cap.count, 1); assert.ok(!('getContent' in cap.entries[0]));
});
// ---- decoded layers, IDs, keep-values ----
const b64 = (x) => Buffer.from(x).toString('base64');
const runBody = async (text, cfgOver) => {
  const har = makeHar(); har.log.entries[0].response.content.text = text;
  const r = await runEngine(har.log.entries, har.log, deepMerge(DEF, cfgOver || {}), { salt: 1 });
  return r.log.entries[0].response.content.text;
};
await t('nested: JSON inside a JSON string is redacted', async () => {
  const out = await runBody(JSON.stringify({ payload: JSON.stringify({ password: 'NESTEDpw12345', note: 'hi' }) }));
  assert.ok(!out.includes('NESTEDpw12345')); assert.ok(out.includes('note'));
});
await t('nested: form data inside a JSON string is redacted', async () => {
  const out = await runBody(JSON.stringify({ body: 'user=a&password=FORMINSTR9999&x=1' }));
  assert.ok(!out.includes('FORMINSTR9999')); assert.ok(out.includes('user=a'));
});
await t('nested: base64-encoded JSON is redacted and stays decodable', async () => {
  const out = await runBody(JSON.stringify({ data: b64(JSON.stringify({ password: 'B64JSONpw12345', ok: 1 })) }));
  const inner = JSON.parse(Buffer.from(JSON.parse(out).data, 'base64').toString());
  assert.ok(!JSON.stringify(inner).includes('B64JSONpw12345')); assert.equal(inner.ok, 1);
});
await t('nested: ordinary strings with "=" or base64 are left alone', async () => {
  const text = JSON.stringify({ a: 'x=1', b: 'SGVsbG8gd29ybGQhIQ==', c: 'plain text value' });
  assert.equal(await runBody(text), text);
});
await t('ids: UUIDs, Stripe-style ids and AWS account ids are redacted when enabled', async () => {
  const text = JSON.stringify({ u: '3f2b8c1e-5a4d-4e7b-9c1a-2d3e4f5a6b7c', c: 'cus_Nf8a7b6c5d4e3', a: 'arn:aws:iam::123456789012:role/x' });
  const on = await runBody(text, { det: { ids: true } });
  assert.ok(!on.includes('3f2b8c1e') && !on.includes('cus_Nf8a7b') && !on.includes('123456789012'));
  assert.equal(await runBody(text, {}), text); // off by default
});
await t('keepValues: a kept value survives every detector; others are still redacted', async () => {
  const text = JSON.stringify({ contact: 'support@acmecorp.com', other: 'jane.doe@acmecorp.com', tok: 'AKIAIOSFODNN7EXAMPLE' });
  const out = await runBody(text, { keepValues: 'support@acmecorp.com\nAKIAIOSFODNN7EXAMPLE' });
  assert.ok(out.includes('support@acmecorp.com')); assert.ok(out.includes('AKIAIOSFODNN7EXAMPLE')); assert.ok(!out.includes('jane.doe@'));
});
await t('keepValues: works for header, cookie and query values too', async () => {
  const har = makeHar();
  const cfg = deepMerge(DEF, { keepValues: SECRETS.queryToken });
  const r = await runEngine(har.log.entries, har.log, cfg, { salt: 1 });
  assert.ok(r.log.entries[0].request.url.includes(SECRETS.queryToken));
  assert.ok(!JSON.stringify(r.log.entries[0].request.headers).includes(SECRETS.bearer));
});
// ---- restore / crypto / summary / curl ----
const { encryptMapping, decryptMapping, restoreHar } = await import('../src/restore.js');
const { toCurl, toFetch, toMarkdownSummary, auditRecord } = await import('../src/summary.js');
for (const style of ['placeholder', 'hash']) {
  await t(`restore: encrypt → decrypt → restore round-trips originals (style=${style})`, async () => {
    const har = makeHar(); const cfg = deepMerge(DEF, {}); cfg.style = style;
    const r = await runEngine(har.log.entries, har.log, cfg, { salt: 7 });
    const blob = await encryptMapping(r.ctx.mapping, 'correct horse battery');
    assert.ok(!blob.includes(SECRETS.cookie));
    const m = await decryptMapping(blob, 'correct horse battery');
    const back = restoreHar({ log: r.log }, m.mappings);
    const txt = JSON.stringify(back);
    for (const k of ['cookie', 'bearer', 'apiKeyHeader', 'queryToken', 'password', 'jwt', 'awsKey', 'clientSecret', 'formPass', 'gqlToken'])
      assert.ok(txt.includes(JSON.stringify(SECRETS[k]).slice(1, -1)) || txt.includes(encodeURIComponent(SECRETS[k])), 'not restored: ' + k);
  });
}
await t('restore: wrong passphrase and short passphrase are rejected', async () => {
  const blob = await encryptMapping([{ placeholder: 'A_1', original: 'x' }], 'long enough pass');
  await assert.rejects(() => decryptMapping(blob, 'wrong passphrase!'), /Wrong passphrase/);
  await assert.rejects(() => encryptMapping([], 'short'), /at least 8/);
});
await t('curl/fetch/markdown are built from sanitized entries and contain no secrets', async () => {
  const har = makeHar(); const r = await runEngine(har.log.entries, har.log, deepMerge(DEF, {}), { salt: 1 });
  const e = r.log.entries[1];
  const out = [toCurl(e), toFetch(e), toMarkdownSummary(r.log, { stats: r.ctx.stats })].join('\n');
  for (const s of secretsList) assert.ok(!out.includes(s), 'leaked ' + s);
  assert.ok(toCurl(e).startsWith('curl -X POST')); assert.ok(toFetch(e).includes('"method": "POST"')); assert.ok(out.includes('# Network capture summary'));
});
await t('audit record has hashes and counts but no secret values or kept values', async () => {
  const cfg = deepMerge(DEF, { keepValues: 'support@acmecorp.com' });
  const a = await auditRecord({ name: 'x.har', entriesBefore: 6, entriesAfter: 6, stats: { cookies: 5 }, residual: { total: 0 } }, cfg, new Uint8Array([1, 2, 3]), new Uint8Array([4]));
  const j = JSON.stringify(a);
  assert.ok(!j.includes('support@acmecorp.com')); assert.equal(a.inputSha256.length, 64); assert.equal(a.valuesKeptByUser, 1);
});
await t('findings collector returns exact values with counts', async () => {
  const har = makeHar(); const { scanCfg: sc } = await import('../src/engine.js');
  const r = await runEngine(har.log.entries, har.log, sc(deepMerge(DEF, {})), { findings: true, salt: 1 });
  assert.ok(r.ctx.findings.cookies.has(SECRETS.cookie)); assert.ok(r.ctx.findings.cookies.get(SECRETS.cookie) >= 3);
});
// ---- diff + safety ----
const { lineDiff, inlineSplit } = await import('../app/diff.js');
const { evaluateSafety } = await import('../app/safety.js');
await t('diff: pairs replaced lines and keeps equal ones', () => {
  const ops = lineDiff(['{', '  "a": "SECRET",', '  "b": 1', '}'], ['{', '  "a": "[X_1]",', '  "b": 1', '}']);
  assert.deepEqual(ops.map((o) => o.t), ['eq', 'chg', 'eq', 'eq']);
  const sp = inlineSplit('  "a": "SECRET",', '  "a": "[X_1]",'); assert.equal(sp.a[1], 'SECRET'); assert.equal(sp.b[1], '[X_1]');
});
await t('diff: handles removed and added lines', () => {
  const ops = lineDiff(['a', 'b', 'c'], ['a', 'c', 'd']).map((o) => o.t);
  assert.ok(ops.includes('del') || ops.includes('chg')); assert.equal(ops[0], 'eq');
});
await t('safety: levels and reasons', () => {
  const ok = evaluateSafety(deepMerge(DEF, {}), { stats: { cookies: 3 }, residual: { total: 0 } });
  assert.equal(ok.level, 'good');
  assert.equal(evaluateSafety(deepMerge(DEF, {}), { stats: { cookies: 3 }, residual: { total: 2 } }).level, 'bad');
  assert.equal(evaluateSafety(deepMerge(DEF, { cookies: { on: false } }), { stats: { cookies: 3 }, residual: { total: 0 } }).level, 'review');
  assert.equal(evaluateSafety(deepMerge(DEF, {}), { stats: {}, residual: { total: 0 } }).level, 'review');
});
// ---- CLI ----
const { spawnSync } = await import('node:child_process'); const fs = await import('node:fs'); const os = await import('node:os'); const path = await import('node:path');
await t('cli: sanitizes, honours --keep, writes report, --fail-on-leak exit codes', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-')); const inp = path.join(d, 'in.har'), out = path.join(d, 'out.har');
  fs.writeFileSync(inp, JSON.stringify(makeHar()));
  const r = spawnSync('node', [new URL('../bin/har-sanitize.mjs', import.meta.url).pathname, inp, '-o', out, '--report', path.join(d, 'r.txt'), '--keep', SECRETS.email, '--fail-on-leak', '-q']);
  assert.equal(r.status, 0, String(r.stderr));
  const o = fs.readFileSync(out, 'utf8');
  for (const s of secretsList) if (s !== SECRETS.email) assert.ok(!o.includes(s), 'leaked ' + s);
  assert.ok(o.includes(SECRETS.email)); assert.ok(fs.existsSync(path.join(d, 'r.txt')));
  assert.equal(spawnSync('node', [new URL('../bin/har-sanitize.mjs', import.meta.url).pathname, path.join(d, 'missing.har')]).status, 1);
  assert.equal(spawnSync('node', [new URL('../bin/har-sanitize.mjs', import.meta.url).pathname, inp, '--bogus']).status, 64);
});

/* ---------------- release 1 + 2 ---------------- */
import fs2 from 'node:fs';
import { makeSampleHar, SAMPLE_SECRETS, SAMPLE_HASH_IN_STATIC } from '../src/sample.js';
import { addRule, mergePatch, matchStarter, effectiveCfg, withProfile, withoutProfile, limitState, LEVELS } from '../src/rules.js';
import { flattenEntry, annotate } from '../src/inspect.js';

const san = async (level, har) => { har = har || makeSampleHar(); const r = await runEngine(har.log.entries, har.log, deepMerge(DEF, { level }), { salt: 1 }); return { r, s: JSON.stringify(r.log) }; };
await t('level: Balanced keeps build hashes in fonts/JS/CSS readable but still redacts API tokens', async () => {
  const { s, r } = await san('balanced');
  assert.ok(s.includes(SAMPLE_HASH_IN_STATIC)); assert.ok(s.includes('chunk-9fK2xQ7mVb3LpZr8TnA4.js')); assert.ok(s.includes('Zq8Xw3Lm9Pv2Tn7Kb4Rc6'));
  assert.ok(!s.includes(SAMPLE_SECRETS.queryToken)); assert.ok(!s.includes(SAMPLE_SECRETS.bearer)); assert.ok(r.ctx.staticSkipped >= 4);
});
await t('level: Thorough redacts random strings inside static files too', async () => {
  const { s } = await san('thorough');
  assert.ok(!s.includes(SAMPLE_HASH_IN_STATIC)); assert.ok(!s.includes('chunk-9fK2xQ7mVb3LpZr8TnA4'));
});
await t('level: Readable never guesses, yet name/pattern rules still catch every sample secret', async () => {
  const { s, r } = await san('readable');
  assert.ok(s.includes(SAMPLE_HASH_IN_STATIC));
  const res = await checkSecrets(r.log, Object.values(SAMPLE_SECRETS));
  assert.deepEqual(res.filter((x) => x.count > 0).map((x) => x.secret), []);
});
await t('level: ordering Readable <= Balanced <= Thorough in redactions; presets map to levels', async () => {
  const n = async (l) => sumStats((await san(l)).r.ctx.stats);
  const [a, b, c] = [await n('readable'), await n('balanced'), await n('thorough')]; assert.ok(a <= b && b <= c && a < c);
  assert.equal(PRESETS.strict.level, 'thorough'); assert.equal(PRESETS.secrets.level, 'readable'); assert.equal(DEF.level, 'balanced'); assert.deepEqual(LEVELS, ['readable', 'balanced', 'thorough']);
});
await t('static detection: by extension, by mime, and not for API paths', async () => {
  const e = (url, mime) => ({ request: { url }, response: { content: { mimeType: mime } } });
  assert.ok(engine.isStaticEntry(e('https://x.com/a/b.woff2?v=1')) && engine.isStaticEntry(e('https://x.com/api', 'image/png')) && engine.isStaticEntry(e('https://x.com/x', 'text/javascript')));
  assert.ok(!engine.isStaticEntry(e('https://x.com/api/me?token=1', 'application/json')));
});
await t('sample HAR: default sanitizing leaves no fake secret behind and passes the safety verdict', async () => {
  const har = makeSampleHar(); const { r } = await san('balanced', har);
  assert.deepEqual((await checkSecrets(r.log, Object.values(SAMPLE_SECRETS))).filter((x) => x.count > 0), []);
  const rs = await runEngine(r.log.entries, r.log, residualCfg(deepMerge(DEF, {})), { collect: true, salt: 1 });
  assert.equal(evaluateSafety(deepMerge(DEF, {}), { stats: r.ctx.stats, residual: { total: sumStats(rs.ctx.stats) } }).level, 'good');
});
await t('capture: sizeBefore is the real raw size (not 0), size grows, limit states', async () => {
  const c = createCapture({}); const es = makeSampleHar().log.entries; let raw = 0;
  es.forEach((e) => { const n = JSON.stringify(e).length; raw += n; c.add(e, n); });
  const out = await c.finish();
  assert.equal(out.info.sizeBefore, raw); assert.ok(out.info.sizeBefore > 0 && out.info.sizeAfter > 0); assert.ok(c.bytes > 0);
  assert.equal(limitState(10 * 1048576, 50), 'ok'); assert.equal(limitState(41 * 1048576, 50), 'warn'); assert.equal(limitState(50 * 1048576, 50), 'full');
});
await t('capture: version bumps per request so a stale leak-check can be detected', async () => {
  const c = createCapture({}); const v0 = c.version; c.add(makeSampleHar().log.entries[0], 10); assert.ok(c.version > v0);
});
await t('capture: records originals per entry (for Keep) and the sanitized output still hides them', async () => {
  const c = createCapture({}); c.add(makeSampleHar().log.entries[1], 100);
  const recs = c.recsOf(0); assert.ok(recs.some((r) => r.original === SAMPLE_SECRETS.bearer));
  assert.ok(!JSON.stringify(c.entryAt(0)).includes(SAMPLE_SECRETS.bearer));
  const rows = annotate(flattenEntry(c.entryAt(0)), recs);
  assert.ok(rows.some((r) => r.redacted && r.originals.includes(SAMPLE_SECRETS.bearer))); assert.ok(rows.some((r) => !r.redacted && r.n === 'page' && r.v === '2'));
});
await t('rules: Keep (never) and Always redact are saved as rules and take effect', async () => {
  const k = addRule({}, 'never', SAMPLE_SECRETS.queryToken); assert.ok(k.ok && k.cfg.keepValues.includes(SAMPLE_SECRETS.queryToken));
  const r1 = await runEngine(makeSampleHar().log.entries, makeSampleHar().log, k.cfg, { salt: 1 }); assert.ok(JSON.stringify(r1.log).includes(SAMPLE_SECRETS.queryToken));
  const a = addRule({}, 'always', 'Sample User'); assert.ok(a.ok);
  const r2 = await runEngine(makeSampleHar().log.entries, makeSampleHar().log, a.cfg, { salt: 1 }); assert.ok(!JSON.stringify(r2.log).includes('Sample User'));
  const flip = addRule(a.cfg, 'never', 'Sample User'); assert.ok(!flip.cfg.literals.includes('Sample User'));
  assert.equal(addRule({}, 'always', 'ab').ok, false); assert.equal(addRule({}, 'always', 'a\nb long').ok, false);
});
await t('profiles: save per site, effective cfg prefers the profile, remove restores global', async () => {
  const g = { level: 'readable' }; const prof = withProfile({}, 'www.Shop.example.com', deepMerge(DEF, { level: 'thorough' }), 'stripe');
  assert.equal(effectiveCfg(g, prof, 'shop.example.com').level, 'thorough'); assert.equal(effectiveCfg(g, prof, 'other.com').level, 'readable');
  assert.deepEqual(prof['shop.example.com'].starters, ['stripe']); assert.equal(effectiveCfg(g, withoutProfile(prof, 'shop.example.com'), 'shop.example.com').level, 'readable');
});
await t('starters: WordPress and Stripe detected; patches union lists and redact the nonce/client secret', async () => {
  assert.equal(matchStarter('https://blog.com/wp-json/wp/v2/posts').id, 'wordpress'); assert.equal(matchStarter('https://api.stripe.com/v1/payment_intents').id, 'stripe');
  assert.equal(matchStarter('https://x.com/api'), null); assert.equal(matchStarter('https://blog.com/wp-json/x', ['wordpress']), null);
  const c = mergePatch({ headers: { names: 'x-mine' } }, matchStarter('https://blog.com/wp-admin/').patch);
  assert.ok(c.headers.names.includes('x-mine') && c.headers.names.includes('x-wp-nonce'));
  const entry = { request: { method: 'GET', url: 'https://blog.com/wp-json/x?_wpnonce=abc12', headers: [{ name: 'X-WP-Nonce', value: 'ab12' }], queryString: [{ name: '_wpnonce', value: 'abc12' }], cookies: [] }, response: { status: 200, headers: [], cookies: [], content: { mimeType: 'application/json', text: '{}' } } };
  const r = await runEngine([entry], { entries: [entry] }, c, { salt: 1 }); const s = JSON.stringify(r.log); assert.ok(!s.includes('abc12') && !s.includes('"ab12"'));
});
await t('manifest: only "storage", no host permissions, network connections blocked by CSP, no remote code', async () => {
  const m = JSON.parse(fs2.readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'));
  assert.deepEqual(m.permissions, ['storage']); assert.ok(!m.host_permissions && !m.optional_host_permissions && !m.optional_permissions);
  assert.match(m.content_security_policy.extension_pages, /connect-src 'none'/); assert.match(m.content_security_policy.extension_pages, /script-src 'self'/);
});
await t('privacy: extension code contains no network calls or inline scripts (only the copy-snippet template)', async () => {
  const walk = (d) => fs2.readdirSync(d, { withFileTypes: true }).flatMap((x) => (x.isDirectory() ? walk(d + '/' + x.name) : [d + '/' + x.name]));
  const root = new URL('..', import.meta.url).pathname; const files = ['src', 'app', 'devtools'].flatMap((d) => walk(root + d));
  const bad = []; files.forEach((f) => { const s = fs2.readFileSync(f, 'utf8'); if (/\.js$/.test(f) && /\b(?:XMLHttpRequest|WebSocket|sendBeacon|EventSource|importScripts)\b|(?<![\w'"` ])fetch\(\s*['"`]https?:/.test(s) && !/summary\.js$|local\.js$/.test(f)) bad.push(f); if (/\.html$/.test(f) && /<script(?![^>]*\bsrc=)/.test(s)) bad.push(f + ' (inline script)'); if (/\.html$/.test(f) && /(?:src|href)=["']https?:\/\/(?!runlocaltools\.online)/.test(s)) bad.push(f + ' (remote asset)'); });
  assert.deepEqual(bad, []);
});
await t('pages: welcome, local, sample button and viewer link exist; outbound links are plain', async () => {
  const rd = (p) => fs2.readFileSync(new URL('../' + p, import.meta.url), 'utf8');
  assert.match(rd('app/welcome.html'), /3 steps/); assert.match(rd('app/local.html'), /Prove it/); assert.match(rd('src/background.js'), /onInstalled/);
  const b = rd('src/brand.js'); assert.match(b, /runlocaltools\.online/); assert.ok(!/[?]/.test(b.split('\n').filter((l) => /HAR_VIEWER_URL|SITE =/.test(l)).join('')));
});

await t('release 3: tools menu links are plain https links to the brand site; listing text fits store limits', async () => {
  const { TOOLS, SITE } = await import('../src/brand.js'); const rd = (p) => fs2.readFileSync(new URL('../' + p, import.meta.url), 'utf8');
  assert.ok(TOOLS.length >= 3 && TOOLS.every((x) => x.url.startsWith(SITE) && !/[?#]/.test(x.url)));
  assert.match(rd('app/app.html'), /data-tools/); assert.match(rd('app/welcome.html'), /data-tools/);
  assert.match(rd('app/tools.js'), /noopener noreferrer/);
  const m = JSON.parse(rd('manifest.json')); assert.ok(m.description.length <= 132, 'manifest description is ' + m.description.length);
  assert.ok(m.name.length <= 75);
});
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

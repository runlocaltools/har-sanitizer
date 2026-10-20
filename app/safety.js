// Plain-language safety verdict. Levels: 'bad' (do not share), 'review', 'good'.
const CORE = [['cookies.on', 'Cookie redaction'], ['headers.on', 'Sensitive-header redaction'], ['params.on', 'URL-parameter redaction'], ['body.keys', 'Sensitive body fields'],
  ['creds', 'URL credentials'], ['det.jwt', 'JWT detection'], ['det.apikeys', 'API-key detection'], ['det.bearer', 'Bearer/Basic detection']];
const get = (o, p) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
export function evaluateSafety(cfg, info) {
  const reasons = []; let level = 'good';
  const bump = (l) => { if (l === 'bad' || (l === 'review' && level === 'good')) level = l; };
  const left = info && info.residual ? info.residual.total : 0;
  if (left > 0) { bump('bad'); reasons.push({ l: 'bad', t: left + ' possible secret(s) still found in the output by the leak check.' }); }
  const off = CORE.filter(([p]) => !get(cfg, p)).map(([, n]) => n);
  if (off.length) { bump('review'); reasons.push({ l: 'review', t: 'Core protections are turned off: ' + off.join(', ') + '.' }); }
  const kept = String(cfg.keepValues || '').split(/\r?\n/).filter((x) => x.trim()).length;
  if (kept) reasons.push({ l: 'info', t: kept + ' value(s) are on your keep list and are NOT redacted.' });
  const pii = [['det.email', 'email addresses'], ['det.ipv4', 'IPv4 addresses'], ['det.ipv6', 'IPv6 addresses']].filter(([p]) => !get(cfg, p)).map(([, n]) => n);
  if (pii.length) { reasons.push({ l: 'info', t: 'Not redacted: ' + pii.join(', ') + '.' }); }
  if (cfg.hosts && cfg.hosts.mode === 'keep') reasons.push({ l: 'info', t: 'Hostnames are visible (fine for support, not for public posting).' });
  if (!cfg.det.entropy) reasons.push({ l: 'info', t: 'Heuristic detection of random-looking tokens is off.' });
  if (info && info.stats && !Object.values(info.stats).some((v) => typeof v === 'number' && v > 0)) { bump('review'); reasons.push({ l: 'review', t: 'Nothing was redacted — check that this is the right file and preset.' }); }
  return { level, reasons, label: level === 'bad' ? 'Not safe to share' : level === 'review' ? 'Review before sharing' : 'Looks safe to share' };
}

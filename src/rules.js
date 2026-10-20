// Rules, site profiles and starter packs. Pure functions (also run in Node tests).
import { DEF, deepMerge } from './engine.js';

export const LEVELS = ['readable', 'balanced', 'thorough'];
export const LEVEL_INFO = {
  readable: { label: 'Readable', hint: 'Only redacts by name and known patterns (cookies, auth headers, JWTs, API keys…). Never guesses at random-looking strings, so URLs and IDs stay readable. A secret hiding under an innocent name can slip through.' },
  balanced: { label: 'Balanced', hint: 'Also redacts random-looking tokens, but not inside fonts, images, CSS or JS files, where build hashes are everywhere. Recommended.' },
  thorough: { label: 'Thorough', hint: 'Redacts random-looking strings everywhere, static files included, with a lower threshold. Expect over-redaction.' }
};
export const levelIndex = (l) => Math.max(0, LEVELS.indexOf(l));

/* ---- text-list helpers (rules are newline-separated lists in the config) ---- */
export const lines = (s) => String(s || '').split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
export function addLine(text, value) { const l = lines(text); if (!l.some((x) => x.toLowerCase() === value.toLowerCase())) l.push(value); return l.join('\n'); }
export function removeLine(text, value) { return lines(text).filter((x) => x.toLowerCase() !== value.toLowerCase()).join('\n'); }

/** kind: 'always' (redact this everywhere) or 'never' (keep this value). Returns { ok, cfg, msg }. */
export function addRule(cfg, kind, value) {
  const v = String(value == null ? '' : value).trim();
  if (!v) return { ok: false, cfg, msg: 'Nothing to save.' };
  if (/[\r\n]/.test(v)) return { ok: false, cfg, msg: 'Multi-line values cannot be saved as a rule.' };
  if (v.length > 500) return { ok: false, cfg, msg: 'That value is too long to use as a rule.' };
  const out = deepMerge(DEF, cfg || {});
  if (kind === 'always') {
    if (v.length < 4) return { ok: false, cfg, msg: 'Too short — it would also match inside unrelated text. Use at least 4 characters.' };
    out.literals = addLine(out.literals, v); out.keepValues = removeLine(out.keepValues, v);
    return { ok: true, cfg: out, msg: 'Will always redact “' + clip(v) + '”.' };
  }
  out.keepValues = addLine(out.keepValues, v); out.literals = removeLine(out.literals, v);
  return { ok: true, cfg: out, msg: 'Will never redact “' + clip(v) + '”.' };
}
const clip = (v) => (v.length > 24 ? v.slice(0, 10) + '…' + v.slice(-6) : v);

/** Merge a starter patch into a config: text lists are unioned, everything else is set. */
export function mergePatch(cfg, patch) {
  const out = deepMerge(DEF, cfg || {});
  (function walk(dst, src) {
    Object.keys(src).forEach((k) => {
      if (src[k] && typeof src[k] === 'object') { dst[k] = dst[k] && typeof dst[k] === 'object' ? dst[k] : {}; walk(dst[k], src[k]); }
      else if (typeof src[k] === 'string') lines(src[k]).forEach((l) => { dst[k] = addLine(dst[k], l); });
      else dst[k] = src[k];
    });
  })(out, patch);
  return out;
}

/* ---- starter packs, suggested when the panel sees matching traffic ---- */
export const STARTERS = [
  { id: 'wordpress', label: 'WordPress',
    test: (url) => /\/wp-(?:json|admin|login\.php|content|includes)\b|admin-ajax\.php|xmlrpc\.php/i.test(url),
    patch: { headers: { names: 'x-wp-nonce' }, params: { names: '_wpnonce\n_ajax_nonce\nnonce\nwpnonce' }, body: { extra: '_wpnonce\n_ajax_nonce\nnonce\nlog\nuser_login\nuser_pass' } } },
  { id: 'stripe', label: 'Stripe',
    test: (url) => /^https?:\/\/(?:[^/@]*\.)?stripe\.com(?:[/:?#]|$)|\/v1\/(?:payment_intents|setup_intents|payment_methods|checkout\/sessions)\b/i.test(url),
    patch: { det: { ids: true }, headers: { names: 'stripe-signature' }, params: { names: 'client_secret\npayment_intent_client_secret\nsetup_intent_client_secret' }, body: { extra: 'client_secret\npayment_method\ncvc\nexp_month\nexp_year\nmuid\nguid\nstripe_js_id' } } }
];
export function matchStarter(url, skipIds) {
  if (typeof url !== 'string') return null;
  return STARTERS.find((s) => !(skipIds || []).includes(s.id) && s.test(url)) || null;
}

/* ---- site profiles: { [host]: { cfg, starters: [id], saved: ms } } ---- */
export const siteKey = (host) => String(host || '').toLowerCase().replace(/^www\./, '');
export function effectiveCfg(globalCfg, profiles, host) {
  const p = profiles && profiles[siteKey(host)];
  return deepMerge(DEF, p && p.cfg ? p.cfg : globalCfg || {});
}
export function withProfile(profiles, host, cfg, starterId) {
  const k = siteKey(host), prev = (profiles && profiles[k]) || {};
  const starters = Array.from(new Set((prev.starters || []).concat(starterId ? [starterId] : [])));
  return Object.assign({}, profiles, { [k]: { cfg, starters, saved: Date.now() } });
}
export function withoutProfile(profiles, host) { const o = Object.assign({}, profiles); delete o[siteKey(host)]; return o; }

/* ---- panel size limits ---- */
export const LIMIT_CHOICES_MB = [25, 50, 100, 200];
export const DEFAULT_LIMIT_MB = 50;
/** 'ok' below 80 %, 'warn' from 80 %, 'full' at 100 %. */
export function limitState(bytes, limitMB) {
  const lim = (limitMB || DEFAULT_LIMIT_MB) * 1048576;
  return bytes >= lim ? 'full' : bytes >= lim * 0.8 ? 'warn' : 'ok';
}
export const fmtBytes = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB');

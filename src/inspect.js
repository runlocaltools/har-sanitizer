// Flattens one sanitized HAR entry into a list of values the user can click: redacted ones (Keep) and visible ones (Always redact).
const isPrim = (v) => typeof v === 'string' || typeof v === 'number';
function leaves(node, prefix, push, depth) {
  if (depth > 6) return;
  if (isPrim(node)) { push(prefix || 'value', node); return; }
  if (Array.isArray(node)) { node.slice(0, 50).forEach((x, i) => leaves(x, prefix + '[' + i + ']', push, depth + 1)); return; }
  if (node && typeof node === 'object') Object.keys(node).slice(0, 80).forEach((k) => leaves(node[k], prefix ? prefix + '.' + k : k, push, depth + 1));
}
const parseJson = (t) => { try { const x = JSON.parse(t); return x && typeof x === 'object' ? x : null; } catch { return null; } };

export function flattenEntry(e, max = 300) {
  const rows = [];
  const add = (w, n, v) => { if (rows.length >= max || v == null) return; const s = String(v); if (s) rows.push({ w, n: String(n), v: s }); };
  const req = (e && e.request) || {}, res = (e && e.response) || {};
  try { const u = new URL(req.url); add('host', 'host', u.hostname); u.pathname.split('/').filter((x) => x.length >= 4).forEach((x, i) => add('path', 'segment ' + (i + 1), decodeURIComponent(x))); } catch { /* not an absolute URL */ }
  (req.queryString || []).forEach((q) => add('query', q.name, q.value));
  (req.headers || []).forEach((h) => add('request header', h.name, h.value));
  (req.cookies || []).forEach((c) => add('request cookie', c.name, c.value));
  const pd = req.postData;
  if (pd) {
    (pd.params || []).forEach((p) => add('form field', p.name, p.value));
    const j = !(pd.params && pd.params.length) && typeof pd.text === 'string' ? parseJson(pd.text) : null;
    if (j) leaves(j, '', (n, v) => add('request body', n, v), 0);
  }
  (res.headers || []).forEach((h) => add('response header', h.name, h.value));
  (res.cookies || []).forEach((c) => add('response cookie', c.name, c.value));
  const ct = res.content;
  if (ct && typeof ct.text === 'string' && ct.encoding !== 'base64') { const j = parseJson(ct.text); if (j) leaves(j, '', (n, v) => add('response body', n, v), 0); }
  return rows;
}

/** Marks rows that contain a placeholder and attaches the original(s) recorded for this entry. */
export function annotate(rows, recs) {
  return rows.map((r) => {
    const hits = (recs || []).filter((x) => x.ph && r.v.indexOf(x.ph) >= 0);
    return Object.assign({}, r, { redacted: hits.length > 0, originals: hits.map((h) => h.original), cats: hits.map((h) => h.cat) });
  });
}
export const mask = (s) => { s = String(s); return s.length <= 8 ? s.charAt(0) + '…' : s.slice(0, 3) + '…' + s.slice(-2); };

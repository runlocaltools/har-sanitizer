// Review panel: findings (keep / redact), entries list, before/after diff, curl/fetch copy.
import { lineDiff, inlineSplit } from './diff.js';
import { toCurl, toFetch } from '../src/summary.js';

const el = (tag, attrs, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v); }
  kids.flat().forEach((c) => c != null && n.append(c.nodeType ? c : document.createTextNode(c)));
  return n;
};
const mask = (s) => { s = String(s); return s.length <= 8 ? s.charAt(0) + '…' : s.slice(0, 3) + '…' + s.slice(-2); };
const trim = (s, n = 400) => (s.length > n ? s.slice(0, n) + '… (+' + (s.length - n) + ')' : s);
const MARKER = /\[(?:REDACTED|[A-Z]+[_:-][A-Za-z0-9]+)\]/g;

/** h: { cats, getKept(): Set, keep(v), unkeep(v), alwaysRedact(name), toast(msg) } */
export function createReview(rec, h) {
  const root = el('details', { class: 'review' }, el('summary', { text: 'Review: findings, entries & before/after' }));
  const tabs = el('div', { class: 'seg tabs' }), body = el('div', { class: 'revbody' });
  const panes = { findings: el('div'), entries: el('div') };
  let current = null, loaded = { findings: false, entries: false };
  const show = (name) => {
    current = name;
    [...tabs.children].forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.t === name)));
    body.textContent = ''; body.append(panes[name]);
    if (name === 'findings' && !loaded.findings) { loaded.findings = true; panes.findings.textContent = 'Scanning…'; rec.worker.postMessage({ type: 'findings', cfg: h.getCfg() }); }
    if (name === 'entries' && !loaded.entries) { loaded.entries = true; list.textContent = 'Loading entries…'; rec.worker.postMessage({ type: 'rows' }); }
  };
  [['findings', 'Findings'], ['entries', 'Entries & diff']].forEach(([k, l]) => { const b = el('button', { type: 'button', 'data-t': k, text: l }); b.addEventListener('click', () => show(k)); tabs.append(b); });
  root.append(tabs, body);
  root.addEventListener('toggle', () => { if (root.open && !current) show('findings'); });

  /* ---- findings ---- */
  rec.on.findings = (m) => {
    const p = panes.findings; p.textContent = '';
    const cats = Object.keys(m.data);
    if (!cats.length) { p.append(el('p', { class: 'hint', text: 'No sensitive values were found in this file.' })); return; }
    p.append(el('p', { class: 'hint', text: 'Every distinct value the detectors found (masked here). “Keep” leaves a value unredacted everywhere — use it for public IDs or test data you know are safe.' }));
    const kept = h.getKept();
    cats.forEach((k) => {
      const label = (h.cats.find((c) => c[0] === k) || [k, k])[1];
      const box = el('details', { class: 'cat' }, el('summary', {}, label, el('span', { class: 'n', text: String(m.data[k].length) })));
      m.data[k].forEach(([val, n]) => {
        const isKept = kept.has(val) || kept.has(String(val).toLowerCase());
        const btn = el('button', { type: 'button', text: isKept ? 'Kept ✓ — redact again' : 'Keep' });
        btn.addEventListener('click', () => { isKept ? h.unkeep(val) : h.keep(val); loaded.findings = false; show('findings'); });
        box.append(el('div', { class: 'frow' }, el('code', { text: mask(val), title: 'Hover is masked; the full value is in your file only' }), el('span', { class: 'meta', text: '× ' + n }), btn));
      });
      p.append(box);
    });
  };

  /* ---- entries + diff ---- */
  let rows = [], q = '', onlyChanged = true, shown = 150;
  const list = el('div', { class: 'elist' }), diffBox = el('div', { class: 'diffbox' });
  const search = el('input', { type: 'search', placeholder: 'Filter by URL, method or status…', class: 'search' });
  const only = el('input', { type: 'checkbox' }); only.checked = true;
  search.addEventListener('input', () => { q = search.value.toLowerCase(); shown = 150; drawList(); });
  only.addEventListener('change', () => { onlyChanged = only.checked; shown = 150; drawList(); });
  panes.entries.append(el('div', { class: 'row' }, search, el('label', { class: 'meta' }, only, ' only entries with redactions')), list, diffBox);
  function drawList() {
    list.textContent = '';
    const f = rows.filter((r) => (!onlyChanged || r.c) && (!q || (r.m + ' ' + r.s + ' ' + r.u).toLowerCase().includes(q)));
    f.slice(0, shown).forEach((r) => {
      const row = el('button', { type: 'button', class: 'erow' }, el('span', { class: 'm', text: r.m }), el('span', { class: 's' + (r.s >= 400 || !r.s ? ' bad' : ''), text: String(r.s || '—') }), el('span', { class: 'u', text: r.u, title: r.u }), el('span', { class: 'cnt', text: r.n ? r.n + ' ✎' : '' }));
      row.addEventListener('click', () => { [...list.children].forEach((c) => c.classList.remove('sel')); row.classList.add('sel'); rec.worker.postMessage({ type: 'entry', i: r.i }); });
      list.append(row);
    });
    if (f.length > shown) { const more = el('button', { type: 'button', text: 'Show more (' + (f.length - shown) + ' left)' }); more.addEventListener('click', () => { shown += 300; drawList(); }); list.append(more); }
    if (!f.length) list.append(el('p', { class: 'hint', text: onlyChanged ? 'No entries with redactions match.' : 'No entries match.' }));
  }
  rec.on.rows = (m) => { rows = m.rows; drawList(); };
  rec.on.entry = (m) => {
    diffBox.textContent = '';
    const bar = el('div', { class: 'actions' });
    const cp = (txt, label) => { const b = el('button', { type: 'button', text: label }); b.addEventListener('click', async () => { try { await navigator.clipboard.writeText(txt); h.toast('Copied (sanitized)'); } catch { h.toast('Copy failed'); } }); return b; };
    bar.append(cp(toCurl(m.sanitized), 'Copy as curl'), cp(toFetch(m.sanitized), 'Copy as fetch'));
    const ops = lineDiff(m.before.split('\n'), m.after.split('\n'));
    const colA = el('div', { class: 'dcol' }, el('div', { class: 'dhead', text: 'Before (original)' })), colB = el('div', { class: 'dcol' }, el('div', { class: 'dhead', text: 'After (sanitized)' }));
    const line = (cls, parts) => el('pre', { class: 'dl ' + cls }, ...parts);
    ops.forEach((o) => {
      if (o.t === 'eq') { colA.append(line('', [trim(o.a)])); colB.append(line('', [trim(o.b)])); }
      else if (o.t === 'chg') {
        const sp = inlineSplit(o.a, o.b);
        colA.append(line('chg', [trim(sp.a[0], 200), el('mark', { class: 'old', text: trim(sp.a[1], 300) }), trim(sp.a[2], 100)]));
        colB.append(line('chg', [trim(sp.b[0], 200), el('mark', { class: 'new', text: trim(sp.b[1], 300) }), trim(sp.b[2], 100)]));
      } else if (o.t === 'del') { colA.append(line('del', [trim(o.a)])); colB.append(line('pad', [' '])); }
      else { colA.append(line('pad', [' '])); colB.append(line('add', [trim(o.b)])); }
    });
    diffBox.append(bar, el('div', { class: 'dgrid' }, colA, colB));
    diffBox.scrollIntoView({ block: 'nearest' });
  };
  rec.invalidateReview = () => { loaded = { findings: false, entries: false }; rows = []; if (root.open && current) show(current); };
  return root;
}

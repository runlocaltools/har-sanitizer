// Line diff (LCS) with pairing of replaced lines so the changed part can be highlighted.
export function lineDiff(a, b) {
  const n = a.length, m = b.length;
  if (n * m > 4_000_000) { // too big for LCS: compare by index
    const ops = []; const k = Math.max(n, m);
    for (let i = 0; i < k; i++) { if (a[i] === b[i]) ops.push({ t: 'eq', a: a[i], b: b[i] }); else ops.push({ t: 'chg', a: a[i], b: b[i] }); }
    return ops;
  }
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const raw = []; let i = 0, j = 0;
  while (i < n && j < m) { if (a[i] === b[j]) { raw.push({ t: 'eq', a: a[i], b: b[j] }); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) raw.push({ t: 'del', a: a[i++] }); else raw.push({ t: 'add', b: b[j++] }); }
  while (i < n) raw.push({ t: 'del', a: a[i++] }); while (j < m) raw.push({ t: 'add', b: b[j++] });
  // pair consecutive del/add blocks into 'chg' rows
  const ops = []; let k = 0;
  while (k < raw.length) {
    if (raw[k].t === 'eq') { ops.push(raw[k++]); continue; }
    const dels = [], adds = [];
    while (k < raw.length && raw[k].t !== 'eq') { (raw[k].t === 'del' ? dels : adds).push(raw[k]); k++; }
    const p = Math.max(dels.length, adds.length);
    for (let x = 0; x < p; x++) {
      const d = dels[x], ad = adds[x];
      if (d && ad) ops.push({ t: 'chg', a: d.a, b: ad.b }); else if (d) ops.push({ t: 'del', a: d.a }); else ops.push({ t: 'add', b: ad.b });
    }
  }
  return ops;
}
/** Split two strings into [prefix, changedMiddle, suffix] each, for highlighting. */
export function inlineSplit(a, b) {
  let p = 0; const max = Math.min(a.length, b.length);
  while (p < max && a[p] === b[p]) p++;
  let s = 0; while (s < max - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++;
  return { a: [a.slice(0, p), a.slice(p, a.length - s), a.slice(a.length - s)], b: [b.slice(0, p), b.slice(p, b.length - s), b.slice(b.length - s)] };
}

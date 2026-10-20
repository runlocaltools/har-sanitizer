// Encrypted private mapping + restore. Pure WebCrypto, works in pages, workers and Node.
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const ITER = 600000;

async function key(pass, salt, iter) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
/** mapping: [{placeholder, kind, original}] → JSON string safe to store (AES-256-GCM, PBKDF2-SHA256). */
export async function encryptMapping(mapping, passphrase, meta = {}) {
  if (!passphrase || passphrase.length < 8) throw new Error('Use a passphrase of at least 8 characters.');
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await key(passphrase, salt, ITER);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(JSON.stringify({ mappings: mapping, meta }))));
  return JSON.stringify({ format: 'har-sanitizer-mapping', v: 1, kdf: 'PBKDF2-SHA256', iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct),
    note: 'Encrypted. Contains the original secret values — keep it private and never share it with the sanitized file.' });
}
export async function decryptMapping(json, passphrase) {
  let o; try { o = JSON.parse(json); } catch { throw new Error('This is not a mapping file.'); }
  if (!o || o.format !== 'har-sanitizer-mapping') throw new Error('This is not a HAR Sanitizer mapping file.');
  try {
    const k = await key(passphrase, unb64(o.salt), o.iter || ITER);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.iv) }, k, unb64(o.ct));
    return JSON.parse(dec.decode(pt));
  } catch { throw new Error('Wrong passphrase, or the file is damaged.'); }
}

/** Build a replacer: placeholder text → original. Handles [KIND_1], KIND_1 (URL-safe) and hash styles KIND:abcd / KIND-abcd. */
export function makeRestorer(mappings) {
  const pairs = new Map();
  for (const m of mappings) {
    const p = m.placeholder; if (!p) continue;
    pairs.set(p, m.original);
    const h = /^([A-Z]+)([:-])([0-9a-f]+)$/.exec(p);
    if (h) pairs.set(h[1] + (h[2] === ':' ? '-' : ':') + h[3], m.original);
  }
  const keys = [...pairs.keys()].sort((a, b) => b.length - a.length);
  if (!keys.length) return (s) => s;
  const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const rx = new RegExp('\\[(' + keys.map(esc).join('|') + ')\\]|(?<![A-Za-z0-9_])(' + keys.map(esc).join('|') + ')(?![A-Za-z0-9_])', 'g');
  return (s) => (typeof s === 'string' ? s.replace(rx, (m, a, b) => { const v = pairs.get(a || b); return v === undefined ? m : v; }) : s);
}
/** Restore originals inside a parsed HAR by walking strings (so JSON escaping stays correct). */
export function restoreHar(har, mappings) {
  const fix = makeRestorer(mappings);
  const walk = (n) => {
    if (typeof n === 'string') return fix(n);
    if (Array.isArray(n)) return n.map(walk);
    if (n && typeof n === 'object') { const o = {}; for (const k of Object.keys(n)) o[k] = walk(n[k]); return o; }
    return n;
  };
  return walk(har);
}

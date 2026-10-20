/* HAR Sanitizer engine — pure functions, no DOM. Extracted from the web tool.
   Runs in a Worker, the extension pages, or Node (tests / CLI). */
const TOOL_ID = 'har-sanitizer';
// Minimal stand-ins for the web tool's shared helpers (the engine only used them optionally).
const TK = {
  formatBytes(n) { if (n < 1024) return n + ' B'; if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'; return (n / 1048576).toFixed(1) + ' MB'; },
  regexSafeMatch({ pattern, flags, text }) {
    try { new RegExp(pattern, flags).test(text); return { ok: true }; } catch (e) { return { ok: false, error: e.message }; }
  },
  // Rejects nested quantifiers like (a+)+ / (a*)* / (.+)* that cause catastrophic backtracking.
  regexBacktrackRisk(pattern) {
    if (/\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]/.test(pattern)) return 'nested repetition can freeze the tab (catastrophic backtracking)';
    if (/\([^()]*\|[^()]*\)[+*]/.test(pattern) && /\(\.\*|\(\.\+/.test(pattern)) return 'overlapping alternation can freeze the tab';
    if (pattern.length > 300) return 'pattern is too long';
    return null;
  }
};

  const KIND = {
    cookies: 'COOKIE', headers: 'AUTH', params: 'PARAM', bodykeys: 'SECRET', urlcreds: 'CRED',
    jwt: 'JWT', apikeys: 'KEY', pem: 'PEM', bearer: 'BEARER', card: 'CARD', email: 'EMAIL',
    ipv4: 'IP', ipv6: 'IP', phone: 'PHONE', ssn: 'SSN', ids: 'ID', entropy: 'TOKEN', literals: 'CUSTOM', regexes: 'MATCH'
  };
  const CATS = [
    ['cookies', 'Cookie values'], ['headers', 'Auth / secret headers'], ['params', 'URL query & fragment secrets'],
    ['bodykeys', 'Sensitive body fields'], ['urlcreds', 'URL credentials (user:pass@)'], ['jwt', 'JWTs'],
    ['apikeys', 'Cloud / API keys'], ['pem', 'Private keys'], ['bearer', 'Bearer / Basic strings'],
    ['card', 'Card numbers'], ['email', 'Email addresses'], ['ipv4', 'IPv4 addresses'], ['ipv6', 'IPv6 addresses'],
    ['phone', 'Phone numbers'], ['ssn', 'SSN-style numbers'], ['ids', 'Account / resource IDs'], ['entropy', 'High-entropy strings (heuristic)'],
    ['literals', 'Custom text'], ['regexes', 'Custom regex']
  ];
  const KIND_NAMES = Array.from(new Set(Object.keys(KIND).map(k => KIND[k]).concat(['HOST'])));

  const HDR_NAMES = ['authorization', 'proxy-authorization', 'x-api-key', 'api-key', 'apikey', 'x-auth-token', 'x-access-token',
    'x-csrf-token', 'x-xsrf-token', 'x-amz-security-token', 'x-goog-api-key', 'x-shopify-access-token', 'x-slack-signature',
    'x-hub-signature', 'x-hub-signature-256', 'stripe-signature', 'x-api-token', 'x-session-id', 'x-session-token', 'x-auth',
    'x-token', 'private-token', 'x-gitlab-token', 'x-figma-token', 'cf-access-jwt-assertion', 'x-forwarded-access-token', 'x-user-token'];
  const PARAM_NAMES = ['token', 'access_token', 'refresh_token', 'id_token', 'auth', 'authorization', 'api_key', 'apikey', 'key',
    'secret', 'client_secret', 'password', 'passwd', 'pwd', 'pass', 'sig', 'signature', 'code', 'state', 'session', 'sessionid',
    'session_id', 'sid', 'jwt', 'otp', 'csrf', 'xsrf', 'ticket', 'assertion', 'samlresponse', 'saml_response', 'code_verifier'];
  const BODY_KEYS = ['password', 'passwd', 'pwd', 'pass', 'passphrase', 'secret', 'client_secret', 'token', 'access_token',
    'refresh_token', 'id_token', 'api_key', 'apikey', 'authorization', 'auth', 'otp', 'pin', 'cvv', 'cvc', 'card_number',
    'cardnumber', 'ssn', 'private_key', 'session', 'session_id', 'sessionid', 'csrf', 'csrf_token', 'xsrf_token',
    'security_code', 'code_verifier', 'assertion', 'samlresponse'];
  const PII_KEYS = ['email', 'email_address', 'phone', 'phone_number', 'mobile', 'first_name', 'last_name', 'full_name', 'fullname',
    'address', 'street', 'street_address', 'postal_code', 'zip', 'zipcode', 'zip_code', 'dob', 'birth_date', 'birthdate',
    'birthday', 'ip', 'ip_address', 'username', 'user_name', 'display_name', 'displayname', 'passport', 'license_number'];
  const TRACKERS = ['google-analytics.com', 'googletagmanager.com', 'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'facebook.net', 'hotjar.com', 'segment.io', 'segment.com', 'mixpanel.com', 'amplitude.com', 'fullstory.com', 'clarity.ms',
    'sentry.io', 'newrelic.com', 'nr-data.net', 'datadoghq.com', 'optimizely.com', 'hs-analytics.net', 'hsforms.com', 'intercom.io',
    'adsrvr.org', 'criteo.com', 'taboola.com', 'outbrain.com', 'scorecardresearch.com', 'quantserve.com', 'bat.bing.com',
    'px.ads.linkedin.com', 'analytics.tiktok.com', 'ads-twitter.com', 'snap.licdn.com', 'heapanalytics.com', 'adnxs.com',
    'rubiconproject.com', 'pubmatic.com', 'amazon-adsystem.com', 'matomo.cloud', 'hotjar.io', 'mouseflow.com', 'crazyegg.com'];
  const DATE_HEADERS = new Set(['date', 'expires', 'last-modified', 'if-modified-since']);
  const VENDOR_KEEP = new Set(['_resourceType', '_priority']);
  const URL_HDRS = new Set(['referer', 'origin', 'location', 'content-location']);
  const FILE_EXT_TLDS = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'ico', 'css', 'js', 'mjs', 'map', 'woff', 'woff2',
    'ttf', 'otf', 'eot', 'json', 'html', 'htm', 'xml', 'txt', 'pdf', 'mp4', 'webm']);

  // Name heuristics run on a normalised name (camelCase split, lower-cased, separators -> "_").
  const SENS_RE = /(?:^|_)(?:token|secret|password|passwd|pwd|passphrase|apikey|auth|authorization|session|sessionid|sid|csrf|xsrf|signature|sig|credential|credentials|jwt|bearer|otp)(?:$|_)|api_?key|(?:access|private|secret|client|app|license|encryption)_?key|^key$/;

  const RX_JWT = /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]*)?/g;
  const RX_PEM = /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[A-Za-z0-9+\/=\s\\]{20,})/g;
  const RX_KEYS = [
    /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b/g,
    /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/g,
    /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    /\b(?:[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,})\b/g,
    /\bAIza[0-9A-Za-z_-]{35}\b/g,
    /\bya29\.[0-9A-Za-z_-]{20,}/g,
    /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
    /\bnpm_[A-Za-z0-9]{36}\b/g,
    /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g
  ];
  const RX_UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
  const RX_PFXID = /\b(?:cus|sub|pi|ch|in|evt|acct|price|prod|cs|pm|seti|src|card|txn|re|po|ba|si|ii|il|ipi|cmd|tr|tok)_[A-Za-z0-9]{10,}\b/g;
  const RX_ARN = /(\barn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:)(\d{12})(?=:)/g;
  const RX_BEARER = /\b(Bearer|Basic)(\s+)([A-Za-z0-9._~+\/\-]{8,}={0,2})/gi;
  const RX_CARD = /\b(?:\d[ -]?){12,18}\d\b/g;
  const RX_SSN = /\b\d{3}-\d{2}-\d{4}\b/g;
  const RX_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
  const RX_IPV6 = /(^|[^0-9A-Fa-f:.\w])((?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{0,4}){2,8})(?![0-9A-Fa-f:\w])/g;
  const RX_PHONE = /(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]\d{3,4}[ .-]\d{3,4}\b|\+\d{8,15}\b/g;
  const RX_EMBED = /\b(?:https?|wss?):\/\/[^\s"'<>\\^`{|}]+/gi;
  const RX_URL = /^(?:([a-zA-Z][a-zA-Z0-9+.\-]*:)\/\/([^\/?#]*))?([^?#]*)(\?[^#]*)?(#[\s\S]*)?$/;
  const RX_PLACEHOLDER = new RegExp('^\\[?(?:REDACTED|(?:' + KIND_NAMES.join('|') + ')[_:-][A-Za-z0-9]+)\\]?$');
  const RX_HOSTPH = /^(?:host-\d+|h-[0-9a-f]{8}|redacted)\.invalid$/;

  function isPlaceholder(v) {
    return typeof v === 'string' && v.length < 40 && (RX_PLACEHOLDER.test(v) || RX_HOSTPH.test(v));
  }
  function normName(n) {
    return String(n).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  }
  function splitList(str) { return String(str || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean); }
  function splitLines(str) { return String(str || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean); }
  function escRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function safeDec(s) { try { return decodeURIComponent(s); } catch (e) { return s; } }
  function trunc(v) {
    v = String(v);
    return v.length > 28 ? v.slice(0, 10) + '…' + v.slice(-6) : v;
  }
  function normHost(h) {
    return String(h).trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^\*\./, '').replace(/[\/?#].*$/, '').replace(/:\d+$/, '');
  }
  function hostMatches(list, host) {
    for (let i = 0; i < list.length; i++) { const e = list[i]; if (host === e || host.endsWith('.' + e)) return true; }
    return false;
  }

  /* ---------- small utilities ---------- */
  function cyrb53(str, seed) {
    let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761); h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 4294967296 * (2097151 & h2) + (h1 >>> 0);
  }
  function hash8(str, salt) { return (cyrb53(str, salt | 0) >>> 0).toString(16).padStart(8, '0').slice(-8); }
  function shannon(s) {
    const f = {};
    for (let i = 0; i < s.length; i++) f[s[i]] = (f[s[i]] || 0) + 1;
    let h = 0;
    for (const k in f) { const p = f[k] / s.length; h -= p * Math.log2(p); }
    return h;
  }
  const ENT_CHARS = /^[A-Za-z0-9_\-+\/=.~%]+$/;
  function looksSecret(s, min) {
    if (typeof s !== 'string' || s.length < 20 || s.length > 2048) return false;
    if (!ENT_CHARS.test(s) || s.indexOf('://') >= 0) return false;
    if (!/\d/.test(s) || !/[A-Za-z]/.test(s)) return false;
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(s) || isPlaceholder(s)) return false;
    if (!/[A-Z]/.test(s) && /[-_.\/]/.test(s)) return false;
    return shannon(s) >= min;
  }
  function luhn(d) {
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = d.charCodeAt(i) - 48;
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }
  function cardOk(digits) {
    const n = digits.length;
    if (n < 13 || n > 19 || !luhn(digits)) return false;
    const p2 = +digits.slice(0, 2), p3 = +digits.slice(0, 3), p4 = +digits.slice(0, 4);
    if (digits[0] === '4') return n === 13 || n === 16 || n === 19;
    if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return n === 16;
    if (p2 === 34 || p2 === 37) return n === 15;
    if (p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649)) return n >= 16 && n <= 19;
    if (p2 === 35) return n >= 16 && n <= 19;
    if (p2 === 36 || p2 === 38 || (p3 >= 300 && p3 <= 305)) return n === 14;
    return false;
  }
  function ssnOk(s) {
    const a = s.slice(0, 3), g = s.slice(4, 6), r = s.slice(7);
    return a !== '000' && a !== '666' && a[0] !== '9' && g !== '00' && r !== '0000';
  }
  function isIPv4(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    return !!m && m.slice(1).every(x => +x <= 255 && String(+x) === x);
  }
  function isPrivateV4(s) {
    const p = s.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168);
  }
  function isIPv6(s) {
    if (s.length < 2 || s.length > 45 || !/^[0-9A-Fa-f:]+$/.test(s) || s.indexOf(':::') >= 0) return false;
    const hex = g => /^[0-9A-Fa-f]{1,4}$/.test(g);
    const dbl = s.indexOf('::');
    if (dbl !== s.lastIndexOf('::')) return false;
    if (dbl < 0) { const g = s.split(':'); return g.length === 8 && g.every(hex); }
    const parts = s.split('::');
    const l = parts[0] ? parts[0].split(':') : [], r = parts[1] ? parts[1].split(':') : [];
    return l.length + r.length <= 7 && l.concat(r).every(hex);
  }
  function isPrivateV6(s) {
    const l = s.toLowerCase();
    return l === '::1' || l === '::' || /^fe[89ab]/.test(l) || /^f[cd]/.test(l);
  }
  function validJwt(m) {
    try {
      const h = m.split('.')[0].replace(/-/g, '+').replace(/_/g, '/');
      const txt = atob(h + '==='.slice((h.length + 3) % 4));
      const o = JSON.parse(txt);
      return !!o && typeof o === 'object' && !Array.isArray(o);
    } catch (e) { return false; }
  }
  function b64ToText(b64) {
    try {
      const bin = atob(b64.replace(/\s+/g, ''));
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (e) { return null; }
  }
  function textToB64(text) {
    const bytes = new TextEncoder().encode(text);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  }
  function mimeBase(m) { return String(m || '').split(';')[0].trim().toLowerCase(); }
  function mimeCat(m) {
    const b = mimeBase(m);
    if (!b) return 'unknown';
    if (b.startsWith('image/')) return 'images';
    if (b.startsWith('font/') || /^application\/(?:x-)?font|vnd\.ms-fontobject|x-woff/.test(b)) return 'fonts';
    if (b.startsWith('audio/') || b.startsWith('video/')) return 'media';
    if (isTextMime(b)) return 'text';
    return 'binary';
  }
  function isTextMime(m) {
    const b = mimeBase(m);
    if (!b) return true;
    return b.startsWith('text/') || /json|xml|javascript|ecmascript|x-www-form-urlencoded|graphql|svg|yaml|html|csv/.test(b);
  }
  function shiftDate(str, ms) {
    if (!ms) return str;
    const t = Date.parse(str);
    return isNaN(t) ? str : new Date(t + ms).toISOString();
  }
  function shiftHttpDate(str, ms) {
    if (!ms) return str;
    const t = Date.parse(str);
    return isNaN(t) ? str : new Date(t + ms).toUTCString();
  }

  /* ---------- config ---------- */
  const DEF = {
    preset: 'support', level: 'balanced', style: 'placeholder', pretty: false,
    cookies: { on: true, mode: 'redact', keep: '' },
    headers: { on: true, heur: true, names: '', keep: '' },
    params: { on: true, heur: true, names: '', keep: '', frag: true },
    creds: true,
    body: { keys: true, heur: true, extra: '', paths: '', pii: false, embed: true, dropReq: false, dropUploads: true,
      dropTypes: { images: false, fonts: false, media: false, binary: false, all: false } },
    det: { jwt: true, apikeys: true, pem: true, bearer: true, card: true, email: true, ipv4: true, ipv6: true,
      phone: false, ssn: false, ids: false, entropy: true, entropyMin: 4.3, keepPrivate: true },
    hosts: { mode: 'keep', keep: '', drop: '', trackers: false },
    meta: { serverIp: true, connection: false, creator: true, pageTitles: false, comments: true, vendor: false,
      ua: false, shift: false, dataUris: true },
    filt: { options: false, failed: false, dropImages: false, dropFonts: false, dropMedia: false, urlSubs: '' },
    literals: '', regexes: '', keepValues: ''
  };
  const PRESETS = {
    support: {},
    strict: {
      level: 'thorough',
      cookies: { mode: 'remove' }, params: { frag: true },
      body: { pii: true, dropUploads: true, dropTypes: { images: true, fonts: true, media: true, binary: true } },
      det: { phone: true, ssn: true, ids: true, entropy: true, entropyMin: 4.0, keepPrivate: false },
      hosts: { mode: 'pseudo', trackers: true },
      meta: { serverIp: true, connection: true, creator: true, pageTitles: true, comments: true, vendor: true, ua: true, shift: true, dataUris: true }
    },
    secrets: {
      level: 'readable',
      det: { email: false, ipv4: false, ipv6: false, phone: false, ssn: false, ids: false, entropy: false },
      hosts: { mode: 'keep', trackers: false },
      meta: { serverIp: false, connection: false, creator: false, pageTitles: false, comments: false, vendor: false, ua: false, shift: false, dataUris: false },
      body: { pii: false, dropUploads: false, dropTypes: { images: false, fonts: false, media: false, binary: false, all: false } }
    },
    pub: {
      body: { pii: true, dropUploads: true, dropTypes: { images: true, fonts: true, media: true, binary: false } },
      det: { phone: true, ids: true, entropy: true, keepPrivate: false },
      hosts: { mode: 'pseudo', trackers: true },
      meta: { serverIp: true, connection: true, creator: true, comments: true, vendor: true, dataUris: true, ua: false, shift: false, pageTitles: false }
    }
  };
  function deepClone(o) { return JSON.parse(JSON.stringify(o)); }
  function deepMerge(base, over) {
    const out = Array.isArray(base) ? base.slice() : Object.assign({}, base);
    if (!over || typeof over !== 'object') return out;
    Object.keys(over).forEach(k => {
      if (over[k] && typeof over[k] === 'object' && !Array.isArray(over[k]) && base[k] && typeof base[k] === 'object') out[k] = deepMerge(base[k], over[k]);
      else out[k] = over[k];
    });
    return out;
  }

  /* ---------- custom regex / literal parsing ---------- */
  function parseCustomRegexes(text) {
    const rules = [], problems = [];
    splitLines(text).forEach((line, i) => {
      let pat = line, flags = '';
      const m = /^\/(.+)\/([a-z]*)$/.exec(line);
      if (m) { pat = m[1]; flags = m[2].replace(/[^imsu]/g, ''); }
      const test = (typeof TK !== 'undefined' && TK.regexSafeMatch)
        ? TK.regexSafeMatch({ pattern: pat, flags: flags, text: 'x' })
        : { ok: true, risk: null };
      if (!test.ok) { problems.push({ line: i + 1, src: line, msg: 'Not a valid pattern: ' + test.error }); return; }
      const risk = (typeof TK !== 'undefined' && TK.regexBacktrackRisk) ? TK.regexBacktrackRisk(pat) : null;
      if (risk) { problems.push({ line: i + 1, src: line, msg: 'Skipped — ' + risk }); return; }
      let re;
      try { re = new RegExp(pat, flags.indexOf('g') >= 0 ? flags : flags + 'g'); }
      catch (e) { problems.push({ line: i + 1, src: line, msg: 'Not a valid pattern.' }); return; }
      let empty = false;
      try { empty = new RegExp(pat, flags).test(''); } catch (e) {}
      if (empty) { problems.push({ line: i + 1, src: line, msg: 'Skipped — this pattern can match an empty string, which would insert a placeholder everywhere.' }); return; }
      rules.push({ re: re, src: line });
    });
    return { rules, problems };
  }
  function parsePaths(text) {
    return splitList(text).map(s => s.replace(/^\$\.?/, '').toLowerCase().split('.').filter(Boolean)).filter(a => a.length);
  }
  function globMatch(p, i, s, j) {
    if (i === p.length) return j === s.length;
    if (p[i] === '**') { for (let k = j; k <= s.length; k++) if (globMatch(p, i + 1, s, k)) return true; return false; }
    if (j < s.length && (p[i] === '*' || p[i] === String(s[j]).toLowerCase())) return globMatch(p, i + 1, s, j + 1);
    return false;
  }
  function pathMatch(pats, segs) {
    for (let i = 0; i < pats.length; i++) if (globMatch(pats[i], 0, segs, 0)) return true;
    return false;
  }

  /* ---------- compile a config into fast lookups ---------- */
  function compile(cfg) {
    const c = {};
    c.cookOn = !!cfg.cookies.on; c.cookRemove = cfg.cookies.mode === 'remove';
    c.cookKeep = new Set(splitList(cfg.cookies.keep).map(s => s.toLowerCase()));
    c.hdrOn = !!cfg.headers.on; c.hdrHeur = !!cfg.headers.heur;
    c.hdrNames = new Set(HDR_NAMES.concat(splitList(cfg.headers.names)).map(normName));
    c.hdrKeep = new Set(splitList(cfg.headers.keep).map(normName));
    c.parOn = !!cfg.params.on; c.parHeur = !!cfg.params.heur; c.frag = !!cfg.params.frag;
    c.parNames = new Set(PARAM_NAMES.concat(splitList(cfg.params.names)).map(normName));
    c.parKeep = new Set(splitList(cfg.params.keep).map(normName));
    c.creds = !!cfg.creds;
    c.keysOn = !!cfg.body.keys; c.keyHeur = !!cfg.body.heur; c.pii = !!cfg.body.pii;
    c.keyNames = new Set(BODY_KEYS.concat(splitList(cfg.body.extra)).map(normName));
    c.piiNames = new Set(PII_KEYS.map(normName));
    c.keyPaths = parsePaths(cfg.body.paths);
    c.embed = !!cfg.body.embed; c.dropReq = !!cfg.body.dropReq; c.dropUploads = !!cfg.body.dropUploads;
    c.dropTypes = cfg.body.dropTypes || {};
    c.det = Object.assign({}, cfg.det);
    c.entMin = Math.min(6, Math.max(3, Number(cfg.det.entropyMin) || 4.3));
    // Over-redaction level: readable = no random-string guessing; balanced = guess, but not inside static files; thorough = guess everywhere, lower threshold.
    c.level = cfg.level === 'readable' || cfg.level === 'thorough' ? cfg.level : 'balanced';
    if (c.level === 'readable') c.det.entropy = false;
    if (c.level === 'thorough') c.entMin = Math.min(c.entMin, 4.0);
    c.skipStatic = c.level !== 'thorough';
    c.keepPriv = !!cfg.det.keepPrivate;
    c.hostMode = cfg.hosts.mode === 'pseudo' ? 'pseudo' : 'keep';
    c.hostKeep = splitList(cfg.hosts.keep).map(normHost).filter(Boolean);
    c.hostDrop = splitList(cfg.hosts.drop).map(normHost).filter(Boolean);
    if (cfg.hosts.trackers) c.hostDrop = c.hostDrop.concat(TRACKERS);
    c.meta = Object.assign({}, cfg.meta);
    c.comments = !!cfg.meta.comments; c.vendor = !!cfg.meta.vendor; c.shift = !!cfg.meta.shift; c.ua = !!cfg.meta.ua;
    c.filt = Object.assign({}, cfg.filt);
    c.urlSubs = splitLines(cfg.filt.urlSubs).map(s => s.toLowerCase());
    const lits = Array.from(new Set(splitLines(cfg.literals))).slice(0, 500).sort((a, b) => b.length - a.length);
    c.litCS = null; c.litCI = null;
    // A literal is case-insensitive unless it is wrapped as "=exact" … keep it simple: one case-insensitive set.
    if (lits.length) c.litCI = new RegExp(lits.map(escRe).join('|'), 'gi');
    const cr = parseCustomRegexes(cfg.regexes);
    c.rules = cr.rules; c.ruleProblems = cr.problems;
    c.keepVals = new Set(splitLines(cfg.keepValues).map(x => x.trim()).filter(Boolean));
    c.hostRx = null;
    return c;
  }
  function buildHostRx(hostList) {
    if (!hostList.length) return null;
    const alt = hostList.slice().sort((a, b) => b.length - a.length).map(escRe).join('|');
    return new RegExp('((?:^|[^A-Za-z0-9.\\-])\\.?)(' + alt + ')(?![A-Za-z0-9\\-]|\\.[A-Za-z0-9])', 'gi');
  }

  /* ---------- run context ---------- */
  function makeCtx(cfg, opts) {
    opts = opts || {};
    const c = compile(cfg);
    const ctx = {
      c: c, stats: {}, ex: {}, findings: opts.findings ? {} : null, collect: !!opts.collect, map: new Map(), counters: {}, mapping: [],
      salt: opts.salt | 0, hostMap: new Map(), shiftMs: c.shift ? (opts.shiftMs || 0) : 0,
      style: cfg.style === 'hash' || cfg.style === 'fixed' ? cfg.style : 'placeholder'
    };
    if (!c.shift) c.shiftOff = true;
    ctx.hostDirty = false;
    if (c.hostMode === 'pseudo') {
      (opts.seedHosts || []).forEach(h => {
        if (isIPv4(h) || isIPv6(h) || h === 'localhost' || hostMatches(c.hostKeep, h)) return;
        hostName(ctx, h);
      });
    }
    return ctx;
  }
  function inc(ctx, key, n) { ctx.stats[key] = (ctx.stats[key] || 0) + (n || 1); }

  function tok(ctx, kind, value, urlSafe) {
    let body;
    if (ctx.style === 'fixed') body = 'REDACTED';
    else if (ctx.style === 'hash') {
      body = kind + (urlSafe ? '-' : ':') + hash8(value, ctx.salt);
      const k = kind + '\u0000' + value;
      if (!ctx.map.has(k)) { ctx.map.set(k, 1); ctx.mapping.push({ placeholder: body, kind: kind, original: value }); }
    } else {
      const k = kind + '\u0000' + value;
      let n = ctx.map.get(k);
      if (!n) {
        n = (ctx.counters[kind] || 0) + 1; ctx.counters[kind] = n; ctx.map.set(k, n);
        ctx.mapping.push({ placeholder: kind + '_' + n, kind: kind, original: value });
      }
      body = kind + '_' + n;
    }
    return urlSafe ? body : '[' + body + ']';
  }
  function red(ctx, cat, value, urlSafe) {
    const kv = ctx.c.keepVals;
    if (kv && kv.size && (kv.has(value) || kv.has(String(value).toLowerCase()))) { inc(ctx, 'kept'); return value; }
    inc(ctx, cat);
    if (ctx.findings) {
      const m = ctx.findings[cat] || (ctx.findings[cat] = new Map());
      if (m.has(value)) m.set(value, m.get(value) + 1); else if (m.size < 200) m.set(value, 1);
    }
    if (ctx.collect) {
      const a = ctx.ex[cat] || (ctx.ex[cat] = []);
      if (a.length < 4) { const t = trunc(value); if (a.indexOf(t) < 0) a.push(t); }
    }
    const t = tok(ctx, KIND[cat], value, urlSafe);
    if (ctx.rec && ctx.rec.length < 80) ctx.rec.push({ cat: cat, original: String(value).slice(0, 300), ph: t });
    return t;
  }
  function hostName(ctx, lower) {
    let v = ctx.hostMap.get(lower);
    if (v) return v;
    if (ctx.style === 'fixed') v = 'redacted.invalid';
    else if (ctx.style === 'hash') v = 'h-' + hash8(lower, ctx.salt) + '.invalid';
    else v = 'host-' + (ctx.hostMap.size + 1) + '.invalid';
    ctx.hostMap.set(lower, v); ctx.hostDirty = true;
    if (ctx.style !== 'fixed') ctx.mapping.push({ placeholder: v, kind: 'HOST', original: lower });
    return v;
  }
  function hostDisp(host, ctx) {
    const lower = host.toLowerCase();
    if (ctx.c.hostMode !== 'pseudo' || hostMatches(ctx.c.hostKeep, lower)) return host;
    inc(ctx, 'hosts');
    return hostName(ctx, lower);
  }

  /* ---------- free-text scrubbing ---------- */
  function replaceEmails(s, fn) {
    if (s.indexOf('@') < 0) return s;
    const LOCAL = /[\p{L}\p{N}._%+\-]/u, DOM = /[\p{L}\p{N}.\-]/u;
    let out = '', last = 0, i = -1;
    while ((i = s.indexOf('@', i + 1)) >= 0) {
      let a = i;
      while (a > last && a > i - 64 && LOCAL.test(s[a - 1])) a--;
      while (a < i && s[a] === '.') a++;
      let b = i + 1;
      while (b < s.length && b < i + 256 && DOM.test(s[b])) b++;
      while (b > i + 1 && /[.\-]/.test(s[b - 1])) b--;
      if (a === i || b === i + 1) continue;
      const domain = s.slice(i + 1, b);
      if (!/^[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+$/u.test(domain)) continue;
      const tld = domain.slice(domain.lastIndexOf('.') + 1).toLowerCase();
      if (!/^\p{L}{2,}$/u.test(tld) || FILE_EXT_TLDS.has(tld)) continue;
      out += s.slice(last, a) + fn(s.slice(a, b));
      last = b;
    }
    return last === 0 ? s : out + s.slice(last);
  }

  function scrubText(s, ctx, urlSafe) {
    if (typeof s !== 'string' || !s) return s;
    const kv = ctx.c.keepVals;
    if (!kv || !kv.size) return scrubTextInner(s, ctx, urlSafe);
    // Shield values the user chose to keep, so no later detector re-redacts them.
    let o = s; const kept = [];
    kv.forEach(v => { if (o.indexOf(v) >= 0) { o = o.split(v).join('\uE000' + kept.length + '\uE001'); kept.push(v); } });
    if (!kept.length) return scrubTextInner(s, ctx, urlSafe);
    o = scrubTextInner(o, ctx, urlSafe);
    return o.replace(/\uE000(\d+)\uE001/g, (m, i) => kept[+i]);
  }
  function scrubTextInner(s, ctx, urlSafe) {
    if (typeof s !== 'string' || !s) return s;
    const c = ctx.c, d = c.det;
    let o = s;
    if (c.litCI) o = o.replace(c.litCI, m => red(ctx, 'literals', m.toLowerCase(), urlSafe));
    for (let i = 0; i < c.rules.length; i++) o = o.replace(c.rules[i].re, m => red(ctx, 'regexes', m, urlSafe));
    if (!urlSafe && c.embed && o.indexOf('://') >= 0) {
      o = o.replace(RX_EMBED, m => {
        let tail = '';
        const t = /[.,;:!?)\]]+$/.exec(m);
        if (t) { tail = t[0]; m = m.slice(0, m.length - tail.length); }
        return scrubUrl(m, ctx, 1) + tail;
      });
    }
    if (d.pem && o.indexOf('PRIVATE KEY') >= 0) o = o.replace(RX_PEM, m => red(ctx, 'pem', m, urlSafe));
    if (d.jwt && o.indexOf('eyJ') >= 0) o = o.replace(RX_JWT, m => validJwt(m) ? red(ctx, 'jwt', m, urlSafe) : m);
    if (d.apikeys) for (let i = 0; i < RX_KEYS.length; i++) o = o.replace(RX_KEYS[i], m => red(ctx, 'apikeys', m, urlSafe));
    if (d.bearer && /bearer|basic/i.test(o)) {
      o = o.replace(RX_BEARER, (m, scheme, ws, t) => {
        if (isPlaceholder(t)) return m;
        if (scheme.toLowerCase() === 'basic') {
          const dec = b64ToText(t.replace(/=+$/, '') + '==='.slice((t.replace(/=+$/, '').length + 3) % 4));
          if (!dec || dec.indexOf(':') < 0) return m;
        } else if (t.length < 10 || /^[a-z]+$/.test(t)) return m;
        return scheme + ws + red(ctx, 'bearer', t, urlSafe);
      });
    }
    if (d.card && /\d{4}/.test(o)) {
      o = o.replace(RX_CARD, m => {
        const dg = m.replace(/[ -]/g, '');
        return cardOk(dg) ? red(ctx, 'card', dg, urlSafe) : m;
      });
    }
    if (d.ssn && o.indexOf('-') >= 0) o = o.replace(RX_SSN, m => ssnOk(m) ? red(ctx, 'ssn', m, urlSafe) : m);
    if (d.email) o = replaceEmails(o, m => red(ctx, 'email', m.toLowerCase(), urlSafe));
    if (d.ids) {
      if (o.indexOf('-') >= 0) o = o.replace(RX_UUID, m => red(ctx, 'ids', m.toLowerCase(), urlSafe));
      if (o.indexOf('_') >= 0) o = o.replace(RX_PFXID, m => red(ctx, 'ids', m, urlSafe));
      if (o.indexOf('arn:') >= 0) o = o.replace(RX_ARN, (m, pre, acct) => pre + red(ctx, 'ids', acct, urlSafe));
    }
    if (d.ipv6 && o.indexOf(':') >= 0) {
      o = o.replace(RX_IPV6, (m, pre, cand) => {
        if (!isIPv6(cand) || (c.keepPriv && isPrivateV6(cand))) return m;
        return pre + red(ctx, 'ipv6', cand.toLowerCase(), urlSafe);
      });
    }
    if (d.ipv4 && o.indexOf('.') >= 0) {
      o = o.replace(RX_IPV4, (m, off, str) => {
        const prev = off > 0 ? str[off - 1] : '', next = str[off + m.length] || '', next2 = str[off + m.length + 1] || '';
        if (/[\w.\/\-:]/.test(prev) && prev !== ':' && !(prev === '/' && str[off - 2] === '/')) return m;
        if (prev === ':' && off > 1 && /[0-9A-Fa-f:]/.test(str[off - 2])) return m;
        if (/\w/.test(next) || (next === '.' && /\d/.test(next2))) return m;
        if (c.keepPriv && isPrivateV4(m)) return m;
        return red(ctx, 'ipv4', m, urlSafe);
      });
    }
    if (d.phone && /\d{3}/.test(o)) {
      o = o.replace(RX_PHONE, (m, off, str) => {
        const prev = off > 0 ? str[off - 1] : '', next = str[off + m.length] || '', next2 = str[off + m.length + 1] || '';
        if (/[\w.\-]/.test(prev) || /\d/.test(next) || (next === '.' && /\d/.test(next2))) return m;
        return red(ctx, 'phone', m, urlSafe);
      });
    }
    if (c.hostMode === 'pseudo') {
      if (ctx.hostDirty) { c.hostRx = buildHostRx(Array.from(ctx.hostMap.keys())); ctx.hostDirty = false; }
      if (c.hostRx && o.length >= 3) o = o.replace(c.hostRx, (m, pre, h) => pre + hostDisp(h, ctx));
    }
    return o;
  }

  function scrubString(s, ctx) {
    if (typeof s !== 'string' || !s) return s;
    if (/^(?:https?|wss?|ftp):\/\//i.test(s)) return scrubUrl(s, ctx, 0);
    if (/^data:/i.test(s)) return scrubDataUri(s, ctx);
    return scrubText(s, ctx, false);
  }
  function scrubDataUri(u, ctx) {
    if (!ctx.c.meta.dataUris || u.length < 256) return u;
    const m = /^(data:[^,]*,)/i.exec(u);
    const head = m ? m[1] : 'data:,';
    inc(ctx, 'dataUris');
    return head + '[' + (u.length - head.length) + ' chars removed]';
  }

  /* ---------- URLs, queries, forms ---------- */
  function keySens(name, ctx) {
    const c = ctx.c;
    if (!c.keysOn) return 0;
    const n = normName(name);
    if (!n) return 0;
    if (c.keyNames.has(n)) return 2;
    if (c.pii && c.piiNames.has(n)) return 2;
    if (c.keyHeur && SENS_RE.test(n)) return 1;
    return 0;
  }
  function paramSens(name, ctx) {
    const c = ctx.c;
    if (!c.parOn) return 0;
    const n = normName(name);
    if (!n || c.parKeep.has(n)) return 0;
    if (c.parNames.has(n)) return 2;
    if (c.parHeur && SENS_RE.test(n)) return 1;
    return 0;
  }
  // mode: 'url' (query/fragment) or 'form' (urlencoded body). Works on the DECODED value.
  function scrubParamDecoded(name, dec, ctx, depth, mode) {
    if (typeof dec !== 'string' || dec === '' || isPlaceholder(dec)) return dec;
    const sens = mode === 'url' ? paramSens(name, ctx) : keySens(name, ctx);
    if (sens) return red(ctx, mode === 'url' ? 'params' : 'bodykeys', dec, true);
    if (ctx.c.det.entropy && !ctx.noEnt && looksSecret(dec, ctx.c.entMin)) return red(ctx, 'entropy', dec, true);
    if (depth < 3 && /^[a-z][a-z0-9+.\-]*:\/\//i.test(dec)) return scrubUrl(dec, ctx, depth + 1);
    return scrubText(dec, ctx, true);
  }
  function scrubQuery(qs, ctx, depth, mode) {
    if (!qs) return qs;
    return qs.split('&').map(p => {
      if (!p) return p;
      const eq = p.indexOf('=');
      if (eq < 0) return p;
      const rn = p.slice(0, eq), rv = p.slice(eq + 1);
      if (rv === '') return p;
      const name = safeDec(rn.replace(/\+/g, ' '));
      const dec = safeDec(rv.replace(/\+/g, ' '));
      const out = scrubParamDecoded(name, dec, ctx, depth, mode);
      return out === dec ? p : rn + '=' + encodeURIComponent(out);
    }).join('&');
  }
  function scrubAuthority(auth, ctx) {
    const c = ctx.c;
    const at = auth.lastIndexOf('@');
    let ui = '', hp = auth;
    if (at >= 0) { ui = auth.slice(0, at); hp = auth.slice(at + 1); }
    let host = hp, port = '', bracket = false;
    if (hp.charAt(0) === '[') {
      const e = hp.indexOf(']');
      if (e > 0) { host = hp.slice(1, e); port = hp.slice(e + 1); bracket = true; }
    } else {
      const col = hp.lastIndexOf(':');
      if (col >= 0 && /^:\d*$/.test(hp.slice(col))) { host = hp.slice(0, col); port = hp.slice(col); }
    }
    let hostOut = host;
    const lower = host.toLowerCase();
    if (isIPv4(lower)) {
      if (c.det.ipv4 && !(c.keepPriv && isPrivateV4(lower))) hostOut = red(ctx, 'ipv4', lower, true);
    } else if (isIPv6(lower)) {
      if (c.det.ipv6 && !(c.keepPriv && isPrivateV6(lower))) hostOut = red(ctx, 'ipv6', lower, true);
    } else if (lower !== 'localhost' && host) {
      hostOut = hostDisp(host, ctx);
    }
    let uiOut = '';
    if (at >= 0) {
      if (c.creds && ui && !isPlaceholder(ui)) uiOut = red(ctx, 'urlcreds', ui, true) + '@';
      else uiOut = scrubText(ui, ctx, true) + '@';
    }
    return uiOut + (bracket ? '[' + hostOut + ']' : hostOut) + port;
  }
  function scrubPath(p, ctx) {
    if (!p) return p;
    let o = scrubText(p, ctx, true);
    if (ctx.c.det.entropy && !ctx.noEnt && o.length >= 20) {
      o = o.split('/').map(seg => {
        if (seg.length >= 20) { const d = safeDec(seg); if (looksSecret(d, ctx.c.entMin)) return red(ctx, 'entropy', d, true); }
        return seg;
      }).join('/');
    }
    return o;
  }
  function scrubUrl(u, ctx, depth) {
    if (typeof u !== 'string' || !u) return u;
    if (/^data:/i.test(u)) return scrubDataUri(u, ctx);
    const m = RX_URL.exec(u);
    if (!m) return scrubText(u, ctx, true);
    const scheme = m[1], auth = m[2], path = m[3], query = m[4], frag = m[5];
    let out = '';
    if (scheme !== undefined) out += scheme + '//' + scrubAuthority(auth, ctx);
    out += scrubPath(path || '', ctx);
    if (query) out += '?' + scrubQuery(query.slice(1), ctx, depth || 0, 'url');
    if (frag) {
      const f = frag.slice(1);
      out += '#' + (f.indexOf('=') >= 0 && ctx.c.frag ? scrubQuery(f, ctx, depth || 0, 'url') : scrubText(f, ctx, true));
    }
    return out;
  }

  /* ---------- headers & cookies ---------- */
  function headerSens(name, ctx) {
    const c = ctx.c;
    if (name.charAt(0) === ':') return false;
    const n = normName(name);
    if (c.hdrKeep.has(n)) return false;
    if (c.hdrNames.has(n)) return true;
    return c.hdrHeur && SENS_RE.test(n);
  }
  function redactHeaderValue(name, v, ctx) {
    if (v === '' || isPlaceholder(v)) return v;
    if (/^(?:proxy-)?authorization$/i.test(name)) {
      const m = /^([A-Za-z][\w.-]{0,24})\s+([\s\S]+)$/.exec(v);
      if (m) return isPlaceholder(m[2]) ? v : m[1] + ' ' + red(ctx, 'headers', m[2], false);
    }
    return red(ctx, 'headers', v, false);
  }
  function scrubCookieHeader(v, ctx) {
    const c = ctx.c, out = [];
    v.split(/;\s*/).forEach(p => {
      if (!p) return;
      const eq = p.indexOf('=');
      if (eq < 0) { out.push(p); return; }
      const name = p.slice(0, eq).trim();
      const val = p.slice(eq + 1);
      if (c.cookKeep.has(name.toLowerCase()) || val === '' || isPlaceholder(val)) { out.push(p); return; }
      if (c.cookRemove) { inc(ctx, 'cookies'); return; }
      out.push(name + '=' + red(ctx, 'cookies', val, false));
    });
    return out.length ? out.join('; ') : null;
  }
  function scrubSetCookie(v, ctx) {
    const c = ctx.c;
    const idx = v.indexOf(';');
    const first = idx < 0 ? v : v.slice(0, idx), rest = idx < 0 ? '' : v.slice(idx);
    const eq = first.indexOf('=');
    if (eq < 0) return scrubText(v, ctx, true);
    const name = first.slice(0, eq).trim(), val = first.slice(eq + 1);
    const restOut = scrubText(rest, ctx, true);
    if (c.cookKeep.has(name.toLowerCase()) || val === '' || isPlaceholder(val)) return first + restOut;
    if (c.cookRemove) { inc(ctx, 'cookies'); return null; }
    return name + '=' + red(ctx, 'cookies', val, false) + restOut;
  }
  function scrubHeaders(arr, ctx) {
    const c = ctx.c, out = [];
    for (let i = 0; i < arr.length; i++) {
      const h = arr[i];
      if (!h || typeof h !== 'object' || typeof h.name !== 'string' || typeof h.value !== 'string') { out.push(h); continue; }
      const ln = h.name.toLowerCase(), v = h.value;
      if (ln === 'cookie' && c.cookOn) {
        const r = scrubCookieHeader(v, ctx);
        if (r !== null) { h.value = r; out.push(h); }
        continue;
      }
      if (ln === 'set-cookie' && c.cookOn) {
        const r = scrubSetCookie(v, ctx);
        if (r !== null) { h.value = r; out.push(h); }
        continue;
      }
      if (c.hdrOn && headerSens(h.name, ctx)) { h.value = redactHeaderValue(h.name, v, ctx); out.push(h); continue; }
      if (ln === 'user-agent' && c.ua) { if (v) { inc(ctx, 'ua'); h.value = '[REDACTED]'; } out.push(h); continue; }
      if (ctx.shiftMs && DATE_HEADERS.has(ln)) { h.value = shiftHttpDate(v, ctx.shiftMs); out.push(h); continue; }
      if (URL_HDRS.has(ln)) h.value = scrubUrl(v, ctx, 0);
      else if (c.det.entropy && !ctx.noEnt && ln.indexOf('x-') === 0 && looksSecret(v, c.entMin)) h.value = red(ctx, 'entropy', v, false);
      else h.value = scrubString(v, ctx);
      out.push(h);
    }
    return out;
  }
  function scrubCookieArray(arr, ctx) {
    const c = ctx.c, out = [];
    for (let i = 0; i < arr.length; i++) {
      const ck = arr[i];
      if (!ck || typeof ck !== 'object') { out.push(ck); continue; }
      const nm = String(ck.name || '').toLowerCase();
      if (!c.cookKeep.has(nm)) {
        if (c.cookRemove) { inc(ctx, 'cookies'); continue; }
        if (typeof ck.value === 'string' && ck.value !== '' && !isPlaceholder(ck.value)) ck.value = red(ctx, 'cookies', ck.value, false);
      }
      if (typeof ck.domain === 'string') ck.domain = scrubText(ck.domain, ctx, true);
      if (typeof ck.expires === 'string' && ctx.shiftMs) ck.expires = shiftDate(ck.expires, ctx.shiftMs);
      out.push(ck);
    }
    return out;
  }
  function scrubQueryArray(arr, ctx) {
    arr.forEach(p => {
      if (p && typeof p === 'object' && typeof p.value === 'string') p.value = scrubParamDecoded(String(p.name || ''), p.value, ctx, 0, 'url');
    });
    return arr;
  }

  /* ---------- bodies ---------- */
  // segs: key path with arrays collapsed (users.profile.nick); asegs: array-aware ("#" per array level).
  // A key-path pattern matches either form, so both users.profile.nick and users.*.profile.nick work.
  // Strings that themselves contain JSON, form data, or base64-encoded JSON (common in logging / analytics payloads).
  function nestedString(s, ctx) {
    if (s.length < 8 || s.length > 4000000 || (ctx.nest || 0) >= 3) return null;
    const t = s.trim(), f = t.charAt(0);
    ctx.nest = (ctx.nest || 0) + 1;
    try {
      if (f === '{' || f === '[') {
        let p; try { p = JSON.parse(t); } catch (e) { return null; }
        const st = { ch: false };
        p = walkJson(p, ctx, [], 0, st);
        return st.ch ? JSON.stringify(p) : null;
      }
      if (t.indexOf('=') > 0 && !/\s/.test(t) && /^[A-Za-z_][\w.\-\[\]%]*=/.test(t)) {
        const key = t.slice(0, t.indexOf('='));
        let dk = key; try { dk = decodeURIComponent(key); } catch (e) { /* keep raw */ }
        if (t.indexOf('&') > 0 || keySens(dk, ctx)) { const r = scrubQuery(t, ctx, 0, 'form'); return r !== t ? r : null; }
        return null;
      }
      if (t.length >= 16 && /^[A-Za-z0-9+\/_-]+={0,2}$/.test(t)) {
        const std = t.replace(/-/g, '+').replace(/_/g, '/');
        const dec = b64ToText(std + '==='.slice((std.length + 3) % 4));
        const g = dec ? dec.trim().charAt(0) : '';
        if (g === '{' || g === '[') {
          let p; try { p = JSON.parse(dec); } catch (e) { return null; }
          const st = { ch: false };
          p = walkJson(p, ctx, [], 0, st);
          return st.ch ? textToB64(JSON.stringify(p)) : null;
        }
      }
      return null;
    } finally { ctx.nest--; }
  }
  function walkJson(node, ctx, segs, lvl, st, asegs) {
    const c = ctx.c;
    asegs = asegs || [];
    if (typeof node === 'string') {
      if (node === '' || isPlaceholder(node)) return node;
      if (lvl) { st.ch = true; return red(ctx, 'bodykeys', node, false); }
      const nested = nestedString(node, ctx);
      if (nested !== null) { st.ch = true; return nested; }
      const r = (c.det.entropy && !ctx.noEnt && looksSecret(node, c.entMin)) ? red(ctx, 'entropy', node, false) : scrubString(node, ctx);
      if (r !== node) st.ch = true;
      return r;
    }
    if (typeof node === 'number') {
      if (lvl === 2) { st.ch = true; return red(ctx, 'bodykeys', String(node), false); }
      return node;
    }
    if (Array.isArray(node)) {
      const na = c.keyPaths.length ? asegs.concat('#') : asegs;
      for (let i = 0; i < node.length; i++) node[i] = walkJson(node[i], ctx, segs, lvl, st, na);
      return node;
    }
    if (node && typeof node === 'object') {
      const keys = Object.keys(node);
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        let l = lvl;
        const s = keySens(k, ctx);
        if (s > l) l = s;
        let nsegs = segs, nas = asegs;
        if (c.keyPaths.length) {
          nsegs = segs.concat(k); nas = asegs.concat(k);
          if (pathMatch(c.keyPaths, nsegs) || pathMatch(c.keyPaths, nas)) l = 2;
        }
        node[k] = walkJson(node[k], ctx, nsegs, l, st, nas);
      }
    }
    return node;
  }
  function scrubJsonish(text, ctx) {
    return text.replace(/"((?:[^"\\]|\\.){1,80})"(\s*:\s*)("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?)/g, (m, key, colon, val) => {
      const s = keySens(key, ctx);
      if (!s) return m;
      if (val.charAt(0) === '"') {
        const inner = val.slice(1, -1);
        if (inner === '' || isPlaceholder(inner)) return m;
        return '"' + key + '"' + colon + '"' + red(ctx, 'bodykeys', inner, false) + '"';
      }
      return s === 2 ? '"' + key + '"' + colon + '"' + red(ctx, 'bodykeys', val, false) + '"' : m;
    });
  }
  function scrubMultipart(text, mime, ctx) {
    const bm = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(mime || '');
    if (!bm) return null;
    const boundary = '--' + (bm[1] || bm[2]);
    const segs = text.split(boundary);
    if (segs.length < 3) return null;
    const c = ctx.c;
    for (let i = 1; i < segs.length; i++) {
      let seg = segs[i];
      if (seg.slice(0, 2) === '--') continue;
      const lead = /^\r?\n/.exec(seg);
      const leadStr = lead ? lead[0] : '';
      const rest = seg.slice(leadStr.length);
      const he = /\r?\n\r?\n/.exec(rest);
      if (!he) continue;
      const headers = rest.slice(0, he.index), sep = he[0];
      let body = rest.slice(he.index + sep.length);
      const tm = /(\r?\n)$/.exec(body);
      const trail = tm ? tm[1] : '';
      if (trail) body = body.slice(0, body.length - trail.length);
      const nm = /name="([^"]*)"/i.exec(headers), fm = /filename="([^"]*)"/i.exec(headers);
      const ctm = /content-type:\s*([^\r\n;]+)/i.exec(headers);
      let hOut = headers;
      if (fm) hOut = headers.replace(/filename="([^"]*)"/i, (mm, f) => 'filename="' + scrubText(f, ctx, true) + '"');
      let bOut;
      if (fm && c.dropUploads && body.length) { inc(ctx, 'uploads'); bOut = '[file removed: ' + body.length + ' chars]'; }
      else if (nm && keySens(nm[1], ctx) && body !== '' && !isPlaceholder(body)) bOut = red(ctx, 'bodykeys', body, false);
      else bOut = scrubBodyText(body, ctm ? ctm[1] : 'text/plain', ctx);
      segs[i] = leadStr + hOut + sep + bOut + trail;
    }
    return segs.join(boundary);
  }
  function scrubBodyText(text, mime, ctx) {
    if (typeof text !== 'string' || !text) return text;
    const b = mimeBase(mime);
    if (b === 'application/x-www-form-urlencoded') return scrubQuery(text, ctx, 0, 'form');
    if (b === 'multipart/form-data') {
      const r = scrubMultipart(text, mime, ctx);
      if (r !== null) return r;
    }
    const first = text.replace(/^\s+/, '').charAt(0);
    if ((/json/.test(b) || (/^(?:|text\/plain|application\/octet-stream)$/.test(b))) && (first === '{' || first === '[')) {
      let parsed, ok = true;
      try { parsed = JSON.parse(text); } catch (e) { ok = false; }
      if (ok) {
        const st = { ch: false };
        try {
          parsed = walkJson(parsed, ctx, [], 0, st);
          if (!st.ch) return text;
          const im = /^\s*[\{\[]\s*\n([ \t]+)/.exec(text);
          return JSON.stringify(parsed, null, im ? Math.min(8, im[1].length) : 0);
        } catch (e) { /* too deep — fall through to text scrubbing */ }
      }
    }
    return scrubText(scrubJsonish(text, ctx), ctx, false);
  }
  function scrubPostData(pd, ctx) {
    const c = ctx.c;
    if (!pd || typeof pd !== 'object') return pd;
    if (c.meta.comments) delete pd.comment;
    if (c.dropReq) {
      if (pd.text || (pd.params && pd.params.length)) inc(ctx, 'reqBodiesDropped');
      delete pd.text; delete pd.params;
      pd.comment = 'request body removed by HAR Sanitizer';
      return pd;
    }
    if (Array.isArray(pd.params)) {
      pd.params.forEach(p => {
        if (!p || typeof p !== 'object') return;
        const hasVal = typeof p.value === 'string' && p.value !== '';
        if (p.fileName) {
          if (c.dropUploads && hasVal) { inc(ctx, 'uploads'); p.value = '[file removed: ' + p.value.length + ' chars]'; }
          p.fileName = scrubText(String(p.fileName), ctx, true);
        }
        if (hasVal && !/^\[file removed/.test(p.value)) {
          const s = keySens(String(p.name || ''), ctx);
          p.value = s && !isPlaceholder(p.value) ? red(ctx, 'bodykeys', p.value, false)
            : (mimeBase(pd.mimeType) === 'application/x-www-form-urlencoded' ? scrubParamDecoded(String(p.name || ''), p.value, ctx, 0, 'form') : scrubString(p.value, ctx));
        }
      });
    }
    if (typeof pd.text === 'string' && pd.text) pd.text = scrubBodyText(pd.text, pd.mimeType, ctx);
    if (c.vendor) stripVendor(pd, ctx);
    return pd;
  }
  function scrubContent(ct, ctx) {
    const c = ctx.c;
    if (!ct || typeof ct !== 'object') return ct;
    if (c.meta.comments) delete ct.comment;
    const cat = mimeCat(ct.mimeType), dt = c.dropTypes;
    if (c.vendor) stripVendor(ct, ctx);
    if (typeof ct.text !== 'string' || !ct.text) return ct;
    if (dt.all || (dt.images && cat === 'images') || (dt.fonts && cat === 'fonts') || (dt.media && cat === 'media') || (dt.binary && cat === 'binary')) {
      delete ct.text; delete ct.encoding;
      ct.comment = 'response body removed by HAR Sanitizer';
      inc(ctx, 'bodiesDropped');
      return ct;
    }
    const isB64 = ct.encoding === 'base64';
    let text = ct.text;
    if (isB64) {
      if (!isTextMime(ct.mimeType)) return ct;
      const dec = b64ToText(text);
      if (dec === null) return ct;
      text = dec;
    }
    const out = scrubBodyText(text, ct.mimeType, ctx);
    if (out !== text) ct.text = isB64 ? textToB64(out) : out;
    return ct;
  }
  function stripVendor(obj, ctx) {
    Object.keys(obj).forEach(k => {
      if (k.charAt(0) === '_' && !VENDOR_KEEP.has(k)) { delete obj[k]; inc(ctx, 'vendor'); }
    });
  }

  /* ---------- whole entries ---------- */
  const SKIP = new Set(['request.url', 'request.headers', 'request.cookies', 'request.queryString', 'request.postData',
    'response.headers', 'response.cookies', 'response.redirectURL', 'response.content', '_webSocketMessages']);
  function deepScrub(node, ctx, path) {
    const c = ctx.c;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const v = node[i];
        if (typeof v === 'string') node[i] = scrubString(v, ctx);
        else if (v && typeof v === 'object') deepScrub(v, ctx, path);
      }
      return;
    }
    Object.keys(node).forEach(k => {
      const p = path ? path + '.' + k : k;
      if (SKIP.has(p)) return;
      if (c.comments && k === 'comment') { delete node[k]; inc(ctx, 'comments'); return; }
      if (c.vendor && k.charAt(0) === '_' && !VENDOR_KEEP.has(k)) { delete node[k]; inc(ctx, 'vendor'); return; }
      const v = node[k];
      if (typeof v === 'string') node[k] = k === 'startedDateTime' ? shiftDate(v, ctx.shiftMs) : scrubString(v, ctx);
      else if (v && typeof v === 'object') deepScrub(v, ctx, p);
    });
  }
  const STATIC_EXT = /\.(?:woff2?|ttf|otf|eot|png|jpe?g|gif|webp|avif|svg|ico|bmp|css|m?js|map)$/i;
  /** Fonts, images, CSS and JS: files whose names and URLs are full of build hashes, not secrets. */
  function isStaticEntry(e) {
    const req = (e && e.request) || {}, res = (e && e.response) || {};
    const url = typeof req.url === 'string' ? req.url : '';
    if (url && !/^data:/i.test(url) && STATIC_EXT.test(url.split(/[?#]/)[0])) return true;
    const b = mimeBase(res.content && res.content.mimeType);
    if (!b) return false;
    const cat = mimeCat(b);
    return cat === 'images' || cat === 'fonts' || b === 'text/css' || /(?:java|ecma)script/.test(b);
  }
  function processEntry(e, ctx) {
    if (!e || typeof e !== 'object') return e;
    ctx.noEnt = !!(ctx.c.skipStatic && isStaticEntry(e));
    if (ctx.noEnt) ctx.staticSkipped = (ctx.staticSkipped || 0) + 1;
    try { return processEntryInner(e, ctx); } finally { ctx.noEnt = false; }
  }
  function processEntryInner(e, ctx) {
    const c = ctx.c;
    const req = e.request, res = e.response;
    if (req && typeof req === 'object') {
      if (c.meta.comments) delete req.comment;
      if (typeof req.url === 'string') req.url = scrubUrl(req.url, ctx, 0);
      if (Array.isArray(req.headers)) req.headers = scrubHeaders(req.headers, ctx);
      if (Array.isArray(req.cookies) && c.cookOn) req.cookies = scrubCookieArray(req.cookies, ctx);
      if (Array.isArray(req.queryString)) req.queryString = scrubQueryArray(req.queryString, ctx);
      if (req.postData) req.postData = scrubPostData(req.postData, ctx);
    }
    if (res && typeof res === 'object') {
      if (c.meta.comments) delete res.comment;
      if (Array.isArray(res.headers)) res.headers = scrubHeaders(res.headers, ctx);
      if (Array.isArray(res.cookies) && c.cookOn) res.cookies = scrubCookieArray(res.cookies, ctx);
      if (typeof res.redirectURL === 'string') res.redirectURL = scrubUrl(res.redirectURL, ctx, 0);
      if (res.content) res.content = scrubContent(res.content, ctx);
    }
    if (c.meta.serverIp) delete e.serverIPAddress;
    if (c.meta.connection) delete e.connection;
    if (c.vendor) { if (req) stripVendor(req, ctx); if (res) stripVendor(res, ctx); }
    if (Array.isArray(e._webSocketMessages) && !c.vendor) {
      e._webSocketMessages.forEach(m => {
        if (m && typeof m.data === 'string' && m.opcode !== 2) m.data = scrubBodyText(m.data, 'application/json', ctx);
      });
    }
    deepScrub(e, ctx, '');
    return e;
  }
  function hostOfUrl(u) {
    if (typeof u !== 'string') return '';
    const m = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/(?:[^\/?#@]*@)?(\[[^\]]+\]|[^\/?#:]+)/.exec(u);
    return m ? m[1].replace(/^\[|\]$/g, '').toLowerCase() : '';
  }
  function entryDropReason(e, c) {
    if (!e || typeof e !== 'object') return null;
    const req = e.request || {}, res = e.response || {};
    const url = typeof req.url === 'string' ? req.url : '';
    const host = hostOfUrl(url);
    if (host && hostMatches(c.hostDrop, host)) return 'host';
    if (c.filt.options && String(req.method || '').toUpperCase() === 'OPTIONS') return 'options';
    if (c.filt.failed && (res.status === 0 || res.status === undefined)) return 'failed';
    if (c.filt.dropImages || c.filt.dropFonts || c.filt.dropMedia) {
      const cat = mimeCat(res.content && res.content.mimeType);
      if ((c.filt.dropImages && cat === 'images') || (c.filt.dropFonts && cat === 'fonts') || (c.filt.dropMedia && cat === 'media')) return 'mime';
    }
    if (c.urlSubs.length) {
      const lu = url.toLowerCase();
      for (let i = 0; i < c.urlSubs.length; i++) if (lu.indexOf(c.urlSubs[i]) >= 0) return 'url';
    }
    return null;
  }
  function processLog(log, entriesOut, ctx) {
    const c = ctx.c;
    const rest = {};
    Object.keys(log).forEach(k => { if (k !== 'entries') rest[k] = deepClone(log[k]); });
    if (Array.isArray(rest.pages) && c.meta.pageTitles) rest.pages.forEach((p, i) => { if (p && typeof p === 'object') p.title = 'Page ' + (i + 1); });
    deepScrub(rest, ctx, 'log');
    if (c.meta.creator) { rest.creator = { name: 'HAR Sanitizer (Run Local Tools)', version: '1.0' }; delete rest.browser; }
    rest.entries = entriesOut;
    return rest;
  }
  function cloneEntry(e) {
    try { return structuredClone(e); } catch (err) { return JSON.parse(JSON.stringify(e)); }
  }

  const engine = { isStaticEntry, DEF, PRESETS, CATS, KIND, KIND_NAMES, compile, makeCtx, processEntry, processLog, entryDropReason, hostOfUrl,
    scrubText, scrubUrl, scrubQuery, scrubBodyText, scrubHeaders, scrubCookieHeader, scrubSetCookie, walkJson, looksSecret, cardOk,
    isIPv4, isIPv6, replaceEmails, parseCustomRegexes, globMatch, pathMatch, normName, deepMerge, deepClone, cloneEntry, mimeCat,
    isPlaceholder, shannon, hostMatches, b64ToText, textToB64, parsePaths, hash8, isTextMime };

  /* ---------- drivers (async, time-sliced so the tab stays responsive) ---------- */
  const yieldUI = () => new Promise(r => setTimeout(r, 0));
  // Hosts worth masking up-front: request URL first (so numbering follows request order), then other places hosts hide.
  function seedHostsOf(e) {
    const out = [];
    if (!e || typeof e !== 'object') return out;
    const push = u => { const h = hostOfUrl(u); if (h) out.push(h); };
    const rq = e.request, rs = e.response;
    if (rq && typeof rq === 'object') {
      push(rq.url);
      if (Array.isArray(rq.headers)) rq.headers.forEach(h => { if (h && URL_HDRS.has(String(h.name).toLowerCase())) push(h.value); });
      if (Array.isArray(rq.cookies)) rq.cookies.forEach(k => { if (k && typeof k.domain === 'string' && k.domain) out.push(normHost(k.domain.replace(/^\./, ''))); });
    }
    if (rs && typeof rs === 'object') {
      push(rs.redirectURL);
      if (Array.isArray(rs.headers)) rs.headers.forEach(h => { if (h && URL_HDRS.has(String(h.name).toLowerCase())) push(h.value); });
      if (Array.isArray(rs.cookies)) rs.cookies.forEach(k => { if (k && typeof k.domain === 'string' && k.domain) out.push(normHost(k.domain.replace(/^\./, ''))); });
    }
    if (e._initiator && typeof e._initiator === 'object') push(e._initiator.url);
    return out.filter(Boolean);
  }
  async function runEngine(entries, log, cfg, opts) {
    opts = opts || {};
    const probe = compile(cfg);
    const keepIdx = [], dropped = {}, seedHosts = [], seen = new Set(), hostCounts = new Map();
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      const h = hostOfUrl(e && e.request && e.request.url);
      if (opts.hostCounts && h) hostCounts.set(h, (hostCounts.get(h) || 0) + 1);
      const r = entryDropReason(e, probe);
      if (r) { dropped[r] = (dropped[r] || 0) + 1; continue; }
      keepIdx.push(i);
      if (probe.hostMode === 'pseudo') seedHostsOf(e).forEach(x => { if (!seen.has(x)) { seen.add(x); seedHosts.push(x); } });
    }
    const ctx = makeCtx(cfg, { collect: opts.collect, findings: opts.findings, salt: opts.salt, shiftMs: opts.shiftMs, seedHosts: seedHosts });
    const out = [], outIdx = [];
    let t0 = Date.now();
    for (let n = 0; n < keepIdx.length; n++) {
      if (opts.isCancelled && opts.isCancelled()) return null;
      const i = keepIdx[n];
      const clone = cloneEntry(entries[i]);
      processEntry(clone, ctx);
      out.push(clone); outIdx.push(i);
      if (Date.now() - t0 > 25) {
        if (opts.onProgress) opts.onProgress(n + 1, keepIdx.length);
        await yieldUI(); t0 = Date.now();
      }
    }
    const logOut = processLog(log, out, ctx);
    return { log: logOut, outIdx: outIdx, ctx: ctx, dropped: dropped, hostCounts: hostCounts };
  }
  function allTypesOff() { return { images: false, fonts: false, media: false, binary: false, all: false }; }
  function scanCfg(cfg) {
    const s = deepClone(cfg);
    s.style = 'fixed'; s.keepValues = '';
    s.cookies.on = true; s.cookies.mode = 'redact';
    s.headers.on = true; s.headers.heur = true;
    s.params.on = true; s.params.heur = true; s.params.frag = true;
    s.creds = true;
    s.body.keys = true; s.body.heur = true; s.body.embed = true; s.body.dropReq = false; s.body.dropUploads = false; s.body.dropTypes = allTypesOff();
    Object.assign(s.det, { jwt: true, apikeys: true, pem: true, bearer: true, card: true, email: true, ipv4: true, ipv6: true, phone: true, ssn: true, ids: true, entropy: true });
    s.hosts = { mode: 'keep', keep: cfg.hosts.keep, drop: '', trackers: false };
    Object.keys(s.meta).forEach(k => { s.meta[k] = false; });
    s.filt = { options: false, failed: false, dropImages: false, dropFonts: false, dropMedia: false, urlSubs: '' };
    return s;
  }
  function residualCfg(cfg) {
    const r = scanCfg(cfg);
    r.det.phone = false; r.det.ssn = false; r.det.entropy = false; r.det.ids = !!cfg.det.ids;
    r.det.keepPrivate = cfg.det.keepPrivate;
    r.keepValues = cfg.keepValues; // values the user chose to keep are not leaks
    r.hosts.keep = cfg.hosts.keep;
    r.literals = cfg.literals; r.regexes = cfg.regexes;
    return r;
  }
  function sumStats(stats) {
    let t = 0;
    CATS.forEach(c => { t += stats[c[0]] || 0; });
    return t;
  }
  async function checkSecrets(outLog, secrets) {
    const res = secrets.map(s => ({ secret: s, count: 0, where: null }));
    const variants = secrets.map(s => {
      const v = [s, JSON.stringify(s).slice(1, -1), encodeURIComponent(s)];
      return Array.from(new Set(v)).filter(x => x.length);
    });
    const entries = outLog.entries || [];
    const rest = JSON.stringify(Object.assign({}, outLog, { entries: [] }));
    function scan(text, where) {
      secrets.forEach((s, k) => {
        variants[k].forEach(v => {
          let i = -1;
          while ((i = text.indexOf(v, i + 1)) >= 0) { res[k].count++; if (!res[k].where) res[k].where = where; }
        });
      });
    }
    scan(rest, 'log metadata');
    let t0 = Date.now();
    for (let n = 0; n < entries.length; n++) {
      const e = entries[n];
      scan(JSON.stringify(e), 'entry #' + (n + 1));
      const ct = e && e.response && e.response.content;
      if (ct && ct.encoding === 'base64' && typeof ct.text === 'string' && isTextMime(ct.mimeType)) {
        const dec = b64ToText(ct.text);
        if (dec) scan(dec, 'entry #' + (n + 1) + ' (decoded response body)');
      }
      if (Date.now() - t0 > 25) { await yieldUI(); t0 = Date.now(); }
    }
    return res;
  }
  function fmtBytes(n) { return (typeof TK !== 'undefined' && TK.formatBytes) ? TK.formatBytes(n) : n + ' B'; }
  function buildReport(info) {
    const L = [];
    L.push('HAR Sanitizer — redaction report');
    L.push('Generated: ' + new Date().toString());
    L.push('File: ' + info.name);
    L.push('Entries: ' + info.entriesBefore + ' → ' + info.entriesAfter + '   Size: ' + fmtBytes(info.sizeBefore) + ' → ' + fmtBytes(info.sizeAfter));
    L.push('Placeholder style: ' + info.style);
    L.push('');
    L.push('Values redacted (counts only — no secret values are listed in this report):');
    let any = false;
    CATS.forEach(c => { const n = info.stats[c[0]] || 0; if (n) { any = true; L.push('  ' + c[1] + ': ' + n); } });
    [['hosts', 'Hostname occurrences masked'], ['ua', 'User-Agent headers redacted'], ['uploads', 'Uploaded file contents removed'],
      ['bodiesDropped', 'Response bodies removed'], ['reqBodiesDropped', 'Request bodies removed'], ['dataUris', 'Large data: URIs shortened'],
      ['vendor', 'Browser-specific (_) fields removed'], ['comments', 'Comment fields removed']].forEach(p => {
      const n = info.stats[p[0]] || 0; if (n) { any = true; L.push('  ' + p[1] + ': ' + n); }
    });
    Object.keys(info.dropped || {}).forEach(k => { any = true; L.push('  Entries dropped (' + k + '): ' + info.dropped[k]); });
    if (!any) L.push('  (nothing matched)');
    L.push('');
    if (info.residual) {
      L.push('Residual check (high-confidence patterns): ' + (info.residual.total ? info.residual.total + ' possible leftover value(s) found' : 'nothing found'));
      CATS.forEach(c => { const n = info.residual.stats[c[0]] || 0; if (n) L.push('  ' + c[1] + ': ' + n); });
    }
    L.push('');
    L.push('Limits: pattern matching cannot recognise every kind of secret. Review the sanitized file before sharing it.');
    return L.join('\n');
  }

export { engine, runEngine, scanCfg, residualCfg, sumStats, checkSecrets, buildReport, DEF, PRESETS, CATS, deepMerge, deepClone };

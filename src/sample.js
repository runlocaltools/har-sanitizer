// Built-in sample HAR. Every "secret" below is fake. It exists so a new user can see the tool work in seconds.
const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
export const SAMPLE_SECRETS = {
  session: 'sess_FAKE_9f8a7b6c5d4e3f2a1b0c', bearer: 'tok_FAKE_4eC39HqLyjWDarjtT1zdp7dc', apiKey: 'FAKE-k7f3a9c1e5b2d8046a1c3e5f7',
  queryToken: 'qt_FAKE_aB3dE5gH7jK9mN1pQ3sT5vX7', password: 'Not-A-Real-Passw0rd!', jwt: JWT, awsKey: 'AKIAIOSFODNN7EXAMPLE',
  email: 'sample.user@example.com', card: '4242424242424242'
};
export const SAMPLE_HASH_IN_STATIC = 'aB3dE5gH7jK9mN1pQ3sT5vX7';
export function makeSampleHar() {
  const S = SAMPLE_SECRETS;
  const e = (url, method, extra, t) => Object.assign({
    startedDateTime: '2026-03-01T10:00:' + String(t || 0).padStart(2, '0') + '.000Z', time: 120, serverIPAddress: '203.0.113.9', connection: '443',
    request: { method, url, httpVersion: 'HTTP/2', headers: [], queryString: [], cookies: [], headersSize: -1, bodySize: 0 },
    response: { status: 200, statusText: 'OK', httpVersion: 'HTTP/2', headers: [], cookies: [], content: { size: 0, mimeType: 'application/json' }, redirectURL: '', headersSize: -1, bodySize: 0 },
    cache: {}, timings: { send: 1, wait: 100, receive: 19 }
  }, extra || {});
  const login = e('https://shop.example.com/api/login', 'POST', {}, 1);
  login.request.headers = [{ name: 'Content-Type', value: 'application/json' }, { name: 'User-Agent', value: 'Mozilla/5.0 (sample)' }];
  login.request.postData = { mimeType: 'application/json', text: JSON.stringify({ email: S.email, password: S.password, remember: true }) };
  login.response.headers = [{ name: 'Set-Cookie', value: 'session=' + S.session + '; HttpOnly; Secure' }, { name: 'Content-Type', value: 'application/json' }];
  login.response.content = { size: 300, mimeType: 'application/json', text: JSON.stringify({ ok: true, id_token: S.jwt, user: { id: 7, name: 'Sample User', email: S.email } }) };

  const me = e('https://shop.example.com/api/me?token=' + S.queryToken + '&page=2&lang=en', 'GET', {}, 2);
  me.request.headers = [{ name: 'Authorization', value: 'Bearer ' + S.bearer }, { name: 'Cookie', value: 'session=' + S.session + '; lang=en' }, { name: 'X-Api-Key', value: S.apiKey }, { name: 'Accept', value: 'application/json' }];
  me.request.cookies = [{ name: 'session', value: S.session }, { name: 'lang', value: 'en' }];
  me.request.queryString = [{ name: 'token', value: S.queryToken }, { name: 'page', value: '2' }, { name: 'lang', value: 'en' }];
  me.response.content = { size: 120, mimeType: 'application/json', text: JSON.stringify({ user: { id: 7, email: S.email }, aws_key: S.awsKey, plan: 'pro' }) };

  const pay = e('https://shop.example.com/api/checkout', 'POST', {}, 3);
  pay.request.headers = [{ name: 'Authorization', value: 'Bearer ' + S.bearer }, { name: 'Content-Type', value: 'application/json' }];
  pay.request.postData = { mimeType: 'application/json', text: JSON.stringify({ card_number: S.card, amount: 4999, currency: 'usd' }) };
  pay.response.status = 402; pay.response.statusText = 'Payment Required';
  pay.response.content = { size: 40, mimeType: 'application/json', text: JSON.stringify({ error: 'card_declined', code: 'insufficient_funds' }) };

  // Static files: build hashes and cache-busters live here. Balanced leaves them readable; Thorough redacts them.
  const font = e('https://shop.example.com/fonts/inter-var.woff2?v=' + SAMPLE_HASH_IN_STATIC, 'GET', {}, 4);
  font.response.content = { size: 10, mimeType: 'font/woff2', text: 'd09GMgABAAAAAA==', encoding: 'base64' };
  const js = e('https://shop.example.com/assets/chunk-9fK2xQ7mVb3LpZr8TnA4.js', 'GET', {}, 5);
  js.response.content = { size: 60, mimeType: 'text/javascript', text: 'export const version = "2026.03"; console.log("app ready");' };
  const css = e('https://shop.example.com/assets/app.css?rev=Zq8Xw3Lm9Pv2Tn7Kb4Rc6', 'GET', {}, 6);
  css.response.content = { size: 30, mimeType: 'text/css', text: 'body{margin:0;font-family:system-ui}' };
  const img = e('https://cdn.example.com/img/logo.png', 'GET', {}, 7);
  img.response.content = { size: 10, mimeType: 'image/png', encoding: 'base64', text: 'iVBORw0KGgo=' };

  return { log: { version: '1.2', creator: { name: 'Sample (fake data)', version: '1' }, pages: [], entries: [login, me, pay, font, js, css, img] } };
}

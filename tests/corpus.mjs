// Synthetic HAR with planted secrets. Every value in SECRETS must NOT survive sanitizing.
export const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
export const SECRETS = {
  cookie: 'sess_9f8a7b6c5d4e3f2a1b0c',
  bearer: 'tok_live_4eC39HqLyjWDarjtT1zdp7dc',
  apiKeyHeader: 'k_7f3a9c1e5b2d8046a1c3e5f7',
  queryToken: 'qt_aB3dE5gH7jK9mN1pQ3sT5vX7',
  password: 'Sup3r$ecretPassw0rd!',
  jwt: JWT,
  awsKey: 'AKIAIOSFODNN7EXAMPLE',
  email: 'jane.doe@acmecorp.com',
  card: '4242424242424242',
  clientSecret: 'cs_Zx9Yw8Vv7Uu6Tt5Ss4Rr3Qq2',
  urlCred: 'hunter2pass',
  formPass: 'F0rmP@ssValue99',
  gqlToken: 'gql_Tk_1234567890abcdefABCDEF'
};
export function makeHar() {
  const S = SECRETS;
  const e = (url, method, extra) => Object.assign({
    startedDateTime: '2026-03-01T10:00:00.000Z', time: 120, serverIPAddress: '203.0.113.9', connection: '443',
    request: { method, url, httpVersion: 'HTTP/2', headers: [], queryString: [], cookies: [], headersSize: -1, bodySize: 0 },
    response: { status: 200, statusText: 'OK', httpVersion: 'HTTP/2', headers: [], cookies: [], content: { size: 0, mimeType: 'application/json' }, redirectURL: '', headersSize: -1, bodySize: 0 },
    cache: {}, timings: { send: 1, wait: 100, receive: 19 }
  }, extra || {});
  const a = e('https://api.acmecorp.com/v1/me?token=' + S.queryToken + '&page=2', 'GET');
  a.request.headers = [{ name: 'Cookie', value: 'session=' + S.cookie + '; lang=en' }, { name: 'Authorization', value: 'Bearer ' + S.bearer }, { name: 'X-Api-Key', value: S.apiKeyHeader }, { name: 'Accept', value: 'application/json' }];
  a.request.cookies = [{ name: 'session', value: S.cookie }, { name: 'lang', value: 'en' }];
  a.request.queryString = [{ name: 'token', value: S.queryToken }, { name: 'page', value: '2' }];
  a.response.headers = [{ name: 'Set-Cookie', value: 'session=' + S.cookie + '; HttpOnly; Secure' }, { name: 'Content-Type', value: 'application/json' }];
  a.response.content = { size: 200, mimeType: 'application/json', text: JSON.stringify({ user: { id: 7, email: S.email, id_token: S.jwt }, aws: S.awsKey, ok: true }) };

  const b = e('https://api.acmecorp.com/v1/login', 'POST');
  b.request.postData = { mimeType: 'application/json', text: JSON.stringify({ username: 'jane', password: S.password, client_secret: S.clientSecret, card_number: S.card }) };
  b.response.content = { size: 50, mimeType: 'application/json', text: JSON.stringify({ access_token: S.jwt, refresh_token: S.bearer }) };

  const c = e('https://user:' + S.urlCred + '@legacy.acmecorp.com/feed', 'GET');

  const d = e('https://auth.acmecorp.com/form', 'POST');
  d.request.postData = { mimeType: 'application/x-www-form-urlencoded', text: 'user=jane&password=' + encodeURIComponent(S.formPass) + '&remember=1', params: [{ name: 'user', value: 'jane' }, { name: 'password', value: S.formPass }] };

  const g = e('https://api.acmecorp.com/graphql', 'POST');
  g.request.postData = { mimeType: 'application/json', text: JSON.stringify({ query: 'mutation($t:String!){login(token:$t){id}}', variables: { token: S.gqlToken } }) };

  const bin = e('https://cdn.acmecorp.com/logo.png', 'GET');
  bin.response.content = { size: 10, mimeType: 'image/png', encoding: 'base64', text: 'iVBORw0KGgo=' };

  return { log: { version: '1.2', creator: { name: 'WebInspector', version: '537.36' }, pages: [], entries: [a, b, c, d, g, bin] } };
}

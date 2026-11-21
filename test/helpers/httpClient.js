import http from 'node:http';

/** Minimal HTTP/1.1 client (one connection per request) returning { status, headers, text, json, cookies }. */
export function call(base, method, path, { headers = {}, body, rawBody } = {}) {
  return new Promise((resolve, reject) => {
    const payload = rawBody ?? (body === undefined ? undefined : JSON.stringify(body));
    const req = http.request(base + path, {
      method, agent: false,
      headers: { ...(payload !== undefined && !('content-type' in headers) ? { 'content-type': 'application/json' } : {}), ...(payload !== undefined ? { 'content-length': Buffer.byteLength(payload) } : {}), connection: 'close', ...headers },
    }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => {
        let json; try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode, headers: res.headers, text, json, cookies: res.headers['set-cookie'] ?? [] });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}
export const cookieOf = (r) => (r.cookies[0] ?? '').split(';')[0];
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

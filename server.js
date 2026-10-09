'use strict';
// Mekuria Prep backend: zero dependencies, uses only Node.js built-ins.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

try { process.loadEnvFile(); } catch { /* no .env file, use real environment variables */ }

const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = path.resolve(process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json'));
const CORS_ORIGIN = process.env.CORS_ORIGIN || '';
const PUBLIC_DIR = path.join(__dirname, 'public');
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const SUBJECTS = ['Mathematics', 'English', 'Physics', 'Biology'];
const TOKEN_DAYS = 7;
if (!process.env.JWT_SECRET) console.warn('JWT_SECRET is not set: using a temporary secret, so everyone is logged out on restart.');

// ---------- storage (JSON file; swap for a real database when you grow) ----------
let db = { users: [], results: [] };
try { db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { /* first run */ }
function persist() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DATA_FILE); // atomic replace, no half-written file
}

// ---------- passwords and tokens ----------
async function hashPw(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return salt + ':' + (await scrypt(pw, salt, 64)).toString('hex');
}
async function checkPw(pw, stored) {
  const [salt, hex] = stored.split(':');
  const key = await scrypt(pw, salt, 64);
  const expected = Buffer.from(hex, 'hex');
  return expected.length === key.length && crypto.timingSafeEqual(expected, key);
}
const DUMMY_HASH = hashPw('dummy-password'); // keeps login timing the same for unknown emails
const b64 = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const sign = (data) => crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
function makeToken(id) {
  const h = b64({ alg: 'HS256', typ: 'JWT' });
  const p = b64({ sub: id, exp: Date.now() + TOKEN_DAYS * 864e5 });
  return `${h}.${p}.${sign(h + '.' + p)}`;
}
function readToken(token) {
  const [h, p, s] = String(token).split('.');
  if (!s) return null;
  const a = Buffer.from(s), b = Buffer.from(sign(h + '.' + p));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const d = JSON.parse(Buffer.from(p, 'base64url')); return d.exp > Date.now() ? d : null; } catch { return null; }
}

// ---------- http helpers ----------
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
function send(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0, big = false;
    req.on('data', (c) => { size += c.length; if (size > 10_000) big = true; else chunks.push(c); });
    req.on('end', () => {
      if (big) return reject(new HttpError(413, 'Request too large'));
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks)) : {}); } catch { reject(new HttpError(400, 'Invalid JSON')); }
    });
    req.on('error', reject);
  });
}
const hits = new Map();
setInterval(() => { const t = Date.now(); for (const [k, v] of hits) if (v.reset < t) hits.delete(k); }, 60_000).unref();
function rateLimit(req) {
  const ip = req.socket.remoteAddress || 'unknown', now = Date.now();
  const max = Number(process.env.AUTH_RATE_LIMIT) || 20;
  let h = hits.get(ip);
  if (!h || h.reset < now) { h = { n: 0, reset: now + 60_000 }; hits.set(ip, h); }
  if (++h.n > max) throw new HttpError(429, 'Too many attempts. Please wait a minute and try again.');
}
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });
function requireUser(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  const t = m && readToken(m[1]);
  const user = t && db.users.find((u) => u.id === t.sub);
  if (!user) throw new HttpError(401, 'Please log in');
  return user;
}

// ---------- API routes: each returns [status, data] ----------
const routes = {
  'GET /api/health': async () => [200, { ok: true }],

  'POST /api/register': async (req, body) => {
    rateLimit(req);
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const pw = String(body.password || '');
    if (name.length < 2 || name.length > 60) throw new HttpError(400, 'Enter your full name (2 to 60 characters)');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) throw new HttpError(400, 'Enter a valid email address');
    if (pw.length < 8 || pw.length > 100) throw new HttpError(400, 'Password must be 8 to 100 characters');
    const password = await hashPw(pw);
    if (db.users.some((u) => u.email === email)) throw new HttpError(409, 'This email is already registered. Try logging in');
    const user = { id: crypto.randomUUID(), name, email, password, createdAt: Date.now() };
    db.users.push(user); persist();
    return [201, { token: makeToken(user.id), user: publicUser(user) }];
  },

  'POST /api/login': async (req, body) => {
    rateLimit(req);
    const email = String(body.email || '').trim().toLowerCase();
    const user = db.users.find((u) => u.email === email);
    const ok = await checkPw(String(body.password || ''), user ? user.password : await DUMMY_HASH);
    if (!user || !ok) throw new HttpError(401, 'Incorrect email or password');
    return [200, { token: makeToken(user.id), user: publicUser(user) }];
  },

  'GET /api/me': async (req) => [200, { user: publicUser(requireUser(req)) }],

  'GET /api/results': async (req) => {
    const u = requireUser(req);
    const results = db.results.filter((r) => r.userId === u.id).slice(-200).map(({ subject, score, total, date }) => ({ subject, score, total, date }));
    return [200, { results }];
  },

  'POST /api/results': async (req, body) => {
    const u = requireUser(req);
    const { subject, score, total } = body;
    if (!SUBJECTS.includes(subject) || !Number.isInteger(total) || total < 1 || total > 50 || !Number.isInteger(score) || score < 0 || score > total)
      throw new HttpError(400, 'Invalid exam result');
    const r = { id: crypto.randomUUID(), userId: u.id, subject, score, total, date: Date.now() };
    db.results.push(r); persist();
    return [201, { result: { subject, score, total, date: r.date } }];
  },
};

// ---------- static files ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";
function serveStatic(pathname, req, res) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { throw new HttpError(400, 'Bad request'); }
  if (rel.includes('\0')) throw new HttpError(400, 'Bad request');
  if (rel.endsWith('/')) rel += 'index.html';
  const file = path.join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) throw new HttpError(403, 'Forbidden');
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': CSP });
    res.end(req.method === 'HEAD' ? undefined : buf);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const cors = CORS_ORIGIN ? { 'Access-Control-Allow-Origin': CORS_ORIGIN, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', Vary: 'Origin' } : {};
  try {
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
    if (url.pathname.startsWith('/api/')) {
      const handler = routes[req.method + ' ' + url.pathname];
      if (!handler) throw new HttpError(404, 'Not found');
      const body = req.method === 'POST' ? await readBody(req) : {};
      const [status, data] = await handler(req, body);
      return send(res, status, data, { ...cors, 'Cache-Control': 'no-store' });
    }
    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(url.pathname, req, res);
    throw new HttpError(405, 'Method not allowed');
  } catch (e) {
    if (!e.status) console.error(e);
    send(res, e.status || 500, { error: e.status ? e.message : 'Server error' }, cors);
  }
});

if (require.main === module) server.listen(PORT, () => console.log(`Mekuria Prep running at http://localhost:${PORT}`));
module.exports = { server };

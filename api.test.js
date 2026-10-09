'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');

process.env.DATA_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mp-')), 'db.json');
process.env.JWT_SECRET = 'test-secret';
process.env.AUTH_RATE_LIMIT = '1000';
const { server } = require('../server');

let base;
test.before(() => new Promise((r) => server.listen(0, () => { base = 'http://127.0.0.1:' + server.address().port; r(); })));
test.after(() => { server.closeAllConnections?.(); server.close(); });

async function call(p, method = 'GET', body, token) {
  const r = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body && JSON.stringify(body) });
  return { status: r.status, data: await r.json().catch(() => null) };
}
const abebe = { name: 'Abebe Kebede', email: 'Abebe@Example.com', password: 'tikur-buna-1' };
let token;

test('register validates input', async () => {
  assert.equal((await call('/api/register', 'POST', { ...abebe, name: 'A' })).status, 400);
  assert.equal((await call('/api/register', 'POST', { ...abebe, email: 'nope' })).status, 400);
  assert.equal((await call('/api/register', 'POST', { ...abebe, password: 'short' })).status, 400);
});
test('register creates an account and rejects duplicates', async () => {
  const r = await call('/api/register', 'POST', abebe);
  assert.equal(r.status, 201); assert.ok(r.data.token);
  assert.equal(r.data.user.email, 'abebe@example.com');
  assert.equal(r.data.user.password, undefined);
  assert.equal((await call('/api/register', 'POST', abebe)).status, 409);
});
test('login works only with the right password', async () => {
  assert.equal((await call('/api/login', 'POST', { email: abebe.email, password: 'wrong-password' })).status, 401);
  assert.equal((await call('/api/login', 'POST', { email: 'who@example.com', password: 'whatever123' })).status, 401);
  const r = await call('/api/login', 'POST', { email: abebe.email, password: abebe.password });
  assert.equal(r.status, 200); token = r.data.token;
});
test('protected routes need a valid token', async () => {
  assert.equal((await call('/api/me')).status, 401);
  assert.equal((await call('/api/me', 'GET', null, token + 'x')).status, 401);
  assert.equal((await call('/api/me', 'GET', null, token)).data.user.name, 'Abebe Kebede');
});
test('results are saved per user and validated', async () => {
  assert.equal((await call('/api/results', 'POST', { subject: 'Physics', score: 4, total: 5 }, token)).status, 201);
  assert.equal((await call('/api/results', 'POST', { subject: 'Cooking', score: 4, total: 5 }, token)).status, 400);
  assert.equal((await call('/api/results', 'POST', { subject: 'Physics', score: 9, total: 5 }, token)).status, 400);
  const mine = await call('/api/results', 'GET', null, token);
  assert.equal(mine.data.results.length, 1);
  const other = (await call('/api/register', 'POST', { name: 'Sara Tesfaye', email: 'sara@example.com', password: 'enjera-2024' })).data.token;
  assert.equal((await call('/api/results', 'GET', null, other)).data.results.length, 0);
});
test('serves the frontend and blocks path traversal', async () => {
  const home = await fetch(base + '/');
  assert.equal(home.status, 200);
  assert.match(await home.text(), /Mekuria Prep/);
  assert.notEqual((await fetch(base + '/..%2fserver.js')).status, 200);
});

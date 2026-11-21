// Offline: the .env.demo checker passes a correct file, names every kind of mistake, and NEVER prints a value.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { evaluate, parseEnv, summarize } from '../scripts/check-demo-env.mjs';
import { pgUrl } from './helpers/fakeSecrets.js';

const PW = 'Zq7' + 'xK2mVb9' + 'LpR4tYw8dN'; // fake, 24 chars, assembled at runtime
const good = (host = 'ep-test-123456.us-west-2.aws.neon.tech', q = '?sslmode=require&channel_binding=require', pw = PW) => pgUrl('neondb_owner', pw, `${host}/neondb${q}`);
const file = (url, datapack = 'trusttrace-demo') => `DATABASE_URL=${url}\nMEKO_DATAPACK=${datapack}\n`;
const run = (text, extra = {}) => evaluate({ text, gitIgnored: true, tracked: false, devDatabaseUrl: 'postgres://u:p@localhost:5432/dev', ...extra });
const failedNames = (results) => results.filter(([, ok]) => !ok).map(([n]) => n);
const passes = (text, extra) => failedNames(run(text, extra)).length === 0;

describe('check-demo-env', () => {
  test('a correct file passes every check', () => { assert.deepEqual(failedNames(run(file(good()))), []); assert.equal(summarize(run(file(good()))), 'CONFIG CHECK: PASSED'); });
  test('CRLF line endings and comments are fine', () => { assert.ok(passes(`# demo\r\nDATABASE_URL=${good()}\r\nMEKO_DATAPACK=trusttrace-demo\r\n`)); });

  const bad = [
    ['missing file', null, /exists/],
    ['host not on neon.tech', file(good('db.example.com')), /neon\.tech/],
    ['look-alike host (neon.tech.evil.com)', file(good('ep-x.neon.tech.evil.com')), /neon\.tech/],
    ['localhost (the development database)', file(good('localhost')), /neon\.tech|local/],
    ['pooled endpoint', file(good('ep-test-123456-pooler.us-west-2.aws.neon.tech')), /DIRECT/],
    ['no TLS requirement', file(good(undefined, '')), /TLS/],
    ['sslmode=disable', file(good(undefined, '?sslmode=disable')), /TLS/],
    ['sslmode=prefer', file(good(undefined, '?sslmode=prefer')), /TLS/],
    ['wrong datapack (the existing test datapack)', file(good(), 'trusttrace-test'), /MEKO_DATAPACK/],
    ['placeholder password', file(good(undefined, undefined, 'password')), /placeholder|password/],
    ['short password', file(good(undefined, undefined, 'abc123')), /password/],
    ['wrapped in quotes', file(`"${good()}"`), /bare URL/],
    ['psql prefix pasted', file(`psql '${good()}'`), /bare URL/],
    ['extra key (e.g. a Meko key pasted by mistake)', `${file(good())}MEKO_API_KEY=x\n`, /only DATABASE_URL/],
    ['duplicate key', `${file(good())}DATABASE_URL=${good()}\n`, /twice|only DATABASE_URL/],
    ['not a URL', file('not a url at all'), /bare URL|parses/],
    ['non-default port', file(good('ep-test-123456.us-west-2.aws.neon.tech:6543')), /port/],
    ['wrong scheme', file(good().replace('postgres://', 'mysql://')), /PostgreSQL URL/],
  ];
  for (const [name, text, expected] of bad) {
    test(`FAILS: ${name}`, () => {
      const names = failedNames(run(text));
      assert.ok(names.length > 0, 'should fail');
      assert.ok(names.some((n) => expected.test(n)), `expected a failed check matching ${expected}, got: ${names.join(' | ')}`);
    });
  }
  test('FAILS when the file is not git-ignored, and when it is tracked', () => {
    assert.ok(failedNames(run(file(good()), { gitIgnored: false })).some((n) => /ignored/.test(n)));
    assert.ok(failedNames(run(file(good()), { tracked: true })).some((n) => /not tracked/.test(n)));
  });
  test('FAILS when it equals the development database URL', () => {
    assert.ok(failedNames(run(file(good()), { devDatabaseUrl: good() })).some((n) => /development/.test(n)));
  });
  test('a byte-order mark is reported (it would corrupt the first key for --env-file)', () => {
    assert.ok(failedNames(run('﻿' + file(good()))).some((n) => /byte-order/.test(n)));
  });
  test('parseEnv: comments, blanks, duplicates, unparseable lines', () => {
    const p = parseEnv('# c\n\nA=1\nA=2\nnot a pair\nB=x=y\n');
    assert.deepEqual(p.keys, ['A', 'A', '<<unparseable line>>', 'B']); assert.deepEqual(p.duplicates, ['A']); assert.equal(p.values.get('B'), 'x=y');
  });
  test('summaries contain only check names, never values', () => {
    const s = summarize(run(file(good('db.example.com', '?sslmode=disable')), {}));
    assert.match(s, /^CONFIG CHECK: FAILED/);
    for (const secret of [PW, 'db.example.com', 'neondb_owner', 'neondb', 'channel_binding']) assert.ok(!s.includes(secret), `leaked ${secret}`);
  });

  test('the command-line tool prints only PASSED/FAILED and never a value (real process, real file)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tt-envcheck-'));
    try {
      const script = resolve('scripts/check-demo-env.mjs');
      const f = join(dir, '.env.demo');
      writeFileSync(f, file(good('db.example.com')));
      const r = spawnSync(process.execPath, [script, f], { cwd: dir, encoding: 'utf8' });
      assert.equal(r.status, 1);
      const all = r.stdout + r.stderr;
      assert.match(all, /CONFIG CHECK: FAILED/);
      for (const secret of [PW, 'db.example.com', 'neondb_owner', 'sslmode=require']) assert.ok(!all.includes(secret), `leaked ${secret}`);
      const missing = spawnSync(process.execPath, [script, join(dir, 'nope')], { cwd: dir, encoding: 'utf8' });
      assert.equal(missing.status, 1); assert.match(missing.stdout, /FAILED/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

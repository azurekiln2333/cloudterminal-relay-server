// Pure parsing / pool-construction tests: no network I/O.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { loadDbConfig } from '../src/db/config.ts';
import { createDbPool, poolFromConfig } from '../src/db/pool.ts';

describe('db config', () => {
  it('is disabled when no DB_* variable is present', () => {
    const result = loadDbConfig({});
    assert.equal(result.state, 'disabled');
    assert.equal(result.config, null);
    assert.match(result.message, /DB_/);
  });

  it('is degraded when required variables are missing', () => {
    const result = loadDbConfig({ DB_HOST: '127.0.0.1', DB_USER: 'ct' });
    assert.equal(result.state, 'degraded');
    assert.equal(result.config, null);
    assert.match(result.message, /DB_NAME/);
  });

  it('is ready with defaults when the minimum is set', () => {
    const result = loadDbConfig({ DB_HOST: '127.0.0.1', DB_USER: 'ct', DB_NAME: 'cloudterminal' });
    assert.equal(result.state, 'ready');
    if (result.state !== 'ready') return;
    assert.equal(result.config.port, 3306);
    assert.equal(result.config.connectionLimit, 10);
    assert.equal(result.config.connectTimeoutMs, 10_000);
    assert.deepEqual(result.config.tls, { enabled: false });
    assert.equal(result.config.password, '');
  });

  it('rejects a bad port', () => {
    assert.throws(
      () => loadDbConfig({ DB_HOST: 'h', DB_USER: 'u', DB_NAME: 'd', DB_PORT: '70000' }),
      /DB_PORT/,
    );
    assert.throws(
      () => loadDbConfig({ DB_HOST: 'h', DB_USER: 'u', DB_NAME: 'd', DB_PORT: 'abc' }),
      /DB_PORT/,
    );
  });

  it('rejects out-of-range timeouts and limits', () => {
    const base = { DB_HOST: 'h', DB_USER: 'u', DB_NAME: 'd' };
    assert.throws(() => loadDbConfig({ ...base, DB_CONNECT_TIMEOUT_MS: '5' }), /DB_CONNECT_TIMEOUT_MS/);
    assert.throws(() => loadDbConfig({ ...base, DB_CONNECTION_LIMIT: '0' }), /DB_CONNECTION_LIMIT/);
  });

  it('parses DB_TLS booleans', () => {
    const base = { DB_HOST: 'h', DB_USER: 'u', DB_NAME: 'd' };
    const on = loadDbConfig({ ...base, DB_TLS: 'true' });
    assert.equal(on.state, 'ready');
    if (on.state === 'ready') assert.deepEqual(on.config.tls, { enabled: true, caFile: null });
    const off = loadDbConfig({ ...base, DB_TLS: 'false' });
    if (off.state === 'ready') assert.deepEqual(off.config.tls, { enabled: false });
    assert.throws(() => loadDbConfig({ ...base, DB_TLS: 'maybe' }), /DB_TLS/);
  });

  it('carries a CA file when TLS is on', () => {
    const result = loadDbConfig({
      DB_HOST: 'h',
      DB_USER: 'u',
      DB_NAME: 'd',
      DB_TLS: '1',
      DB_TLS_CA_FILE: '/etc/ssl/ca.pem',
    });
    assert.equal(result.state, 'ready');
    if (result.state === 'ready') assert.deepEqual(result.config.tls, { enabled: true, caFile: '/etc/ssl/ca.pem' });
  });

  it('rejects a CA file without TLS enabled', () => {
    assert.throws(
      () => loadDbConfig({ DB_HOST: 'h', DB_USER: 'u', DB_NAME: 'd', DB_TLS_CA_FILE: '/ca.pem' }),
      /DB_TLS_CA_FILE/,
    );
  });
});

describe('db pool construction', () => {
  it('never connects at import time: a disabled config yields no pool', () => {
    const result = createDbPool({});
    assert.equal(result.state, 'disabled');
    assert.equal(result.pool, null);
  });

  it('builds a pool without dialling out, and DB_TLS=true without a CA file is accepted', () => {
    const parsed = loadDbConfig({ DB_HOST: '127.0.0.1', DB_USER: 'u', DB_NAME: 'd', DB_TLS: 'true' });
    assert.equal(parsed.state, 'ready');
    if (parsed.state !== 'ready') return;
    const pool = poolFromConfig(parsed.config);
    assert.equal(pool.state, 'ready');
    assert.equal(pool.closed, false);
    // Closing a pool that never connected must resolve without error.
    return pool.close();
  });

  it('exposes ping/close and rejects work after close', async () => {
    const parsed = loadDbConfig({ DB_HOST: '127.0.0.1', DB_USER: 'u', DB_NAME: 'd' });
    if (parsed.state !== 'ready') throw new Error('expected ready config');
    const pool = poolFromConfig(parsed.config);
    await pool.close();
    assert.equal(pool.closed, true);
    await assert.rejects(() => pool.ping(), /closed/);
    await assert.rejects(() => pool.query('select 1'), /closed/);
    // close is idempotent
    await pool.close();
  });
});

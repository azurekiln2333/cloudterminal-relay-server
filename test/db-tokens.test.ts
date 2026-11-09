// MySQL-backed token tests. Skips cleanly without a configured database.
//
// These assert the at-rest contract from PRD R17: only `sha256` hex is stored
// and the plaintext is returned exactly once.

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';

import { sha256Hex } from '../src/shared/crypto.ts';
import type { DbPool } from '../src/db/pool.ts';
import { countByHash, issueToken, purgeExpired, revokeToken, rotateRefresh, verifyToken } from '../src/db/tokens.ts';
import { SKIP_MESSAGE, mysqlConfigured, openTestPool, seedAccountDevice, truncateAll } from './db-helpers.ts';

const skip = mysqlConfigured() ? false : SKIP_MESSAGE;
const HOUR = 3_600_000;

describe('tokens', { skip }, () => {
  let pool: DbPool;

  before(async () => {
    const opened = await openTestPool();
    assert.ok(opened, SKIP_MESSAGE);
    pool = opened;
  });

  beforeEach(async () => {
    await truncateAll(pool);
    await seedAccountDevice(pool, 'acct-a', 'device-1');
  });

  after(async () => {
    await pool.close();
  });

  it('round-trips an issued token', async () => {
    const issued = await issueToken(pool, { accountId: 'acct-a', deviceId: 'device-1', kind: 'access', ttlMs: HOUR });
    assert.match(issued.token, /^ct_[A-Za-z0-9_-]{43}$/);
    const verified = await verifyToken(pool, issued.token);
    assert.ok(verified);
    assert.equal(verified.accountId, 'acct-a');
    assert.equal(verified.deviceId, 'device-1');
    assert.equal(verified.kind, 'access');
  });

  it('stores only the sha256 hash, never the plaintext', async () => {
    const issued = await issueToken(pool, { accountId: 'acct-a', kind: 'refresh', ttlMs: HOUR });
    assert.equal(issued.tokenHash, sha256Hex(issued.token));
    assert.equal(await countByHash(pool, issued.tokenHash), 1);
    const rows = await pool.query<{ token_hash: string; n: number } & import('mysql2').RowDataPacket>(
      'select token_hash, count(*) as n from ct_tokens group by token_hash',
    );
    for (const row of rows) {
      assert.notEqual(row.token_hash, issued.token, 'plaintext must not be stored');
      assert.match(row.token_hash, /^[0-9a-f]{64}$/);
    }
  });

  it('rejects unknown, empty and malformed tokens', async () => {
    assert.equal(await verifyToken(pool, 'ct_unknown'), null);
    assert.equal(await verifyToken(pool, ''), null);
    assert.equal(await verifyToken(pool, 'not-a-token'), null);
  });

  it('rejects an expired token', async () => {
    const issued = await issueToken(pool, { accountId: 'acct-a', kind: 'access', ttlMs: HOUR });
    await pool.execute('update ct_tokens set expires_at = current_timestamp - interval 1 second where token_hash = ?', [
      issued.tokenHash,
    ]);
    assert.equal(await verifyToken(pool, issued.token), null);
  });

  it('revokes immediately', async () => {
    const issued = await issueToken(pool, { accountId: 'acct-a', kind: 'access', ttlMs: HOUR });
    assert.equal(await revokeToken(pool, issued.token), true);
    assert.equal(await verifyToken(pool, issued.token), null);
    assert.equal(await revokeToken(pool, issued.token), false, 'second revoke is a no-op');
  });

  it('rotates a refresh token and forbids reuse of the old one', async () => {
    const issued = await issueToken(pool, { accountId: 'acct-a', deviceId: 'device-1', kind: 'refresh', ttlMs: HOUR });
    const rotated = await rotateRefresh(pool, issued.token, HOUR);
    assert.equal(rotated.ok, true);
    if (!rotated.ok) return;
    assert.notEqual(rotated.token.token, issued.token);
    assert.equal(await verifyToken(pool, issued.token), null, 'rotated token cannot be reused');
    const fresh = await verifyToken(pool, rotated.token.token);
    assert.ok(fresh);
    assert.equal(fresh.accountId, 'acct-a');
    assert.equal(fresh.kind, 'refresh');
  });

  it('refuses to rotate a non-refresh token or an unknown one', async () => {
    const access = await issueToken(pool, { accountId: 'acct-a', kind: 'access', ttlMs: HOUR });
    const wrongKind = await rotateRefresh(pool, access.token, HOUR);
    assert.equal(wrongKind.ok, false);
    if (!wrongKind.ok) assert.equal(wrongKind.reason, 'wrong_kind');
    const missing = await rotateRefresh(pool, 'ct_missing', HOUR);
    assert.equal(missing.ok, false);
    if (!missing.ok) assert.equal(missing.reason, 'invalid');
  });

  it('validates the ttl and kind', async () => {
    await assert.rejects(() => issueToken(pool, { accountId: 'acct-a', kind: 'access', ttlMs: 0 }), /ttlMs/);
    await assert.rejects(
      () => issueToken(pool, { accountId: 'acct-a', kind: 'bogus' as never, ttlMs: HOUR }),
      /kind/,
    );
  });

  it('purges expired rows', async () => {
    const issued = await issueToken(pool, { accountId: 'acct-a', kind: 'access', ttlMs: HOUR });
    const purgedNone = await purgeExpired(pool);
    assert.equal(purgedNone, 0);
    await pool.execute('update ct_tokens set expires_at = current_timestamp - interval 1 second where token_hash = ?', [
      issued.tokenHash,
    ]);
    const purged = await purgeExpired(pool);
    assert.equal(purged, 1);
    assert.equal(await countByHash(pool, issued.tokenHash), 0);
  });
});

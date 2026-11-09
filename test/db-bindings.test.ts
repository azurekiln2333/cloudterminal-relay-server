// MySQL-backed binding (M:N) tests. Skips cleanly without a configured database.

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';

import {
  createBinding,
  isBound,
  listAccountsForDevice,
  listDevicesForAccount,
  revokeBinding,
} from '../src/db/bindings.ts';
import type { DbPool } from '../src/db/pool.ts';
import { SKIP_MESSAGE, mysqlConfigured, openTestPool, seedAccountDevice, truncateAll } from './db-helpers.ts';

const skip = mysqlConfigured() ? false : SKIP_MESSAGE;

describe('bindings', { skip }, () => {
  let pool: DbPool;

  before(async () => {
    const opened = await openTestPool();
    assert.ok(opened, SKIP_MESSAGE);
    pool = opened;
  });

  beforeEach(async () => {
    await truncateAll(pool);
    await seedAccountDevice(pool, 'acct-a', 'device-1');
    await seedAccountDevice(pool, 'acct-b', 'device-1');
    await seedAccountDevice(pool, 'acct-a', 'device-2');
    await seedAccountDevice(pool, 'acct-c', 'device-3');
  });

  after(async () => {
    await pool.close();
  });

  it('creates many-to-many bindings', async () => {
    await createBinding(pool, { accountId: 'acct-a', deviceId: 'device-1', createdBy: 'pair_code' });
    await createBinding(pool, { accountId: 'acct-b', deviceId: 'device-1', createdBy: 'device_auth' });
    await createBinding(pool, { accountId: 'acct-a', deviceId: 'device-2', createdBy: 'admin' });

    const devicesA = await listDevicesForAccount(pool, 'acct-a');
    assert.deepEqual(devicesA.map((d) => d.deviceId).sort(), ['device-1', 'device-2']);
    const accounts = await listAccountsForDevice(pool, 'device-1');
    assert.deepEqual(accounts.map((a) => a.accountId).sort(), ['acct-a', 'acct-b']);
  });

  it('is idempotent on re-bind and reactivates a revoked row', async () => {
    await createBinding(pool, { accountId: 'acct-a', deviceId: 'device-1', createdBy: 'pair_code' });
    await createBinding(pool, { accountId: 'acct-a', deviceId: 'device-1', createdBy: 'pair_code' });
    const rows = await pool.query<{ n: number } & import('mysql2').RowDataPacket>(
      "select count(*) as n from ct_bindings where account_id = 'acct-a' and device_id = 'device-1'",
    );
    assert.equal(Number(rows[0]?.n), 1, 'unique key must prevent duplicate rows');

    await revokeBinding(pool, 'acct-a', 'device-1');
    assert.equal(await isBound(pool, 'acct-a', 'device-1'), false);
    await createBinding(pool, { accountId: 'acct-a', deviceId: 'device-1', createdBy: 'device_auth' });
    assert.equal(await isBound(pool, 'acct-a', 'device-1'), true);
  });

  it('revoking one binding leaves the other accounts on the device working', async () => {
    await createBinding(pool, { accountId: 'acct-a', deviceId: 'device-1', createdBy: 'pair_code' });
    await createBinding(pool, { accountId: 'acct-b', deviceId: 'device-1', createdBy: 'pair_code' });
    assert.equal(await revokeBinding(pool, 'acct-a', 'device-1'), true);
    assert.equal(await isBound(pool, 'acct-a', 'device-1'), false);
    assert.equal(await isBound(pool, 'acct-b', 'device-1'), true, 'AC4: other binding untouched');
    const remaining = await listAccountsForDevice(pool, 'device-1');
    assert.deepEqual(remaining.map((a) => a.accountId), ['acct-b']);
  });

  it('does not list revoked bindings', async () => {
    await createBinding(pool, { accountId: 'acct-c', deviceId: 'device-3', createdBy: 'admin' });
    await revokeBinding(pool, 'acct-c', 'device-3');
    assert.deepEqual(await listDevicesForAccount(pool, 'acct-c'), []);
    assert.deepEqual(await listAccountsForDevice(pool, 'device-3'), []);
  });

  it('keeps accounts isolated from each other', async () => {
    await createBinding(pool, { accountId: 'acct-a', deviceId: 'device-2', createdBy: 'admin' });
    assert.equal(await isBound(pool, 'acct-b', 'device-2'), false, 'AC1: cross-account access rejected');
    assert.equal(await isBound(pool, 'acct-a', 'device-3'), false);
  });

  it('rejects an invalid role or created_by before touching SQL', async () => {
    await assert.rejects(
      () => createBinding(pool, { accountId: 'acct-a', deviceId: 'device-1', createdBy: 'nope' as never }),
      /created_by/,
    );
    await assert.rejects(
      () => createBinding(pool, { accountId: 'acct-a', deviceId: 'device-1', role: 'root' as never, createdBy: 'admin' }),
      /role/,
    );
  });

  it('stores a display label and role', async () => {
    await createBinding(pool, {
      accountId: 'acct-a',
      deviceId: 'device-1',
      role: 'owner',
      label: 'work laptop',
      createdBy: 'admin',
    });
    const devices = await listDevicesForAccount(pool, 'acct-a');
    assert.equal(devices[0]?.role, 'owner');
    const accounts = await listAccountsForDevice(pool, 'device-1');
    assert.equal(accounts[0]?.label, 'work laptop');
  });
});

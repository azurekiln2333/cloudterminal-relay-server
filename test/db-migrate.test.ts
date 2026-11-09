// MySQL-backed migration tests. Skips cleanly without a configured database.

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { runMigrations, applyMigration, pendingVersions } from '../src/db/migrate.ts';
import { MIGRATIONS } from '../src/db/schema.sql.ts';
import type { DbPool } from '../src/db/pool.ts';
import { SKIP_MESSAGE, mysqlConfigured, openTestPool, rawQuery } from './db-helpers.ts';

const skip = mysqlConfigured() ? false : SKIP_MESSAGE;

describe('migrations', { skip }, () => {
  let pool: DbPool;

  before(async () => {
    const opened = await openTestPool();
    assert.ok(opened, SKIP_MESSAGE);
    pool = opened;
  });

  after(async () => {
    await pool.close();
  });

  it('creates every ct_ table', async () => {
    const rows = await rawQuery<{ table_name: string } & import('mysql2').RowDataPacket>(
      pool,
      "select table_name from information_schema.tables where table_schema = database() and table_name like 'ct\\_%'",
    );
    const names = new Set(rows.map((row) => row.table_name));
    for (const table of [
      'ct_schema_migrations',
      'ct_accounts',
      'ct_devices',
      'ct_bindings',
      'ct_tokens',
      'ct_oauth_states',
    ]) {
      assert.ok(names.has(table), `missing ${table}`);
    }
  });

  it('records the applied versions', async () => {
    const rows = await rawQuery<{ version: number } & import('mysql2').RowDataPacket>(
      pool,
      'select version from ct_schema_migrations order by version',
    );
    const versions = rows.map((row) => Number(row.version));
    for (const migration of MIGRATIONS) assert.ok(versions.includes(migration.version));
  });

  it('is a no-op when re-run', async () => {
    const first = await runMigrations(pool);
    const second = await runMigrations(pool);
    assert.deepEqual(first.skipped, []);
    assert.deepEqual(second.skipped, []);
    assert.deepEqual(first.applied, second.applied);
    const pending = await pendingVersions(pool);
    assert.deepEqual(pending, []);
  });

  it('rolls back the version row when a statement fails', async () => {
    await pool.execute('delete from ct_schema_migrations where version = 999');
    const broken = {
      version: 999,
      name: 'deliberately_broken',
      statements: ['create table if not exists ct_broken_test (id int primary key)', 'this is not sql'],
    };
    await assert.rejects(() =>
      pool.withTransaction((tx) => applyMigration(tx, broken)),
    );
    const rows = await rawQuery<{ n: number } & import('mysql2').RowDataPacket>(
      pool,
      'select count(*) as n from ct_schema_migrations where version = 999',
    );
    assert.equal(Number(rows[0]?.n), 0, 'failed migration must not be recorded');
    await pool.execute('drop table if exists ct_broken_test');
  });
});

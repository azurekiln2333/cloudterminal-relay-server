// Shared setup for the opt-in MySQL-backed suites.
//
// There is no test database server in CI by default, so every DB-backed test
// skips cleanly with an actionable message unless a connection is configured
// via `CT_TEST_MYSQL_URL` (or the `DB_*` variables). This keeps `npm test`
// green on a machine without MySQL.

import type { RowDataPacket } from 'mysql2';

import { createDbPool, type DbPool } from '../src/db/pool.ts';
import { runMigrations } from '../src/db/migrate.ts';

export const SKIP_MESSAGE =
  'no MySQL configured: set CT_TEST_MYSQL_URL (or DB_HOST/DB_USER/DB_NAME) to run this suite';

/** True when the environment supplies a test database. */
export function mysqlConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.CT_TEST_MYSQL_URL?.trim()) return true;
  return Boolean(env.DB_HOST?.trim() && env.DB_USER?.trim() && env.DB_NAME?.trim());
}

type ParsedUrl = {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
};

function parseUrl(url: string): ParsedUrl {
  const parsed = new URL(url);
  if (parsed.protocol !== 'mysql:') throw new Error('CT_TEST_MYSQL_URL must use the mysql:// scheme');
  return {
    host: parsed.hostname,
    port: parsed.port ? Number(parsed.port) : 3306,
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
    database: parsed.pathname.replace(/^\//, ''),
  };
}

/**
 * Build a pool for the test database and make sure the schema exists. Returns
 * `null` when no database is configured so callers can skip.
 */
export async function openTestPool(): Promise<DbPool | null> {
  const url = process.env.CT_TEST_MYSQL_URL?.trim();
  let pool: DbPool | null;
  if (url) {
    const parsed = parseUrl(url);
    pool = createDbPool({
      DB_HOST: parsed.host,
      DB_PORT: String(parsed.port),
      DB_USER: parsed.user,
      DB_PASSWORD: parsed.password,
      DB_NAME: parsed.database,
    }).pool;
  } else {
    pool = createDbPool().pool;
  }
  if (!pool) return null;
  await runMigrations(pool);
  return pool;
}

/**
 * Delete all application rows so each suite starts from a known state. Order
 * respects the foreign keys; DDL is left in place.
 */
export async function truncateAll(pool: DbPool): Promise<void> {
  await pool.execute('set foreign_key_checks = 0');
  try {
    for (const table of ['ct_bindings', 'ct_tokens', 'ct_oauth_states', 'ct_devices', 'ct_accounts']) {
      await pool.execute(`truncate table ${table}`);
    }
  } finally {
    await pool.execute('set foreign_key_checks = 1');
  }
}

/** Insert an account + device pair so bindings can be created in tests. */
export async function seedAccountDevice(
  pool: DbPool,
  accountId: string,
  deviceId: string,
  secretHash = 'a'.repeat(64),
): Promise<void> {
  await pool.execute(
    'insert into ct_accounts (account_id, issuer, display_name) values (?, ?, ?) on duplicate key update issuer = values(issuer)',
    [accountId, 'https://sso.test', `name-${accountId}`],
  );
  await pool.execute(
    `insert into ct_devices (device_id, label, platform, secret_hash) values (?, ?, ?, ?)
     on duplicate key update secret_hash = values(secret_hash)`,
    [deviceId, `label-${deviceId}`, 'linux', secretHash],
  );
}

/** Convenience for tests that need to read a raw cell. */
export async function rawQuery<T extends RowDataPacket>(pool: DbPool, sql: string, values: unknown[] = []): Promise<T[]> {
  return pool.query<T>(sql, values);
}

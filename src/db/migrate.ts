// Idempotent, versioned migrations for the `ct_*` schema.
//
// Programmatic entry: `runMigrations(pool)`.
// CLI entry: `node src/db/migrate.ts` (reads `DB_*` from the environment).
//
// DDL runs outside any request path and is never auto-applied by a query
// (PRD R15). Each version's statements run inside a transaction; the version
// row is inserted in the same transaction after the DDL succeeds, so a broken
// statement leaves `ct_schema_migrations` without that version and the next
// run retries it. MySQL auto-commits DDL regardless of the surrounding
// transaction, so an interrupted run may leave some already-created tables
// behind; every statement is `if not exists`, which makes the retry a no-op.

import { pathToFileURL } from 'node:url';
import type { RowDataPacket } from 'mysql2';

import { createDbPool, type DbPool } from './pool.ts';
import { MIGRATIONS, MIGRATIONS_TABLE_SQL, type Migration } from './schema.sql.ts';

export type MigrationResult = {
  applied: number[];
  skipped: number[];
};

const LOCK_NAME = 'ct_schema_migrations';

async function appliedVersions(pool: Pick<DbPool, 'query'>): Promise<Set<number>> {
  const rows = await pool.query<{ version: number } & RowDataPacket>(
    'select version from ct_schema_migrations',
  );
  return new Set(rows.map((row) => Number(row.version)));
}

/** Apply every migration not yet recorded. Re-running is a no-op. */
export async function runMigrations(pool: DbPool): Promise<MigrationResult> {
  if (pool.state !== 'ready') throw new Error(`cannot migrate: database is ${pool.state}`);

  await pool.execute(MIGRATIONS_TABLE_SQL);

  // Serialise concurrent migrators (multi-instance startup). The lock is
  // released when the connection closes; a throw still releases it because the
  // connection is returned to the pool and `GET_LOCK` is connection-scoped.
  await pool.withTransaction(async (tx) => {
    const lock = await tx.query<{ locked: number | null } & RowDataPacket>('select get_lock(?, 30) as locked', [
      LOCK_NAME,
    ]);
    if (Number(lock[0]?.locked) !== 1) {
      throw new Error('could not acquire migration lock; another migrator is running');
    }
    try {
      const done = await appliedVersions(tx);
      const ordered = [...MIGRATIONS].sort((a, b) => a.version - b.version);
      for (const migration of ordered) {
        if (done.has(migration.version)) continue;
        await applyMigration(tx, migration);
      }
    } finally {
      await tx.execute('select release_lock(?)', [LOCK_NAME]);
    }
  });

  const done = await appliedVersions(pool);
  const result: MigrationResult = { applied: [], skipped: [] };
  for (const migration of MIGRATIONS) {
    if (done.has(migration.version)) result.applied.push(migration.version);
    else result.skipped.push(migration.version);
  }
  return result;
}

/**
 * Run one version's statements and record it. Exported for tests that inject a
 * deliberately broken statement; normal callers use `runMigrations`.
 */
export async function applyMigration(
  tx: Pick<DbPool, 'execute'>,
  migration: Migration,
): Promise<void> {
  for (const statement of migration.statements) {
    await tx.execute(statement);
  }
  await tx.execute('insert into ct_schema_migrations (version, name) values (?, ?)', [
    migration.version,
    migration.name,
  ]);
}

/** Versions that are missing from the bookkeeping table. */
export async function pendingVersions(pool: DbPool): Promise<number[]> {
  await pool.execute(MIGRATIONS_TABLE_SQL);
  const done = await appliedVersions(pool);
  return MIGRATIONS.filter((m) => !done.has(m.version)).map((m) => m.version);
}

/** CLI: `node src/db/migrate.ts`. Fails loudly with a non-zero exit code. */
async function main(): Promise<void> {
  const { state, message, pool } = createDbPool();
  if (!pool) {
    console.error(`[migrate] database is ${state}: ${message}`);
    process.exitCode = state === 'disabled' ? 0 : 1;
    return;
  }
  try {
    const result = await runMigrations(pool);
    console.log(`[migrate] schema up to date; versions present: ${result.applied.join(', ') || 'none'}`);
  } catch (err) {
    console.error(`[migrate] failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  } finally {
    await pool.close();
  }
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  await main();
}

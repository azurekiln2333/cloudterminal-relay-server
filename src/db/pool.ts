// MySQL connection pool built from `DB_*`.
//
// The pool is created eagerly (cheap, opens no socket) but the first real
// connection happens on the first `query`/`execute`/`ping`, never at import
// time. This keeps the relay startable with an unreachable database (PRD R18).

import { readFileSync } from 'node:fs';
import mysql from 'mysql2/promise';
import type { Pool as MysqlPool, PoolConnection, RowDataPacket, ResultSetHeader } from 'mysql2/promise';

import { loadDbConfig, type DbConfig, type DbConfigResult, type DbState } from './config.ts';

/** Minimal typed surface the data-access layer depends on. */
export type DbPool = {
  readonly state: DbState;
  /** Execute a prepared statement. Values are always bound, never interpolated. */
  query<Row extends RowDataPacket = RowDataPacket>(sql: string, values?: readonly unknown[]): Promise<Row[]>;
  /** Execute a prepared statement returning write metadata. */
  execute(sql: string, values?: readonly unknown[]): Promise<ResultSetHeader>;
  /** Run `fn` inside a transaction, rolling back on any throw. */
  withTransaction<T>(fn: (tx: DbExecutor) => Promise<T>): Promise<T>;
  /** Cheap liveness check; throws when the database is unreachable. */
  ping(): Promise<void>;
  /** Close every pooled connection. Safe to call more than once. */
  close(): Promise<void>;
  /** Whether `close()` has run; further queries are rejected. */
  readonly closed: boolean;
};

/** The subset of the pool valid inside a transaction callback. */
export type DbExecutor = Pick<DbPool, 'query' | 'execute'>;

export type CreatePoolResult =
  | { state: 'disabled' | 'degraded'; message: string; pool: null }
  | { state: 'ready'; message: ''; pool: DbPool };

function sslOptions(config: DbConfig): { rejectUnauthorized: boolean; ca?: string } | undefined {
  if (!config.tls.enabled) return undefined;
  if (config.tls.caFile) {
    // readFileSync throws a contextual error if the path is wrong; that is a
    // startup misconfiguration, so failing loudly is correct.
    const ca = readFileSync(config.tls.caFile, 'utf8');
    return { rejectUnauthorized: true, ca };
  }
  // No CA file: trust the system root store.
  return { rejectUnauthorized: true };
}

/** Build a mysql2 pool from a resolved `DbConfig`. Does not dial out. */
export function poolFromConfig(config: DbConfig): DbPool {
  const inner: MysqlPool = mysql.createPool({
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password,
    database: config.database,
    connectionLimit: config.connectionLimit,
    connectTimeout: config.connectTimeoutMs,
    waitForConnections: true,
    enableKeepAlive: true,
    charset: 'utf8mb4_unicode_ci',
    // InnoDB + utf8mb4 is enforced by the migrations; keep dates as Dates.
    ssl: sslOptions(config),
  });

  let closed = false;

  const pool: DbPool = {
    state: 'ready',
    async query<Row extends RowDataPacket = RowDataPacket>(
      sql: string,
      values: readonly unknown[] = [],
    ): Promise<Row[]> {
      if (closed) throw new Error('database pool is closed');
      const [rows] = await inner.query<Row[]>(sql, values as unknown[]);
      return rows;
    },
    async execute(sql: string, values: readonly unknown[] = []): Promise<ResultSetHeader> {
      if (closed) throw new Error('database pool is closed');
      const [result] = await inner.execute<ResultSetHeader>(sql, values as unknown[]);
      return result;
    },
    async withTransaction<T>(fn: (tx: DbExecutor) => Promise<T>): Promise<T> {
      if (closed) throw new Error('database pool is closed');
      const conn: PoolConnection = await inner.getConnection();
      try {
        await conn.beginTransaction();
        const tx: DbExecutor = {
          async query<Row extends RowDataPacket = RowDataPacket>(
            sql: string,
            values: readonly unknown[] = [],
          ): Promise<Row[]> {
            const [rows] = await conn.query<Row[]>(sql, values as unknown[]);
            return rows;
          },
          async execute(sql: string, values: readonly unknown[] = []): Promise<ResultSetHeader> {
            const [result] = await conn.execute<ResultSetHeader>(sql, values as unknown[]);
            return result;
          },
        };
        const value = await fn(tx);
        await conn.commit();
        return value;
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }
    },
    async ping(): Promise<void> {
      if (closed) throw new Error('database pool is closed');
      await inner.query('select 1');
    },
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      await inner.end();
    },
    get closed() {
      return closed;
    },
  };
  return pool;
}

/**
 * Resolve `DB_*` and build a pool. Returns `{ pool: null }` for `disabled`
 * (no `DB_*` at all) and `degraded` (partial) configurations rather than
 * throwing, so callers can start the legacy relay and surface the state.
 * Invalid values still throw from `loadDbConfig`.
 */
export function createDbPool(env: NodeJS.ProcessEnv = process.env): CreatePoolResult {
  const result: DbConfigResult = loadDbConfig(env);
  if (result.state !== 'ready') return { state: result.state, message: result.message, pool: null };
  return { state: 'ready', message: '', pool: poolFromConfig(result.config) };
}

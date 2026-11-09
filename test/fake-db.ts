// In-memory `DbPool` stand-in for relay tenancy tests.
//
// The relay only needs `isBound` and `verifyToken` on the hot path, so instead
// of a real MySQL this fake answers those two queries directly. It exists so
// tenancy routing can be tested on machines without a database; the SQL itself
// is covered by the opt-in `db-*.test.ts` suites.

import type { RowDataPacket, ResultSetHeader } from 'mysql2/promise';
import type { DbPool } from '../src/db/pool.ts';
import { sha256Hex } from '../src/shared/crypto.ts';

export type FakeDbOptions = {
  /** Active bindings as `accountId\u0000deviceId`. */
  bindings?: Iterable<string>;
  /** Live tokens: plaintext token → accountId (+ optional device scope). */
  tokens?: Iterable<{ token: string; accountId: string; deviceId?: string | null }>;
  /** When set, every call rejects, simulating an unreachable database. */
  failWith?: Error;
};

export type FakeDb = DbPool & {
  bind(accountId: string, deviceId: string): void;
  unbind(accountId: string, deviceId: string): void;
  addToken(token: string, accountId: string, deviceId?: string | null): void;
  revokeToken(token: string): void;
  calls: number;
};

const BOUND = /from ct_bindings\s+where account_id = \? and device_id = \?/i;
const TOKEN = /from ct_tokens\s+where token_hash = \?/i;

export function createFakeDb(opts: FakeDbOptions = {}): FakeDb {
  const bindings = new Set<string>(opts.bindings ?? []);
  const tokens = new Map<string, { accountId: string; deviceId: string | null }>();
  for (const t of opts.tokens ?? []) tokens.set(sha256Hex(t.token), { accountId: t.accountId, deviceId: t.deviceId ?? null });
  let closed = false;
  const db: FakeDb = {
    state: 'ready',
    calls: 0,
    async query<Row extends RowDataPacket = RowDataPacket>(
      sql: string,
      values: readonly unknown[] = [],
    ): Promise<Row[]> {
      db.calls++;
      if (opts.failWith) throw opts.failWith;
      if (BOUND.test(sql)) {
        const [accountId, deviceId] = values as [string, string];
        return (bindings.has(`${accountId}\u0000${deviceId}`) ? [{ present: 1 }] : []) as unknown as Row[];
      }
      if (TOKEN.test(sql)) {
        const [tokenHash] = values as [string];
        const hit = tokens.get(tokenHash);
        return (hit
          ? [{ account_id: hit.accountId, device_id: hit.deviceId, kind: 'access', expires_at: new Date(Date.now() + 60_000) }]
          : []) as unknown as Row[];
      }
      return [] as unknown as Row[];
    },
    async execute(): Promise<ResultSetHeader> {
      db.calls++;
      if (opts.failWith) throw opts.failWith;
      return { affectedRows: 0 } as ResultSetHeader;
    },
    async withTransaction<T>(fn: (tx: { query: DbPool['query']; execute: DbPool['execute'] }) => Promise<T>) {
      return fn({ query: db.query.bind(db), execute: db.execute.bind(db) });
    },
    async ping() {
      if (opts.failWith) throw opts.failWith;
    },
    async close() {
      closed = true;
    },
    get closed() {
      return closed;
    },
    bind(accountId, deviceId) {
      bindings.add(`${accountId}\u0000${deviceId}`);
    },
    unbind(accountId, deviceId) {
      bindings.delete(`${accountId}\u0000${deviceId}`);
    },
    addToken(token, accountId, deviceId = null) {
      tokens.set(sha256Hex(token), { accountId, deviceId });
    },
    revokeToken(token) {
      tokens.delete(sha256Hex(token));
    },
  };
  return db;
}

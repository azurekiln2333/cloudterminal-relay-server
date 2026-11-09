// Account-bound authorization for the relay (design §5).
//
// The relay remains the in-memory switch it always was. What changes is that a
// client may now authenticate as an *account* instead of presenting the
// device's own secret, and that one device may serve clients of several
// different accounts at once.
//
// The database is consulted on connect and on an explicit cache refresh, never
// on the hot message path.

import type { DbPool } from '../db/pool.ts';
import { isBound } from '../db/bindings.ts';
import { verifyToken } from '../db/tokens.ts';
import { type Logger, silentLogger } from '../shared/log.ts';
import type { AccountAuthorizer, AccountClientResult } from './relay.ts';

export type TenancyOptions = {
  /** A ready pool, or null when the database is disabled/unreachable. */
  pool: DbPool | null;
  /** How long a positive/negative binding decision is cached. */
  bindingCacheMs?: number;
  logger?: Logger;
};

export type Tenancy = AccountAuthorizer & {
  /** Resolve a relay access token presented by a client for `deviceId`. */
  authorizeClient(token: string, deviceId: string): Promise<AccountClientResult>;
  /** Drop every cached decision for `(accountId, deviceId)` after a revoke. */
  invalidate(accountId: string, deviceId: string): void;
  /** Recompute the bound accounts of a device; used on binding changes. */
  boundAccounts(deviceId: string): Promise<string[]>;
  /** True when account features are usable at all. */
  readonly available: boolean;
  stats(): { cacheEntries: number; hits: number; misses: number };
};

const DEFAULT_BINDING_CACHE_MS = 30_000;

export function createTenancy(opts: TenancyOptions): Tenancy {
  const log = opts.logger ?? silentLogger;
  const cacheMs = opts.bindingCacheMs ?? DEFAULT_BINDING_CACHE_MS;
  /** key: `${accountId}\u0000${deviceId}` → { bound, expiresAt } */
  const bindings = new Map<string, { bound: boolean; expiresAt: number }>();
  let hits = 0;
  let misses = 0;

  function key(accountId: string, deviceId: string): string {
    return `${accountId}\u0000${deviceId}`;
  }

  async function checkBound(accountId: string, deviceId: string): Promise<boolean | null> {
    const pool = opts.pool;
    if (!pool || pool.closed) return null;
    const now = Date.now();
    const cached = bindings.get(key(accountId, deviceId));
    if (cached && cached.expiresAt > now) {
      hits++;
      return cached.bound;
    }
    misses++;
    try {
      const bound = await isBound(pool, accountId, deviceId);
      bindings.set(key(accountId, deviceId), { bound, expiresAt: now + cacheMs });
      return bound;
    } catch (err) {
      // A database blip must not silently grant access. Fail closed and let the
      // caller surface a retryable error instead.
      log.warn('binding lookup failed', { accountId, deviceId, err: (err as Error).message });
      return null;
    }
  }

  return {
    get available() {
      return opts.pool !== null && !opts.pool.closed;
    },

    async authorizeClient(token, deviceId) {
      const pool = opts.pool;
      if (!pool || pool.closed) return { ok: false, reason: 'no_database' };
      let verified;
      try {
        verified = await verifyToken(pool, token);
      } catch (err) {
        log.warn('token verification failed', { deviceId, err: (err as Error).message });
        return { ok: false, reason: 'unavailable' };
      }
      if (!verified) return { ok: false, reason: 'invalid_token' };
      // A device-scoped token may only be used for the device it was issued to.
      if (verified.deviceId !== null && verified.deviceId !== deviceId) {
        return { ok: false, reason: 'not_bound' };
      }
      const bound = await checkBound(verified.accountId, deviceId);
      if (bound === null) return { ok: false, reason: 'unavailable' };
      if (!bound) return { ok: false, reason: 'not_bound' };
      return { ok: true, accountId: verified.accountId };
    },

    invalidate(accountId, deviceId) {
      bindings.delete(key(accountId, deviceId));
    },

    async boundAccounts(deviceId) {
      const pool = opts.pool;
      if (!pool || pool.closed) return [];
      const { listAccountsForDevice } = await import('../db/bindings.ts');
      const rows = await listAccountsForDevice(pool, deviceId);
      return rows.map((r) => r.accountId);
    },

    stats() {
      return { cacheEntries: bindings.size, hits, misses };
    },
  };
}

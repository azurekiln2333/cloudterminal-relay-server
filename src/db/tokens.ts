// Relay-issued tokens (design §4.4).
//
// The plaintext token is generated here, returned to the caller exactly once,
// and only its `sha256` hex digest is persisted. `verifyToken` hashes the
// presented value and looks up the digest, so plaintext never touches the
// database or the log.

import type { RowDataPacket } from 'mysql2';
import { randomToken, sha256Hex } from '../shared/crypto.ts';

import type { DbExecutor } from './pool.ts';

export type TokenKind = 'access' | 'refresh' | 'device';

export type IssueTokenInput = {
  accountId: string;
  deviceId?: string | null;
  kind: TokenKind;
  ttlMs: number;
};

export type IssuedToken = {
  /** Plaintext token. Returned here only; never stored or logged. */
  token: string;
  tokenHash: string;
  accountId: string;
  deviceId: string | null;
  kind: TokenKind;
  expiresAt: Date;
};

export type VerifiedToken = {
  accountId: string;
  deviceId: string | null;
  kind: TokenKind;
  expiresAt: Date;
};

const KINDS = new Set<TokenKind>(['access', 'refresh', 'device']);

function assertKind(kind: string): TokenKind {
  if (!KINDS.has(kind as TokenKind)) throw new Error(`invalid token kind: ${kind}`);
  return kind as TokenKind;
}

function assertTtl(ttlMs: number): number {
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('ttlMs must be a positive integer');
  return ttlMs;
}

/** `ct_` + 32 random bytes, base64url. */
function newToken(): string {
  return `ct_${randomToken(32)}`;
}

/**
 * Issue a token and persist only its hash. The plaintext is in the returned
 * object and is not written anywhere else.
 */
export async function issueToken(db: DbExecutor, input: IssueTokenInput): Promise<IssuedToken> {
  const kind = assertKind(input.kind);
  const ttlMs = assertTtl(input.ttlMs);
  const token = newToken();
  const tokenHash = sha256Hex(token);
  const expiresAt = new Date(Date.now() + ttlMs);
  await db.execute(
    `insert into ct_tokens (token_hash, account_id, device_id, kind, expires_at)
     values (?, ?, ?, ?, from_unixtime(? / 1000))`,
    [tokenHash, input.accountId, input.deviceId ?? null, kind, expiresAt.getTime()],
  );
  return {
    token,
    tokenHash,
    accountId: input.accountId,
    deviceId: input.deviceId ?? null,
    kind,
    expiresAt,
  };
}

type TokenRow = RowDataPacket & {
  account_id: string;
  device_id: string | null;
  kind: string;
  expires_at: Date;
};

/**
 * Resolve a presented plaintext token to its claims, or `null` when it is
 * unknown, expired or revoked. Never throws for an invalid token.
 */
export async function verifyToken(db: DbExecutor, token: string): Promise<VerifiedToken | null> {
  if (typeof token !== 'string' || token.length === 0) return null;
  const tokenHash = sha256Hex(token);
  const rows = await db.query<TokenRow>(
    `select account_id, device_id, kind, expires_at
       from ct_tokens
      where token_hash = ? and revoked_at is null and expires_at > current_timestamp
      limit 1`,
    [tokenHash],
  );
  const row = rows[0];
  if (!row) return null;
  return {
    accountId: row.account_id,
    deviceId: row.device_id,
    kind: assertKind(row.kind),
    expiresAt: row.expires_at,
  };
}

/** Revoke by plaintext token. Returns true when a live row was revoked. */
export async function revokeToken(db: DbExecutor, token: string): Promise<boolean> {
  const tokenHash = sha256Hex(token);
  return revokeTokenHash(db, tokenHash);
}

/** Revoke by stored digest; used by `rotateRefresh`. */
export async function revokeTokenHash(db: DbExecutor, tokenHash: string): Promise<boolean> {
  const result = await db.execute(
    'update ct_tokens set revoked_at = current_timestamp where token_hash = ? and revoked_at is null',
    [tokenHash],
  );
  return result.affectedRows > 0;
}

export type RotateRefreshResult =
  | { ok: true; token: IssuedToken }
  | { ok: false; reason: 'invalid' | 'wrong_kind' };

/**
 * Revoke a refresh token and issue a replacement for the same account/device.
 * A rotated refresh token cannot be reused because its row is revoked before
 * the new one is created.
 */
export async function rotateRefresh(
  db: DbExecutor,
  oldToken: string,
  ttlMs: number,
): Promise<RotateRefreshResult> {
  assertTtl(ttlMs);
  const oldHash = sha256Hex(oldToken);
  const rows = await db.query<TokenRow>(
    `select account_id, device_id, kind, expires_at
       from ct_tokens
      where token_hash = ? and revoked_at is null and expires_at > current_timestamp
      limit 1`,
    [oldHash],
  );
  const row = rows[0];
  if (!row) return { ok: false, reason: 'invalid' };
  if (row.kind !== 'refresh') return { ok: false, reason: 'wrong_kind' };
  await revokeTokenHash(db, oldHash);
  const token = await issueToken(db, {
    accountId: row.account_id,
    deviceId: row.device_id,
    kind: 'refresh',
    ttlMs,
  });
  return { ok: true, token };
}

/** Delete expired and long-revoked rows. Called on a timer, never on reads. */
export async function purgeExpired(db: DbExecutor): Promise<number> {
  const result = await db.execute(
    `delete from ct_tokens
      where expires_at < current_timestamp
         or (revoked_at is not null and revoked_at < current_timestamp - interval 7 day)`,
  );
  return result.affectedRows;
}

/** Number of rows holding `token_hash` (used by tests to assert at-rest form). */
export async function countByHash(db: DbExecutor, tokenHash: string): Promise<number> {
  const rows = await db.query<RowDataPacket & { n: number }>(
    'select count(*) as n from ct_tokens where token_hash = ?',
    [tokenHash],
  );
  return Number(rows[0]?.n ?? 0);
}

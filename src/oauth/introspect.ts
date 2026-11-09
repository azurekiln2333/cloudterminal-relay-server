// Remote token introspection (RFC 7662) as the fallback verification strategy
// (design §4.3, PRD R5.1).
//
// Uses client credentials (HTTP Basic) against the gateway introspection
// endpoint. Results are cached for the token's remaining lifetime, bounded by
// `OAUTH_INTROSPECT_CACHE_MS`, so a websocket reconnect storm does not hammer
// the gateway.

import { type Logger, silentLogger } from '../shared/log.ts';
import { sha256Hex } from '../shared/crypto.ts';
import { type OidcEndpoints } from './discovery.ts';

export type IntrospectionClaims = {
  sub: string;
  iss: string | null;
  aud: string[];
  exp: number | null;
  name: string | null;
};

export type IntrospectFailure = {
  ok: false;
  code: 'inactive' | 'wrong_issuer' | 'wrong_audience' | 'missing_claim' | 'introspect_unavailable' | 'introspect_invalid';
  message: string;
};

export type IntrospectResult = { ok: true; claims: IntrospectionClaims } | IntrospectFailure;

export type IntrospectOptions = {
  endpoints: OidcEndpoints;
  clientId: string;
  clientSecret: string;
  /** Expected token audience, from `OAUTH_AUDIENCE`. */
  audience: string;
  /** Expected issuer; defaults to `endpoints.issuer`. */
  issuer?: string;
  /** Upper bound on how long an introspection response is cached. */
  cacheMs?: number;
  timeoutMs?: number;
  logger?: Logger;
  fetchFn?: typeof fetch;
  now?: () => number;
};

export type Introspector = {
  introspect(token: string): Promise<IntrospectResult>;
  reset(): void;
  stats(): { entries: number; hits: number; misses: number };
};

const DEFAULT_CACHE_MS = 60_000;
const DEFAULT_TIMEOUT_MS = 5_000;
/** Hard ceiling so a long-lived token cannot pin a cache entry forever. */
const MAX_CACHE_MS = 3_600_000;

function readAudience(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return [];
}

export function createIntrospector(opts: IntrospectOptions): Introspector {
  const log = opts.logger ?? silentLogger;
  const cacheMs = Math.min(opts.cacheMs ?? DEFAULT_CACHE_MS, MAX_CACHE_MS);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const doFetch = opts.fetchFn ?? fetch;
  const now = opts.now ?? (() => Date.now());
  const expectedIssuer = (opts.issuer ?? opts.endpoints.issuer).replace(/\/$/, '');
  // The raw token is never used as a cache key; hash it.
  const cache = new Map<string, { result: IntrospectResult; expiresAt: number }>();
  let hits = 0;
  let misses = 0;

  async function request(token: string): Promise<IntrospectResult> {
    const body = new URLSearchParams({ token, token_type_hint: 'access_token' });
    const basic = Buffer.from(`${opts.clientId}:${opts.clientSecret}`, 'utf8').toString('base64');
    let response: Response;
    try {
      response = await doFetch(opts.endpoints.introspectionEndpoint ?? '', {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
          authorization: `Basic ${basic}`,
        },
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      log.warn('introspection request failed', { err: (err as Error).message });
      return { ok: false, code: 'introspect_unavailable', message: `introspection request failed: ${(err as Error).message}` };
    }
    if (!response.ok) {
      return { ok: false, code: 'introspect_unavailable', message: `introspection returned status ${response.status}` };
    }
    let json: unknown;
    try {
      json = await response.json();
    } catch (err) {
      return { ok: false, code: 'introspect_invalid', message: `introspection body is not JSON: ${(err as Error).message}` };
    }
    if (typeof json !== 'object' || json === null) {
      return { ok: false, code: 'introspect_invalid', message: 'introspection body is not an object' };
    }
    const doc = json as Record<string, unknown>;
    if (doc.active !== true) return { ok: false, code: 'inactive', message: 'token is not active' };

    const sub = doc.sub;
    if (typeof sub !== 'string' || sub === '') return { ok: false, code: 'missing_claim', message: 'introspection has no sub' };
    const iss = typeof doc.iss === 'string' ? doc.iss : null;
    if (iss !== null && iss.replace(/\/$/, '') !== expectedIssuer) {
      return { ok: false, code: 'wrong_issuer', message: 'introspection iss does not match the configured issuer' };
    }
    const aud = readAudience(doc.aud);
    if (aud.length > 0 && !aud.includes(opts.audience)) {
      return { ok: false, code: 'wrong_audience', message: 'introspection aud does not include the configured audience' };
    }
    const exp = typeof doc.exp === 'number' && Number.isFinite(doc.exp) ? doc.exp : null;
    return {
      ok: true,
      claims: { sub, iss, aud, exp, name: typeof doc.name === 'string' ? doc.name : null },
    };
  }

  function cacheable(result: IntrospectResult, token: string): void {
    if (cacheMs <= 0) return;
    const nowMs = now();
    // Never cache an inactive/negative result longer than the bound; positive
    // results are capped by the token's own expiry.
    let ttl = cacheMs;
    if (result.ok && result.claims.exp !== null) {
      const remaining = result.claims.exp * 1000 - nowMs;
      if (remaining <= 0) return;
      ttl = Math.min(ttl, remaining);
    }
    cache.set(sha256Hex(token), { result, expiresAt: nowMs + ttl });
  }

  return {
    async introspect(token: string): Promise<IntrospectResult> {
      if (cacheMs > 0) {
        const key = sha256Hex(token);
        const hit = cache.get(key);
        if (hit && hit.expiresAt > now()) {
          hits++;
          return hit.result;
        }
        if (hit) cache.delete(key);
      }
      misses++;
      const result = await request(token);
      cacheable(result, token);
      return result;
    },
    reset() {
      cache.clear();
    },
    stats() {
      return { entries: cache.size, hits, misses };
    },
  };
}

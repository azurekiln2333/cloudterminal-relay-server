// JWKS fetching and RS256 JWT verification (design §4.3, PRD R5.2).
//
// Uses only `node:crypto`: the public key is imported from the JWK, the RS256
// signature is verified against the signing input, and the registered claims
// are checked with a small clock skew. No new dependency.
//
// A verification failure is always a typed result, never a bare throw, so the
// API layer can map it to a machine-readable error (PRD R5.1/R5.2).

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

import { type Logger, silentLogger } from '../shared/log.ts';
import { type OidcEndpoints } from './discovery.ts';

export type JwtClaims = {
  sub: string;
  iss: string;
  aud: string[];
  exp: number | null;
  nbf: number | null;
  iat: number | null;
  name: string | null;
};

export type JwksVerifyFailure = {
  ok: false;
  code:
    | 'malformed_token'
    | 'unsupported_algorithm'
    | 'unknown_key'
    | 'bad_signature'
    | 'expired'
    | 'not_yet_valid'
    | 'wrong_issuer'
    | 'wrong_audience'
    | 'missing_claim'
    | 'jwks_unavailable'
    | 'jwks_invalid';
  message: string;
};

export type JwksVerifyResult = { ok: true; claims: JwtClaims } | JwksVerifyFailure;

export type JwksOptions = {
  endpoints: OidcEndpoints;
  /** Expected token audience, from `OAUTH_AUDIENCE`. */
  audience: string;
  /** Expected issuer; defaults to `endpoints.issuer`. */
  issuer?: string;
  /** JWKS cache TTL. */
  ttlMs?: number;
  /** Per-request timeout. */
  timeoutMs?: number;
  /** Allowed clock skew for `exp`/`nbf`/`iat`. */
  clockSkewSec?: number;
  logger?: Logger;
  fetchFn?: typeof fetch;
  /** Injectable clock (seconds); defaults to `Date.now()/1000`. */
  now?: () => number;
};

export type JwksVerifier = {
  verify(token: string): Promise<JwksVerifyResult>;
  reset(): void;
};

const DEFAULT_TTL_MS = 3_600_000;
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_CLOCK_SKEW_SEC = 60;

type Jwk = { kid: string; key: ReturnType<typeof createPublicKey> };

/** Decode a base64url segment to UTF-8 text. */
function base64UrlDecode(segment: string): string {
  return Buffer.from(segment, 'base64url').toString('utf8');
}

function decodeJsonSegment(segment: string): unknown {
  return JSON.parse(base64UrlDecode(segment));
}

type ParsedJwt = {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
  kid: string | null;
};

/** Split and decode a compact JWS. Throws only internally; callers get a code. */
function parseJwt(token: string): ParsedJwt | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  if (!headerB64 || !payloadB64 || !signatureB64) return null;
  let header: unknown;
  let payload: unknown;
  try {
    header = decodeJsonSegment(headerB64);
    payload = decodeJsonSegment(payloadB64);
  } catch {
    return null;
  }
  if (typeof header !== 'object' || header === null) return null;
  if (typeof payload !== 'object' || payload === null) return null;
  const h = header as Record<string, unknown>;
  return {
    header: h,
    payload: payload as Record<string, unknown>,
    signingInput: `${headerB64}.${payloadB64}`,
    signature: Buffer.from(signatureB64, 'base64url'),
    kid: typeof h.kid === 'string' ? h.kid : null,
  };
}

/** The audience claim may be a string or an array of strings. */
function readAudience(value: unknown): string[] | null {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value) && value.every((v) => typeof v === 'string')) return value as string[];
  return null;
}

function readNumericDate(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  return null;
}

/**
 * Verify a compact RS256 JWS against a raw JWK. Exported so the JWKS cache
 * stays small; the actual math lives here.
 */
export function importJwk(jwk: Record<string, unknown>): ReturnType<typeof createPublicKey> | null {
  if (jwk.kty !== 'RSA') return null;
  try {
    return createPublicKey({ key: jwk as never, format: 'jwk' });
  } catch {
    return null;
  }
}

export function createJwksVerifier(opts: JwksOptions): JwksVerifier {
  const log = opts.logger ?? silentLogger;
  const ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const clockSkewSec = opts.clockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC;
  const doFetch = opts.fetchFn ?? fetch;
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const expectedIssuer = (opts.issuer ?? opts.endpoints.issuer).replace(/\/$/, '');

  let cache: { keys: Map<string, Jwk>; fetchedAt: number } | null = null;
  let inflight: Promise<{ ok: true; keys: Map<string, Jwk> } | JwksVerifyFailure> | null = null;

  async function fetchJwks(): Promise<{ ok: true; keys: Map<string, Jwk> } | JwksVerifyFailure> {
    let response: Response;
    try {
      response = await doFetch(opts.endpoints.jwksUri, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      log.warn('jwks request failed', { uri: opts.endpoints.jwksUri, err: (err as Error).message });
      return { ok: false, code: 'jwks_unavailable', message: `jwks request failed: ${(err as Error).message}` };
    }
    if (!response.ok) {
      return { ok: false, code: 'jwks_unavailable', message: `jwks returned status ${response.status}` };
    }
    let json: unknown;
    try {
      json = await response.json();
    } catch (err) {
      return { ok: false, code: 'jwks_invalid', message: `jwks body is not JSON: ${(err as Error).message}` };
    }
    const list = (json as { keys?: unknown })?.keys;
    if (!Array.isArray(list)) return { ok: false, code: 'jwks_invalid', message: 'jwks document has no keys array' };
    const keys = new Map<string, Jwk>();
    for (const entry of list) {
      if (typeof entry !== 'object' || entry === null) continue;
      const raw = entry as Record<string, unknown>;
      if (typeof raw.kid !== 'string' || raw.kid === '') continue;
      if (raw.use !== undefined && raw.use !== 'sig') continue;
      const key = importJwk(raw);
      if (!key) continue;
      keys.set(raw.kid, { kid: raw.kid, key });
    }
    if (keys.size === 0) return { ok: false, code: 'jwks_invalid', message: 'jwks document exposes no usable signing keys' };
    return { ok: true, keys };
  }

  async function keys(): Promise<{ ok: true; keys: Map<string, Jwk> } | JwksVerifyFailure> {
    const fresh = cache;
    if (fresh && Date.now() - fresh.fetchedAt < ttlMs) return { ok: true, keys: fresh.keys };
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        const result = await fetchJwks();
        if (result.ok) cache = { keys: result.keys, fetchedAt: Date.now() };
        return result;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  async function verify(token: string): Promise<JwksVerifyResult> {
    const parsed = parseJwt(token);
    if (!parsed) return { ok: false, code: 'malformed_token', message: 'token is not a compact JWS' };
    if (parsed.header.alg !== 'RS256') {
      return { ok: false, code: 'unsupported_algorithm', message: `unsupported alg ${String(parsed.header.alg)}` };
    }

    let resolved = await keys();
    // A `kid` miss may mean the gateway rotated keys; refresh once.
    if (resolved.ok && (!parsed.kid || !resolved.keys.has(parsed.kid))) {
      cache = null;
      resolved = await keys();
    }
    if (!resolved.ok) return resolved;
    if (!parsed.kid) return { ok: false, code: 'unknown_key', message: 'token header has no kid' };
    const jwk = resolved.keys.get(parsed.kid);
    if (!jwk) return { ok: false, code: 'unknown_key', message: `no signing key for kid ${parsed.kid}` };

    let signatureOk = false;
    try {
      signatureOk = cryptoVerify(
        'RSA-SHA256',
        Buffer.from(parsed.signingInput, 'utf8'),
        jwk.key,
        parsed.signature,
      );
    } catch (err) {
      return { ok: false, code: 'bad_signature', message: `signature check failed: ${(err as Error).message}` };
    }
    if (!signatureOk) return { ok: false, code: 'bad_signature', message: 'signature does not match any signing key' };

    const sub = parsed.payload.sub;
    if (typeof sub !== 'string' || sub === '') return { ok: false, code: 'missing_claim', message: 'sub claim is missing' };
    const iss = parsed.payload.iss;
    if (typeof iss !== 'string' || iss === '') return { ok: false, code: 'missing_claim', message: 'iss claim is missing' };
    if (iss.replace(/\/$/, '') !== expectedIssuer) {
      return { ok: false, code: 'wrong_issuer', message: 'iss claim does not match the configured issuer' };
    }
    const aud = readAudience(parsed.payload.aud);
    if (!aud) return { ok: false, code: 'missing_claim', message: 'aud claim is missing or invalid' };
    if (!aud.includes(opts.audience)) {
      return { ok: false, code: 'wrong_audience', message: 'aud claim does not include the configured audience' };
    }

    const exp = readNumericDate(parsed.payload.exp);
    const nbf = readNumericDate(parsed.payload.nbf);
    const iat = readNumericDate(parsed.payload.iat);
    const nowSec = now();
    if (exp === null) return { ok: false, code: 'missing_claim', message: 'exp claim is missing' };
    if (exp + clockSkewSec < nowSec) return { ok: false, code: 'expired', message: 'token has expired' };
    if (nbf !== null && nbf - clockSkewSec > nowSec) {
      return { ok: false, code: 'not_yet_valid', message: 'token is not valid yet' };
    }
    if (iat !== null && iat - clockSkewSec > nowSec) {
      return { ok: false, code: 'not_yet_valid', message: 'token was issued in the future' };
    }

    return {
      ok: true,
      claims: {
        sub,
        iss,
        aud,
        exp,
        nbf,
        iat,
        name: typeof parsed.payload.name === 'string' ? parsed.payload.name : null,
      },
    };
  }

  return {
    verify,
    reset() {
      cache = null;
    },
  };
}

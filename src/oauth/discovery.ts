// OIDC discovery document cache (design §4.3).
//
// Fetches `<issuer>/.well-known/openid-configuration` with a timeout and caches
// the endpoints for a short TTL. Every outbound call is bounded so a slow or
// unreachable gateway can never block a websocket upgrade (design §9).
//
// The document is treated as untrusted remote input: each field is validated at
// runtime before it is exposed.

import { type Logger, silentLogger } from '../shared/log.ts';

/** The endpoints this relay actually uses. Everything else is ignored. */
export type OidcEndpoints = {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  introspectionEndpoint: string | null;
  /**
   * `null` when the gateway does not advertise RFC 8628 device authorization.
   * Flow B reports `device_flow_unsupported` in that case; flow A is unaffected
   * (PRD R4).
   */
  deviceAuthorizationEndpoint: string | null;
};

export type DiscoveryOptions = {
  /** Normalised issuer, no trailing slash. */
  issuer: string;
  /** How long a resolved document is reused. */
  ttlMs?: number;
  /** Per-request timeout. */
  timeoutMs?: number;
  logger?: Logger;
  /** Injectable for tests; defaults to global `fetch`. */
  fetchFn?: typeof fetch;
};

export type Discovery = {
  /**
   * Resolve the document, using the cache when fresh. Never throws for a
   * network/parse problem: returns a typed failure instead.
   */
  get(): Promise<DiscoveryResult>;
  /** Drop the cached document (e.g. after a `kid` miss suggests rotation). */
  reset(): void;
};

export type DiscoveryFailure = {
  ok: false;
  code: 'discovery_unavailable' | 'discovery_invalid';
  message: string;
};

export type DiscoveryResult = { ok: true; endpoints: OidcEndpoints; fetchedAt: number } | DiscoveryFailure;

const DEFAULT_TTL_MS = 3_600_000;
const DEFAULT_TIMEOUT_MS = 5_000;

/** Trim a string field; return null when absent/blank/not a string. */
function optionalUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.trim() === '') return null;
  return value.trim();
}

/** Accept only absolute http(s) URLs; reject everything else. */
function asHttpUrl(value: unknown, field: string): string {
  const raw = optionalUrl(value);
  if (!raw) throw new Error(`missing ${field}`);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${field} is not an absolute URL`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`${field} must use http or https`);
  }
  return url.toString();
}

/**
 * Map a raw discovery document onto the endpoints we need. Throws with a
 * descriptive (non-secret) message when a required field is missing or not a
 * valid URL. Exported so tests can exercise it directly.
 */
export function parseDiscoveryDocument(raw: unknown): OidcEndpoints {
  if (typeof raw !== 'object' || raw === null) throw new Error('discovery document is not an object');
  const doc = raw as Record<string, unknown>;
  return {
    issuer: asHttpUrl(doc.issuer, 'issuer').replace(/\/$/, ''),
    authorizationEndpoint: asHttpUrl(doc.authorization_endpoint, 'authorization_endpoint'),
    tokenEndpoint: asHttpUrl(doc.token_endpoint, 'token_endpoint'),
    jwksUri: asHttpUrl(doc.jwks_uri, 'jwks_uri'),
    introspectionEndpoint: optionalUrl(doc.introspection_endpoint),
    deviceAuthorizationEndpoint: optionalUrl(doc.device_authorization_endpoint),
  };
}

export function createDiscovery(opts: DiscoveryOptions): Discovery {
  const log = opts.logger ?? silentLogger;
  const ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const doFetch = opts.fetchFn ?? fetch;
  const url = `${opts.issuer}/.well-known/openid-configuration`;

  let cached: { endpoints: OidcEndpoints; fetchedAt: number } | null = null;
  /** Coalesce concurrent misses so a burst makes one request. */
  let inflight: Promise<DiscoveryResult> | null = null;

  async function fetchOnce(): Promise<DiscoveryResult> {
    let response: Response;
    try {
      response = await doFetch(url, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const message = (err as Error).message;
      log.warn('oidc discovery request failed', { url, err: message });
      return { ok: false, code: 'discovery_unavailable', message: `discovery request failed: ${message}` };
    }
    if (!response.ok) {
      log.warn('oidc discovery returned an error status', { url, status: response.status });
      return {
        ok: false,
        code: 'discovery_unavailable',
        message: `discovery returned status ${response.status}`,
      };
    }
    let json: unknown;
    try {
      json = await response.json();
    } catch (err) {
      return { ok: false, code: 'discovery_invalid', message: `discovery body is not JSON: ${(err as Error).message}` };
    }
    try {
      const endpoints = parseDiscoveryDocument(json);
      return { ok: true, endpoints, fetchedAt: Date.now() };
    } catch (err) {
      log.warn('oidc discovery document is invalid', { url, err: (err as Error).message });
      return { ok: false, code: 'discovery_invalid', message: (err as Error).message };
    }
  }

  async function load(): Promise<DiscoveryResult> {
    const fresh = cached;
    if (fresh && Date.now() - fresh.fetchedAt < ttlMs) {
      return { ok: true, endpoints: fresh.endpoints, fetchedAt: fresh.fetchedAt };
    }
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        const result = await fetchOnce();
        if (result.ok) cached = { endpoints: result.endpoints, fetchedAt: result.fetchedAt };
        return result;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  return {
    get: load,
    reset() {
      cached = null;
    },
  };
}

// Token verification strategy selection (design §4.3).
//
// `jwks` is preferred; `introspect` is the fallback selected by
// `OAUTH_VERIFY`. Both paths normalize to `{sub, issuer, name?}` and both
// return a typed failure instead of throwing, so the API layer can map a
// rejection to a machine-readable `401`.

import { type Logger, silentLogger } from '../shared/log.ts';
import { type OauthConfig } from './config.ts';
import { createDiscovery, type Discovery, type OidcEndpoints } from './discovery.ts';
import { createJwksVerifier, type JwksVerifier } from './jwks.ts';
import { createIntrospector, type Introspector } from './introspect.ts';

/** Normalized identity handed to the rest of the relay. */
export type VerifiedIdentity = {
  sub: string;
  issuer: string;
  name: string | null;
};

export type VerifyFailure = {
  ok: false;
  /** Broad category used by the API layer to pick a status code. */
  code:
    | 'invalid_token'
    | 'expired'
    | 'wrong_issuer'
    | 'wrong_audience'
    | 'unknown_key'
    | 'unavailable'
    | 'misconfigured';
  /** Machine-readable detail code (e.g. `bad_signature`). */
  detail: string;
  message: string;
};

export type VerifyResult = { ok: true; identity: VerifiedIdentity } | VerifyFailure;

export type VerifierOptions = {
  config: OauthConfig;
  logger?: Logger;
  fetchFn?: typeof fetch;
  now?: () => number;
  /** Override discovery resolution; mainly for tests. */
  discovery?: Discovery;
  /** Pre-supplied endpoints (skips discovery); mainly for tests. */
  endpoints?: OidcEndpoints;
};

export type Verifier = {
  verify(token: string): Promise<VerifyResult>;
  /** Resolve the discovery document; used by `/readyz` and the flows. */
  endpoints(): Promise<{ ok: true; endpoints: OidcEndpoints } | { ok: false; code: string; message: string }>;
  readonly strategy: 'jwks' | 'introspect';
};

function mapJwksFailure(code: string, message: string): VerifyFailure {
  switch (code) {
    case 'expired':
      return { ok: false, code: 'expired', detail: code, message };
    case 'wrong_issuer':
      return { ok: false, code: 'wrong_issuer', detail: code, message };
    case 'wrong_audience':
      return { ok: false, code: 'wrong_audience', detail: code, message };
    case 'unknown_key':
    case 'bad_signature':
    case 'malformed_token':
    case 'unsupported_algorithm':
    case 'missing_claim':
    case 'not_yet_valid':
      return { ok: false, code: 'invalid_token', detail: code, message };
    case 'jwks_unavailable':
    case 'jwks_invalid':
    default:
      return { ok: false, code: 'unavailable', detail: code, message };
  }
}

function mapIntrospectFailure(code: string, message: string): VerifyFailure {
  switch (code) {
    case 'wrong_issuer':
      return { ok: false, code: 'wrong_issuer', detail: code, message };
    case 'wrong_audience':
      return { ok: false, code: 'wrong_audience', detail: code, message };
    case 'inactive':
    case 'missing_claim':
      return { ok: false, code: 'invalid_token', detail: code, message };
    case 'introspect_unavailable':
    case 'introspect_invalid':
    default:
      return { ok: false, code: 'unavailable', detail: code, message };
  }
}

export function createVerifier(opts: VerifierOptions): Verifier {
  const log = opts.logger ?? silentLogger;
  const config = opts.config;
  const discovery =
    opts.discovery ??
    createDiscovery({
      issuer: config.issuer,
      ttlMs: config.jwksTtlMs,
      logger: log,
      ...(opts.fetchFn ? { fetchFn: opts.fetchFn } : {}),
    });

  const jwks: JwksVerifier | null =
    opts.endpoints && config.verify === 'jwks'
      ? createJwksVerifier({
          endpoints: opts.endpoints,
          audience: config.audience,
          issuer: config.issuer,
          ttlMs: config.jwksTtlMs,
          logger: log,
          ...(opts.fetchFn ? { fetchFn: opts.fetchFn } : {}),
          ...(opts.now ? { now: opts.now } : {}),
        })
      : null;

  const introspector: Introspector | null =
    opts.endpoints && config.verify === 'introspect'
      ? createIntrospector({
          endpoints: opts.endpoints,
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          audience: config.audience,
          issuer: config.issuer,
          cacheMs: config.introspectCacheMs,
          logger: log,
          ...(opts.fetchFn ? { fetchFn: opts.fetchFn } : {}),
          ...(opts.now ? { now: opts.now } : {}),
        })
      : null;

  /** Lazily build the strategy that needs discovered endpoints. */
  const lazy = new Map<string, JwksVerifier | Introspector>();
  function strategy(endpoints: OidcEndpoints): JwksVerifier | Introspector {
    const existing = lazy.get(config.verify);
    if (existing) return existing;
    const built =
      config.verify === 'jwks'
        ? createJwksVerifier({
            endpoints,
            audience: config.audience,
            issuer: config.issuer,
            ttlMs: config.jwksTtlMs,
            logger: log,
            ...(opts.fetchFn ? { fetchFn: opts.fetchFn } : {}),
            ...(opts.now ? { now: opts.now } : {}),
          })
        : createIntrospector({
            endpoints,
            clientId: config.clientId,
            clientSecret: config.clientSecret,
            audience: config.audience,
            issuer: config.issuer,
            cacheMs: config.introspectCacheMs,
            logger: log,
            ...(opts.fetchFn ? { fetchFn: opts.fetchFn } : {}),
            ...(opts.now ? { now: opts.now } : {}),
          });
    lazy.set(config.verify, built);
    return built;
  }

  async function resolveEndpoints(): Promise<
    { ok: true; endpoints: OidcEndpoints } | { ok: false; code: string; message: string }
  > {
    if (opts.endpoints) return { ok: true, endpoints: opts.endpoints };
    const result = await discovery.get();
    if (!result.ok) return { ok: false, code: result.code, message: result.message };
    return { ok: true, endpoints: result.endpoints };
  }

  return {
    strategy: config.verify,

    endpoints: resolveEndpoints,

    async verify(token: string): Promise<VerifyResult> {
      if (typeof token !== 'string' || token.length === 0) {
        return { ok: false, code: 'invalid_token', detail: 'empty_token', message: 'token is empty' };
      }
      if (config.verify === 'introspect' && !config.clientSecret) {
        // Introspection without a secret almost always fails at the gateway;
        // report a clear misconfiguration instead of a confusing 401.
        return {
          ok: false,
          code: 'misconfigured',
          detail: 'missing_client_secret',
          message: 'OAUTH_CLIENT_SECRET is required for introspection',
        };
      }
      const resolved = await resolveEndpoints();
      if (!resolved.ok) {
        return { ok: false, code: 'unavailable', detail: resolved.code, message: resolved.message };
      }
      const verifier = config.verify === 'jwks' && jwks ? jwks : introspector ?? strategy(resolved.endpoints);
      if (config.verify === 'jwks') {
        const result = await (verifier as JwksVerifier).verify(token);
        if (!result.ok) return mapJwksFailure(result.code, result.message);
        return { ok: true, identity: { sub: result.claims.sub, issuer: result.claims.iss, name: result.claims.name } };
      }
      const result = await (verifier as Introspector).introspect(token);
      if (!result.ok) return mapIntrospectFailure(result.code, result.message);
      return {
        ok: true,
        identity: {
          sub: result.claims.sub,
          issuer: result.claims.iss ?? config.issuer,
          name: result.claims.name,
        },
      };
    },
  };
}

// OAuth2 / OIDC gateway settings parsed from `OAUTH_*`.
//
// Same contract as `db/config.ts`: pure parsing, no network I/O at import time.
// A missing configuration disables `/api/v1/auth/*`; a partial one degrades it
// with an actionable message while the legacy relay protocol keeps running
// (PRD R18, design §7).
//
// The client secret is carried in the parsed config but must never be logged.

export type OauthState = 'disabled' | 'degraded' | 'ready';

export type OauthVerifyStrategy = 'jwks' | 'introspect';

export type OauthConfig = {
  state: 'ready';
  issuer: string;
  clientId: string;
  clientSecret: string;
  audience: string;
  redirectUri: string;
  scopes: string;
  verify: OauthVerifyStrategy;
  jwksTtlMs: number;
  introspectCacheMs: number;
};

export type OauthConfigResult =
  | { state: 'disabled' | 'degraded'; message: string; config: null }
  | { state: 'ready'; message: ''; config: OauthConfig };

const DEFAULT_SCOPES = 'openid profile';
const DEFAULT_JWKS_TTL_MS = 3_600_000;
const DEFAULT_INTROSPECT_CACHE_MS = 60_000;

function anyOauthVarSet(env: NodeJS.ProcessEnv): boolean {
  return Object.keys(env).some((key) => key.startsWith('OAUTH_'));
}

function parseInteger(raw: string, name: string, min: number, max: number): number {
  const text = raw.trim();
  if (!/^\d+$/.test(text)) throw new Error(`${name} must be an integer, got ${JSON.stringify(raw)}`);
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be between ${min} and ${max}, got ${text}`);
  }
  return value;
}

function parseIssuer(raw: string): string {
  const value = raw.trim();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`OAUTH_ISSUER must be an absolute http(s) URL, got ${JSON.stringify(raw)}`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`OAUTH_ISSUER must use http or https, got ${url.protocol}`);
  }
  // Normalise away a trailing slash so issuer comparison and endpoint joins
  // are consistent.
  return url.toString().replace(/\/$/, '');
}

/**
 * Parse `OAUTH_*`.
 *
 * - No `OAUTH_*` variable: `disabled`, auth endpoints are off.
 * - Some but not all required variables: `degraded` with the missing names.
 * - Syntactically invalid value: throws, because silently disabling auth on a
 *   typo would be worse than failing loudly at startup.
 */
export function loadOauthConfig(env: NodeJS.ProcessEnv = process.env): OauthConfigResult {
  if (!anyOauthVarSet(env)) {
    return { state: 'disabled', message: 'no OAUTH_* settings configured; account login is off', config: null };
  }

  const required = ['OAUTH_ISSUER', 'OAUTH_CLIENT_ID'] as const;
  const missing: string[] = [];
  for (const name of required) {
    if (!env[name]?.trim()) missing.push(name);
  }
  if (missing.length > 0) {
    return {
      state: 'degraded',
      message: `incomplete OAUTH_* settings; missing ${missing.join(', ')}`,
      config: null,
    };
  }

  const issuer = parseIssuer(env.OAUTH_ISSUER!);
  const clientId = env.OAUTH_CLIENT_ID!.trim();
  const audience = env.OAUTH_AUDIENCE?.trim() || clientId;
  const redirectUri = env.OAUTH_REDIRECT_URI?.trim() || 'cloudterminal://oauth/callback';
  const scopes = env.OAUTH_SCOPES?.trim() || DEFAULT_SCOPES;

  const verifyRaw = (env.OAUTH_VERIFY?.trim() || 'jwks').toLowerCase();
  if (verifyRaw !== 'jwks' && verifyRaw !== 'introspect') {
    throw new Error(`OAUTH_VERIFY must be "jwks" or "introspect", got ${JSON.stringify(env.OAUTH_VERIFY)}`);
  }

  const jwksTtlMs =
    env.OAUTH_JWKS_TTL_MS === undefined
      ? DEFAULT_JWKS_TTL_MS
      : parseInteger(env.OAUTH_JWKS_TTL_MS, 'OAUTH_JWKS_TTL_MS', 1000, 86_400_000);
  const introspectCacheMs =
    env.OAUTH_INTROSPECT_CACHE_MS === undefined
      ? DEFAULT_INTROSPECT_CACHE_MS
      : parseInteger(env.OAUTH_INTROSPECT_CACHE_MS, 'OAUTH_INTROSPECT_CACHE_MS', 0, 86_400_000);

  return {
    state: 'ready',
    message: '',
    config: {
      state: 'ready',
      issuer,
      clientId,
      clientSecret: env.OAUTH_CLIENT_SECRET ?? '',
      audience,
      redirectUri,
      scopes,
      verify: verifyRaw,
      jwksTtlMs,
      introspectCacheMs,
    },
  };
}

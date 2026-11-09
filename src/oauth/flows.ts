// OAuth2 authorization flows against the external gateway (design §4.1/§4.2).
//
// Flow A: authorization code + PKCE. The app opens the gateway in a system
// browser; the relay exchanges the returned code for tokens and validates the
// result, so the gateway client secret and the gateway tokens never reach the
// app.
//
// Flow B: RFC 8628 device authorization. The desktop asks the relay for a
// `user_code`, the user approves in a browser, and the desktop polls the relay
// until it gets relay-issued credentials bound to the device.
//
// Both flows persist their pending state in `ct_oauth_states` through the
// existing pool shape; the pending state is used exactly once and then deleted.
// Nothing here logs an authorization code, a `code_verifier` or a token.

import { randomBytes, createHash } from 'node:crypto';
import type { RowDataPacket } from 'mysql2';

import { issueToken, type IssuedToken } from '../db/tokens.ts';
import { upsertAccount } from '../db/accounts.ts';
import { upsertDevice } from '../db/devices.ts';
import { createBinding } from '../db/bindings.ts';
import type { DbPool } from '../db/pool.ts';
import { type Logger, silentLogger } from '../shared/log.ts';
import { type OauthConfig } from './config.ts';
import { type OidcEndpoints } from './discovery.ts';
import { type Verifier, type VerifiedIdentity } from './verify.ts';

export type FlowFailureCode =
  | 'invalid_request'
  | 'flow_disabled'
  | 'unknown_state'
  | 'state_expired'
  | 'state_consumed'
  | 'gateway_unavailable'
  | 'gateway_rejected'
  | 'verification_failed'
  | 'device_flow_unsupported'
  | 'authorization_pending'
  | 'slow_down'
  | 'expired_token'
  | 'access_denied'
  | 'device_unknown'
  | 'misconfigured';

export type FlowFailure = { ok: false; code: FlowFailureCode; message: string };

export type RelayCredentials = {
  accountId: string;
  displayName: string | null;
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: string;
  refreshExpiresAt: string;
};

export type FlowAStartInput = { codeChallenge: string; redirectUri?: string };
export type FlowAStartOk = { ok: true; state: string; authorizeUrl: string; expiresAt: string };
export type FlowACompleteInput = { code: string; state: string; codeVerifier: string };
export type FlowACompleteOk = { ok: true; credentials: RelayCredentials };
export type DeviceStartInput = { deviceId: string; label?: string; platform?: string; secretHash?: string };
export type DeviceStartOk = {
  ok: true;
  state: string;
  userCode: string;
  verificationUri: string;
  interval: number;
  expiresIn: number;
};
export type DevicePollInput = { deviceId: string; userCode: string };
export type DevicePollOk = { ok: true; status: 'approved'; credentials: RelayCredentials };

export type FlowsOptions = {
  db: DbPool | null;
  config: OauthConfig | null;
  verifier: Verifier | null;
  /** Resolved OIDC endpoints. Mutually exclusive with `endpointsProvider`. */
  endpoints?: OidcEndpoints | null;
  /**
   * Lazily resolve the endpoints (e.g. from discovery) so a gateway that is
   * down at startup does not disable login forever (PRD R18).
   */
  endpointsProvider?: () => Promise<
    { ok: true; endpoints: OidcEndpoints } | { ok: false; code: string; message: string }
  >;
  accessTtlMs: number;
  refreshTtlMs: number;
  /** Lifetime of a pending PKCE/device state row. */
  stateTtlMs?: number;
  deviceStateTtlMs?: number;
  timeoutMs?: number;
  logger?: Logger;
  fetchFn?: typeof fetch;
  now?: () => number;
};

export type Flows = {
  /** True when DB + OAuth config + verifier + endpoints are all present. */
  readonly available: boolean;
  startFlowA(input: FlowAStartInput): Promise<FlowAStartOk | FlowFailure>;
  completeFlowA(input: FlowACompleteInput): Promise<FlowACompleteOk | FlowFailure>;
  startDevice(input: DeviceStartInput): Promise<DeviceStartOk | FlowFailure>;
  pollDevice(input: DevicePollInput): Promise<DevicePollOk | FlowFailure>;
  purgeExpiredStates(): Promise<number>;
};

const DEFAULT_STATE_TTL_MS = 10 * 60_000;
const DEFAULT_DEVICE_STATE_TTL_MS = 15 * 60_000;
const DEFAULT_TIMEOUT_MS = 8_000;

type StateRow = RowDataPacket & {
  state: string;
  kind: string;
  code_verifier: string | null;
  device_id: string | null;
  user_code: string | null;
  expires_at: Date;
};

type StateInput = {
  state: string;
  kind: string;
  code_verifier: string | null;
  device_id: string | null;
  user_code: string | null;
  expires_at: Date;
};

function base64Url(buffer: Buffer): string {
  return buffer.toString('base64url');
}

function newState(): string {
  return base64Url(randomBytes(24));
}

function pkceChallenge(verifier: string): string {
  return base64Url(createHash('sha256').update(verifier, 'utf8').digest());
}

/** sha256 hex (lowercase) of a device secret hash field; validation helper. */
function isSecretHash(value: string | null): boolean {
  return value !== null && /^[0-9a-f]{64}$/.test(value);
}

/** Read a non-empty string field, or null. */
function str(value: unknown, max = 512): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) return null;
  return trimmed;
}

export function createFlows(opts: FlowsOptions): Flows {
  const log = opts.logger ?? silentLogger;
  const doFetch = opts.fetchFn ?? fetch;
  const now = opts.now ?? (() => Date.now());
  const stateTtlMs = opts.stateTtlMs ?? DEFAULT_STATE_TTL_MS;
  const deviceStateTtlMs = opts.deviceStateTtlMs ?? DEFAULT_DEVICE_STATE_TTL_MS;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const available = opts.db !== null && opts.config !== null && opts.verifier !== null;

  /** Resolve endpoints once and cache them for the process lifetime. */
  let cachedEndpoints: OidcEndpoints | null = opts.endpoints ?? null;
  let endpointsInflight: Promise<{ ok: true; endpoints: OidcEndpoints } | FlowFailure> | null = null;

  async function resolveEndpoints(): Promise<{ ok: true; endpoints: OidcEndpoints } | FlowFailure> {
    if (cachedEndpoints) return { ok: true, endpoints: cachedEndpoints };
    const provider = opts.endpointsProvider ?? (opts.verifier ? opts.verifier.endpoints : undefined);
    if (!provider) return { ok: false, code: 'flow_disabled', message: 'OIDC endpoints are not configured' };
    if (endpointsInflight) return endpointsInflight;
    endpointsInflight = (async () => {
      try {
        const resolved = await provider();
        if (!resolved.ok) return { ok: false, code: 'gateway_unavailable', message: resolved.message };
        cachedEndpoints = resolved.endpoints;
        return { ok: true, endpoints: resolved.endpoints };
      } finally {
        endpointsInflight = null;
      }
    })();
    return endpointsInflight;
  }

  function unavailable(): FlowFailure {
    return { ok: false, code: 'flow_disabled', message: 'account login is not configured on this relay' };
  }

  async function deleteState(state: string): Promise<void> {
    await opts.db!.execute('delete from ct_oauth_states where state = ?', [state]);
  }

  async function loadState(state: string): Promise<StateRow | null> {
    const rows = await opts.db!.query<StateRow>(
      `select state, kind, code_verifier, device_id, user_code, expires_at
         from ct_oauth_states where state = ? limit 1`,
      [state],
    );
    return rows[0] ?? null;
  }

  async function saveState(row: StateInput): Promise<void> {
    await opts.db!.execute(
      `insert into ct_oauth_states (state, kind, code_verifier, device_id, user_code, expires_at)
       values (?, ?, ?, ?, ?, from_unixtime(? / 1000))`,
      [row.state, row.kind, row.code_verifier, row.device_id, row.user_code, row.expires_at.getTime()],
    );
  }

  /** Upsert the account cache and issue a relay access + refresh pair. */
  async function credentialsFor(identity: VerifiedIdentity, deviceId: string | null = null): Promise<RelayCredentials> {
    await upsertAccount(opts.db!, {
      accountId: identity.sub,
      issuer: identity.issuer,
      displayName: identity.name,
    });
    const access = await issueToken(opts.db!, {
      accountId: identity.sub,
      deviceId,
      kind: 'access',
      ttlMs: opts.accessTtlMs,
    });
    const refresh = await issueToken(opts.db!, {
      accountId: identity.sub,
      deviceId,
      kind: 'refresh',
      ttlMs: opts.refreshTtlMs,
    });
    return {
      accountId: identity.sub,
      displayName: identity.name,
      accessToken: access.token,
      refreshToken: refresh.token,
      accessExpiresAt: access.expiresAt.toISOString(),
      refreshExpiresAt: refresh.expiresAt.toISOString(),
    };
  }

  /** POST a form-encoded request to a gateway endpoint. Never throws. */
  async function postForm(
    url: string,
    form: Record<string, string>,
    accept: string,
  ): Promise<{ ok: true; status: number; json: Record<string, unknown> } | FlowFailure> {
    const body = new URLSearchParams(form);
    let response: Response;
    try {
      response = await doFetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept },
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      log.warn('gateway request failed', { err: (err as Error).message });
      return { ok: false, code: 'gateway_unavailable', message: `gateway request failed: ${(err as Error).message}` };
    }
    let json: unknown = null;
    try {
      json = await response.json();
    } catch {
      // Some gateway error responses have an empty body; keep status handling.
      json = null;
    }
    if (typeof json !== 'object' || json === null) json = {};
    return { ok: true, status: response.status, json: json as Record<string, unknown> };
  }

  /**
   * Validate the identity token returned by the token endpoint. Prefers the
   * `id_token` and falls back to `access_token`, mirroring `oauth/verify.ts`.
   */
  async function identityFromTokenResponse(json: Record<string, unknown>): Promise<VerifiedIdentity | FlowFailure> {
    const idToken = str(json.id_token, 8192);
    const accessToken = str(json.access_token, 8192);
    const token = idToken ?? accessToken;
    if (!token) return { ok: false, code: 'gateway_rejected', message: 'gateway token response has no token' };
    const result = await opts.verifier!.verify(token);
    if (!result.ok) {
      log.warn('gateway identity token rejected', { code: result.code, detail: result.detail });
      return { ok: false, code: 'verification_failed', message: result.message };
    }
    return result.identity;
  }

  return {
    get available() {
      return available;
    },

    async startFlowA(input) {
      if (!available) return unavailable();
      const codeChallenge = str(input.codeChallenge, 256);
      if (!codeChallenge) return { ok: false, code: 'invalid_request', message: 'code_challenge is required' };
      const resolved = await resolveEndpoints();
      if (!resolved.ok) return resolved;
      const redirectUri = str(input.redirectUri, 512) ?? opts.config!.redirectUri;
      const state = newState();
      const expiresAt = new Date(now() + stateTtlMs);
      try {
        // The challenge is public; storing it lets `complete` reject a
        // `code_verifier` that does not match the one the client selected.
        await saveState({
          state,
          kind: 'pkce',
          code_verifier: codeChallenge,
          device_id: null,
          user_code: null,
          expires_at: expiresAt,
        });
      } catch (err) {
        log.warn('could not persist oauth state', { err: (err as Error).message });
        return { ok: false, code: 'gateway_unavailable', message: 'could not store the login state' };
      }
      const url = new URL(resolved.endpoints.authorizationEndpoint);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', opts.config!.clientId);
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('scope', opts.config!.scopes);
      url.searchParams.set('state', state);
      url.searchParams.set('code_challenge', codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
      return { ok: true, state, authorizeUrl: url.toString(), expiresAt: expiresAt.toISOString() };
    },

    async completeFlowA(input) {
      if (!available) return unavailable();
      const code = str(input.code, 4096);
      const state = str(input.state, 128);
      if (!code || !state) return { ok: false, code: 'invalid_request', message: 'code and state are required' };
      const resolved = await resolveEndpoints();
      if (!resolved.ok) return resolved;
      let row: StateRow | null;
      try {
        row = await loadState(state);
      } catch (err) {
        log.warn('could not read oauth state', { err: (err as Error).message });
        return { ok: false, code: 'gateway_unavailable', message: 'could not read the login state' };
      }
      if (!row || row.kind !== 'pkce') return { ok: false, code: 'unknown_state', message: 'unknown or reused login state' };
      // Single use: consume before touching the gateway so a replay fails.
      try {
        await deleteState(state);
      } catch (err) {
        log.warn('could not consume oauth state', { err: (err as Error).message });
        return { ok: false, code: 'gateway_unavailable', message: 'could not consume the login state' };
      }
      if (row.expires_at.getTime() < now()) return { ok: false, code: 'state_expired', message: 'login state has expired' };
      const codeVerifier = str(input.codeVerifier, 256);
      if (!codeVerifier) return { ok: false, code: 'invalid_request', message: 'code_verifier is required' };
      // The verifier must match the challenge the client registered in `start`.
      if (pkceChallenge(codeVerifier) !== row.code_verifier) {
        return { ok: false, code: 'invalid_request', message: 'code_verifier does not match code_challenge' };
      }

      const form: Record<string, string> = {
        grant_type: 'authorization_code',
        code,
        redirect_uri: opts.config!.redirectUri,
        client_id: opts.config!.clientId,
        code_verifier: codeVerifier,
      };
      if (opts.config!.clientSecret) form.client_secret = opts.config!.clientSecret;
      const response = await postForm(resolved.endpoints.tokenEndpoint, form, 'application/json');
      if (!('status' in response)) return response;
      if (response.status >= 400) {
        log.warn('gateway rejected the authorization code', { status: response.status });
        return { ok: false, code: 'gateway_rejected', message: 'gateway rejected the authorization code' };
      }
      const identity = await identityFromTokenResponse(response.json);
      if ('code' in identity) return identity;
      try {
        return { ok: true, credentials: await credentialsFor(identity) };
      } catch (err) {
        log.warn('could not issue relay credentials', { err: (err as Error).message });
        return { ok: false, code: 'gateway_unavailable', message: 'could not issue relay credentials' };
      }
    },

    async startDevice(input) {
      if (!available) return unavailable();
      const deviceId = str(input.deviceId, 128);
      if (!deviceId) return { ok: false, code: 'invalid_request', message: 'deviceId is required' };
      const resolved = await resolveEndpoints();
      if (!resolved.ok) return resolved;
      const endpoint = resolved.endpoints.deviceAuthorizationEndpoint;
      if (!endpoint) {
        return {
          ok: false,
          code: 'device_flow_unsupported',
          message: 'the gateway does not advertise device authorization; use the browser flow',
        };
      }
      // A device that already holds a secret can register itself here; the
      // secret is hashed before it reaches the database and is never logged.
      const secretHash = str(input.secretHash, 64);
      if (secretHash !== null && !isSecretHash(secretHash)) {
        return { ok: false, code: 'invalid_request', message: 'secretHash must be 64 lowercase hex characters' };
      }
      const form: Record<string, string> = { client_id: opts.config!.clientId, scope: opts.config!.scopes };
      if (opts.config!.clientSecret) form.client_secret = opts.config!.clientSecret;
      const response = await postForm(endpoint, form, 'application/json');
      if (!('status' in response)) return response;
      if (response.status >= 400) {
        log.warn('gateway rejected device authorization', { status: response.status });
        return { ok: false, code: 'gateway_rejected', message: 'gateway rejected the device authorization request' };
      }
      const deviceCode = str(response.json.device_code, 4096);
      const userCode = str(response.json.user_code, 64);
      const verificationUri = str(response.json.verification_uri, 512) ?? str(response.json.verification_url, 512);
      const verificationUriComplete = str(response.json.verification_uri_complete, 1024);
      if (!deviceCode || !userCode || !verificationUri) {
        return { ok: false, code: 'gateway_rejected', message: 'gateway device response is missing fields' };
      }
      const expiresIn = Number.isFinite(response.json.expires_in) ? Number(response.json.expires_in) : 600;
      const interval = Number.isFinite(response.json.interval) ? Number(response.json.interval) : 5;
      const ttl = Math.min(Math.min(Math.max(expiresIn, 30), 3600) * 1000, deviceStateTtlMs);
      const state = newState();
      const expiresAt = new Date(now() + ttl);
      try {
        if (secretHash !== null) {
          await upsertDevice(opts.db!, {
            deviceId,
            label: str(input.label, 191),
            platform: str(input.platform, 64),
            secretHash,
          });
        }
        await saveState({
          state,
          kind: 'device',
          // Reuse the state column to carry the gateway device code; it is
          // short-lived and never logged.
          code_verifier: deviceCode,
          device_id: deviceId,
          user_code: userCode,
          expires_at: expiresAt,
        });
      } catch (err) {
        log.warn('could not persist device state', { err: (err as Error).message });
        return { ok: false, code: 'gateway_unavailable', message: 'could not store the device state' };
      }
      return {
        ok: true,
        state,
        userCode,
        verificationUri: verificationUriComplete ?? verificationUri,
        interval: Math.min(Math.max(interval, 1), 60),
        expiresIn: Math.round(ttl / 1000),
      };
    },

    async pollDevice(input) {
      if (!available) return unavailable();
      const deviceId = str(input.deviceId, 128);
      const userCode = str(input.userCode, 64);
      if (!deviceId || !userCode) return { ok: false, code: 'invalid_request', message: 'deviceId and userCode are required' };
      // Look the pending device flow up by (device_id, user_code); the state
      // itself is only returned to the caller that started the flow.
      const rows = await opts.db!.query<StateRow>(
        `select state, kind, code_verifier, device_id, user_code, expires_at
           from ct_oauth_states
          where kind = 'device' and device_id = ? and user_code = ?
          order by created_at desc limit 1`,
        [deviceId, userCode],
      );
      const row = rows[0];
      if (!row) return { ok: false, code: 'unknown_state', message: 'unknown or expired device code' };
      if (row.expires_at.getTime() < now()) {
        await deleteState(row.state);
        return { ok: false, code: 'expired_token', message: 'the device code has expired' };
      }
      const deviceCode = str(row.code_verifier, 4096);
      if (!deviceCode) return { ok: false, code: 'unknown_state', message: 'device state is incomplete' };
      const resolved = await resolveEndpoints();
      if (!resolved.ok) return resolved;

      const form: Record<string, string> = {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceCode,
        client_id: opts.config!.clientId,
      };
      if (opts.config!.clientSecret) form.client_secret = opts.config!.clientSecret;
      const response = await postForm(resolved.endpoints.tokenEndpoint, form, 'application/json');
      if (!('status' in response)) return response;

      if (response.status >= 400) {
        const error = str(response.json.error, 64) ?? '';
        switch (error) {
          case 'authorization_pending':
            return { ok: false, code: 'authorization_pending', message: 'waiting for the user to approve' };
          case 'slow_down':
            return { ok: false, code: 'slow_down', message: 'polling too fast; increase the interval' };
          case 'expired_token':
            await deleteState(row.state);
            return { ok: false, code: 'expired_token', message: 'the device code has expired' };
          case 'access_denied':
            await deleteState(row.state);
            return { ok: false, code: 'access_denied', message: 'the user denied the request' };
          default:
            return { ok: false, code: 'gateway_rejected', message: `gateway rejected the device code (${error || response.status})` };
        }
      }

      const identity = await identityFromTokenResponse(response.json);
      if ('code' in identity) return identity;

      // The device must already be registered (it authenticates as itself with
      // its own secret before showing the user code, PRD R11) unless
      // `device/start` supplied the secret hash.
      try {
        const existing = await opts.db!.query<RowDataPacket & { device_id: string }>(
          'select device_id from ct_devices where device_id = ? limit 1',
          [deviceId],
        );
        if (existing.length === 0) {
          return { ok: false, code: 'device_unknown', message: 'the device must register with the relay before binding' };
        }
        await createBinding(opts.db!, { accountId: identity.sub, deviceId, createdBy: 'device_auth' });
        await deleteState(row.state);
        // Device-scope the access token so it can only drive this device.
        return { ok: true, status: 'approved', credentials: await credentialsFor(identity, deviceId) };
      } catch (err) {
        log.warn('could not bind the approved device', { err: (err as Error).message });
        return { ok: false, code: 'gateway_unavailable', message: 'could not store the device binding' };
      }
    },

    async purgeExpiredStates(): Promise<number> {
      if (!opts.db) return 0;
      const result = await opts.db.execute('delete from ct_oauth_states where expires_at < current_timestamp');
      return result.affectedRows;
    },
  };
}

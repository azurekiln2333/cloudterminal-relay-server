// HTTP JSON API for account login, the device list and binding management
// (design §4, implement.md step 6).
//
// The API lives on the same HTTP server as `/ws` and `/healthz`. It is attached
// with `attachApi(server, deps)`, which becomes the first `request` listener:
// `/api/v1/*` and `/readyz` are answered here, every other request falls through
// to the relay's existing handler untouched, so the websocket upgrade and
// `/healthz` keep working.
//
// Every failure is JSON with a machine-readable `code`. 4xx is a caller problem
// (bad input, missing/expired credentials, unknown resource); 5xx is this relay
// or the gateway failing. Secrets, tokens and authorization codes are never
// logged.

import type { IncomingMessage, Server, ServerResponse } from 'node:http';

import { listDevicesForAccount, listAccountsForDevice, createBinding, revokeBinding, isBound } from '../db/bindings.ts';
import { getAccount } from '../db/accounts.ts';
import type { DbPool } from '../db/pool.ts';
import { revokeToken, rotateRefresh, verifyToken, issueToken } from '../db/tokens.ts';
import { type Logger, silentLogger } from '../shared/log.ts';
import { type OauthConfig, type OauthState } from '../oauth/config.ts';
import type { Flows, FlowFailure, FlowFailureCode } from '../oauth/flows.ts';
import type { Verifier } from '../oauth/verify.ts';

export type ApiDeps = {
  /** A ready pool, or null when the account layer is disabled/unreachable. */
  db: DbPool | null;
  /** OAuth settings, or null when disabled/degraded. */
  config: OauthConfig | null;
  oauthState: OauthState;
  oauthMessage: string;
  /** Token verifier used by the API itself (not the relay hot path). */
  verifier: Verifier | null;
  /** Flow A / flow B entry points, or null when account login is off. */
  flows: Flows | null;
  /** Optional live online-state lookup for `GET /devices`. */
  isDeviceOnline?: (deviceId: string) => boolean;
  /**
   * Resolve a one-time `pair_code` to the device it belongs to. Supplied by the
   * composition root; when absent the bind-by-code route reports
   * `pair_code_unavailable` instead of guessing.
   */
  resolvePairCode?: (code: string) => Promise<string | null>;
  /** Called after a successful revoke so the relay can drop its cache. */
  onBindingRevoked?: (accountId: string, deviceId: string) => void;
  /** Relay-issued token lifetimes; must match the flows' configuration. */
  accessTtlMs: number;
  refreshTtlMs: number;
  /** Per-IP failed-auth budget, mirroring the relay. */
  maxAuthFailures?: number;
  authWindowMs?: number;
  /** Maximum accepted JSON body size. */
  maxBodyBytes?: number;
  logger?: Logger;
};

export type Api = {
  /** Remove the listener from the server (tests / graceful shutdown). */
  detach(): void;
};

const API_PREFIX = '/api/v1/';
const DEFAULT_MAX_AUTH_FAILURES = 20;
const DEFAULT_AUTH_WINDOW_MS = 10 * 60_000;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;

type Json = Record<string, unknown>;

/** Map a flow failure to an HTTP status; all are 4xx except gateway/DB faults. */
function statusForFlow(code: FlowFailureCode): number {
  switch (code) {
    case 'invalid_request':
      return 400;
    case 'unknown_state':
    case 'state_expired':
    case 'state_consumed':
    case 'expired_token':
    case 'access_denied':
      return 400;
    case 'device_unknown':
      return 404;
    case 'device_flow_unsupported':
      return 501;
    case 'flow_disabled':
    case 'misconfigured':
      return 503;
    case 'gateway_unavailable':
    case 'verification_failed':
      return 502;
    case 'gateway_rejected':
      return 401;
    case 'authorization_pending':
    case 'slow_down':
      // Not errors: the client keeps polling.
      return 202;
    default:
      return 400;
  }
}

/** Machine-readable codes that stay stable for clients. */
const FLOW_DETAIL_CODES = new Set<string>([
  'invalid_request',
  'flow_disabled',
  'unknown_state',
  'state_expired',
  'state_consumed',
  'gateway_unavailable',
  'gateway_rejected',
  'verification_failed',
  'device_flow_unsupported',
  'authorization_pending',
  'slow_down',
  'expired_token',
  'access_denied',
  'device_unknown',
  'misconfigured',
]);

function flowBody(failure: FlowFailure): Json {
  const code = FLOW_DETAIL_CODES.has(failure.code) ? failure.code : 'invalid_request';
  return { error: { code, message: failure.message } };
}

class BodyError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Read and parse a bounded JSON body; never yields a raw token to the log. */
async function readJson(req: IncomingMessage, maxBytes: number): Promise<Json> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    size += buf.length;
    if (size > maxBytes) throw new BodyError(413, 'payload_too_large', 'request body is too large');
    chunks.push(buf);
  }
  if (size === 0) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new BodyError(400, 'invalid_json', 'request body is not valid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new BodyError(400, 'invalid_json', 'request body must be a JSON object');
  }
  return parsed as Json;
}

/** Trimmed non-empty string, or undefined. Does not reject on length. */
function text(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function sendJson(res: ServerResponse, status: number, body: Json): void {
  if (res.headersSent || res.writableEnded) return;
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': String(payload.length) });
  res.end(payload);
}

function sendError(res: ServerResponse, status: number, code: string, message: string): void {
  sendJson(res, status, { error: { code, message } });
}

function clientIp(req: IncomingMessage): string {
  if (process.env.RELAY_TRUST_PROXY === '1') {
    const fwd = req.headers['x-forwarded-for'];
    const first = (Array.isArray(fwd) ? fwd[0] : fwd)?.split(',')[0]?.trim();
    if (first) return first;
  }
  return req.socket.remoteAddress ?? 'unknown';
}

/** Bearer credential from the `Authorization` header, or null. */
function bearer(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1]?.trim() || null;
}

export function attachApi(server: Server, deps: ApiDeps): Api {
  const log = deps.logger ?? silentLogger;
  const maxAuthFailures = deps.maxAuthFailures ?? DEFAULT_MAX_AUTH_FAILURES;
  const authWindowMs = deps.authWindowMs ?? DEFAULT_AUTH_WINDOW_MS;
  const maxBodyBytes = deps.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  const authFailures = new Map<string, { count: number; since: number }>();
  function isRateLimited(ip: string): boolean {
    const entry = authFailures.get(ip);
    if (!entry) return false;
    if (Date.now() - entry.since > authWindowMs) {
      authFailures.delete(ip);
      return false;
    }
    return entry.count >= maxAuthFailures;
  }
  function recordAuthFailure(ip: string): void {
    const now = Date.now();
    const entry = authFailures.get(ip);
    if (!entry || now - entry.since > authWindowMs) authFailures.set(ip, { count: 1, since: now });
    else entry.count++;
  }

  /** Account features are usable only with a pool, a ready config and flows. */
  function accountReady(): boolean {
    return deps.db !== null && !deps.db.closed && deps.config !== null && deps.flows !== null;
  }

  /** 503 with an actionable message when account login is not ready. */
  function requireAccountLayer(res: ServerResponse): boolean {
    if (accountReady()) return true;
    const detail =
      deps.oauthState === 'degraded'
        ? deps.oauthMessage
        : deps.oauthState === 'disabled'
          ? 'account login is not configured (set OAUTH_* and DB_*)'
          : 'account login is temporarily unavailable';
    sendError(res, 503, 'auth_unavailable', detail);
    return false;
  }

  type AuthContext = { accountId: string; deviceId: string | null };
  /** Resolve the caller's access token; writes 401 and returns null on failure. */
  async function authenticate(req: IncomingMessage, res: ServerResponse): Promise<AuthContext | null> {
    const ip = clientIp(req);
    if (isRateLimited(ip)) {
      sendError(res, 429, 'rate_limited', 'too many failed attempts, try again later');
      return null;
    }
    const token = bearer(req);
    if (!token) {
      recordAuthFailure(ip);
      sendError(res, 401, 'unauthorized', 'missing bearer token');
      return null;
    }
    if (!deps.db || deps.db.closed) {
      sendError(res, 503, 'db_unavailable', 'account storage is unavailable');
      return null;
    }
    let verified;
    try {
      verified = await verifyToken(deps.db, token);
    } catch (err) {
      log.warn('api token verification failed', { err: (err as Error).message });
      sendError(res, 503, 'db_unavailable', 'account storage is unavailable');
      return null;
    }
    if (!verified || verified.kind !== 'access') {
      recordAuthFailure(ip);
      sendError(res, 401, 'unauthorized', 'invalid or expired access token');
      return null;
    }
    return { accountId: verified.accountId, deviceId: verified.deviceId };
  }

  // --- route handlers -------------------------------------------------------

  async function handleAuthStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!requireAccountLayer(res)) return;
    const body = await readJson(req, maxBodyBytes);
    const codeChallenge = text(body.code_challenge);
    if (!codeChallenge) return sendError(res, 400, 'invalid_request', 'code_challenge is required');
    const redirectUri = text(body.redirect_uri);
    const result = await deps.flows!.startFlowA({
      codeChallenge,
      ...(redirectUri ? { redirectUri } : {}),
    });
    if (!result.ok) return sendError(res, statusForFlow(result.code), result.code, result.message);
    sendJson(res, 200, { state: result.state, authorize_url: result.authorizeUrl, expires_at: result.expiresAt });
  }

  async function handleAuthComplete(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!requireAccountLayer(res)) return;
    const body = await readJson(req, maxBodyBytes);
    const code = text(body.code);
    const state = text(body.state);
    const codeVerifier = text(body.code_verifier);
    if (!code || !state || !codeVerifier) {
      return sendError(res, 400, 'invalid_request', 'code, state and code_verifier are required');
    }
    const result = await deps.flows!.completeFlowA({ code, state, codeVerifier });
    if (!result.ok) return sendError(res, statusForFlow(result.code), result.code, result.message);
    sendJson(res, 200, credentialsBody(result.credentials));
  }

  async function handleDeviceStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!requireAccountLayer(res)) return;
    const body = await readJson(req, maxBodyBytes);
    const deviceId = text(body.device_id);
    if (!deviceId) return sendError(res, 400, 'invalid_request', 'device_id is required');
    const result = await deps.flows!.startDevice({
      deviceId,
      ...(text(body.label) ? { label: text(body.label)! } : {}),
      ...(text(body.platform) ? { platform: text(body.platform)! } : {}),
      ...(text(body.secret_hash) ? { secretHash: text(body.secret_hash)! } : {}),
    });
    if (!result.ok) return sendError(res, statusForFlow(result.code), result.code, result.message);
    sendJson(res, 200, {
      state: result.state,
      user_code: result.userCode,
      verification_uri: result.verificationUri,
      interval: result.interval,
      expires_in: result.expiresIn,
    });
  }

  async function handleDevicePoll(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!requireAccountLayer(res)) return;
    const body = await readJson(req, maxBodyBytes);
    const deviceId = text(body.device_id);
    const userCode = text(body.user_code);
    if (!deviceId || !userCode) return sendError(res, 400, 'invalid_request', 'device_id and user_code are required');
    const result = await deps.flows!.pollDevice({ deviceId, userCode });
    if (!result.ok) {
      // Pending/slow-down are expected poll results, not failures.
      if (result.code === 'authorization_pending' || result.code === 'slow_down') {
        return sendJson(res, 202, { status: result.code, error: { code: result.code, message: result.message } });
      }
      return sendError(res, statusForFlow(result.code), result.code, result.message);
    }
    sendJson(res, 200, { status: 'approved', ...credentialsBody(result.credentials) });
  }

  async function handleTokenRefresh(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Refreshing only touches the relay's own token table; it does not need the
    // gateway, so a degraded OAuth layer still allows an existing session to
    // rotate rather than forcing a full re-login.
    if (!deps.db || deps.db.closed) return sendError(res, 503, 'db_unavailable', 'account storage is unavailable');
    const body = await readJson(req, maxBodyBytes);
    const refreshToken = text(body.refresh_token);
    if (!refreshToken) return sendError(res, 400, 'invalid_request', 'refresh_token is required');
    const db = deps.db!;
    const rotated = await rotateRefresh(db, refreshToken, deps.refreshTtlMs);
    if (!rotated.ok) {
      return sendError(res, 401, 'invalid_grant', 'refresh token is invalid, expired or already used');
    }
    // A rotated refresh pair also gets a fresh access token for the same scope.
    const access = await issueToken(db, {
      accountId: rotated.token.accountId,
      deviceId: rotated.token.deviceId,
      kind: 'access',
      ttlMs: deps.accessTtlMs,
    });
    sendJson(res, 200, {
      account_id: rotated.token.accountId,
      access_token: access.token,
      refresh_token: rotated.token.token,
      access_expires_at: access.expiresAt.toISOString(),
      refresh_expires_at: rotated.token.expiresAt.toISOString(),
    });
  }

  async function handleLogout(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req, maxBodyBytes);
    const accessToken = bearer(req);
    const refreshToken = text(body.refresh_token);
    if (!accessToken && !refreshToken) return sendError(res, 400, 'invalid_request', 'a bearer token or refresh_token is required');
    if (!deps.db || deps.db.closed) return sendError(res, 503, 'db_unavailable', 'account storage is unavailable');
    let revoked = 0;
    if (accessToken && (await revokeToken(deps.db, accessToken))) revoked++;
    if (refreshToken && (await revokeToken(deps.db, refreshToken))) revoked++;
    // Logout is idempotent: an unknown token is still a success.
    sendJson(res, 200, { ok: true, revoked });
  }

  async function handleListDevices(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const auth = await authenticate(req, res);
    if (!auth) return;
    const rows = await listDevicesForAccount(deps.db!, auth.accountId);
    const account = await getAccount(deps.db!, auth.accountId);
    sendJson(res, 200, {
      account_id: auth.accountId,
      display_name: account?.displayName ?? null,
      devices: rows.map((row) => ({
        device_id: row.deviceId,
        label: row.label,
        platform: row.platform,
        role: row.role,
        device_revoked: row.deviceRevoked,
        online: deps.isDeviceOnline ? deps.isDeviceOnline(row.deviceId) : false,
      })),
    });
  }

  async function handleCreateBinding(
    req: IncomingMessage,
    res: ServerResponse,
    deviceId: string,
  ): Promise<void> {
    const auth = await authenticate(req, res);
    if (!auth) return;
    const body = await readJson(req, maxBodyBytes);
    const pairCode = text(body.pair_code);
    if (!pairCode) return sendError(res, 400, 'invalid_request', 'pair_code is required for consent');
    if (!deps.resolvePairCode) {
      // Without a resolver the relay cannot prove device consent; never bind
      // on the account's word alone (PRD R12).
      return sendError(res, 503, 'pair_code_unavailable', 'pairing-code consent is not available on this relay');
    }
    let resolved: string | null;
    try {
      resolved = await deps.resolvePairCode(pairCode);
    } catch (err) {
      log.warn('pair code resolution failed', { err: (err as Error).message });
      return sendError(res, 503, 'pair_code_unavailable', 'pairing-code lookup failed, retry shortly');
    }
    if (!resolved) return sendError(res, 404, 'pair_code_invalid', 'the pairing code is invalid or expired');
    if (resolved !== deviceId) {
      return sendError(res, 403, 'pair_code_mismatch', 'the pairing code belongs to a different device');
    }
    try {
      await createBinding(deps.db!, { accountId: auth.accountId, deviceId, createdBy: 'pair_code' });
    } catch (err) {
      log.warn('binding creation failed', { deviceId, err: (err as Error).message });
      return sendError(res, 503, 'db_unavailable', 'could not store the binding');
    }
    sendJson(res, 201, { ok: true, account_id: auth.accountId, device_id: deviceId });
  }

  async function handleListAccounts(
    req: IncomingMessage,
    res: ServerResponse,
    deviceId: string,
  ): Promise<void> {
    const auth = await authenticate(req, res);
    if (!auth) return;
    // Isolation: only an account actively bound to this device may see the
    // device's other accounts (AC1).
    const allowed = await isBound(deps.db!, auth.accountId, deviceId);
    if (!allowed) return sendError(res, 403, 'forbidden', 'your account is not bound to this device');
    const accounts = await listAccountsForDevice(deps.db!, deviceId);
    sendJson(res, 200, {
      device_id: deviceId,
      accounts: accounts.map((row) => ({
        account_id: row.accountId,
        display_name: row.displayName,
        role: row.role,
        label: row.label,
      })),
    });
  }

  async function handleRevokeBinding(
    req: IncomingMessage,
    res: ServerResponse,
    deviceId: string,
    accountId: string,
  ): Promise<void> {
    const auth = await authenticate(req, res);
    if (!auth) return;
    if (accountId !== auth.accountId) {
      // Only an owner of this device may revoke someone else's binding.
      const accounts = await listAccountsForDevice(deps.db!, deviceId);
      const own = accounts.find((a) => a.accountId === auth.accountId);
      if (!own || own.role !== 'owner') {
        return sendError(res, 403, 'forbidden', 'only the account owner or the bound account itself may revoke');
      }
    }
    const revoked = await revokeBinding(deps.db!, accountId, deviceId);
    if (!revoked) return sendError(res, 404, 'binding_not_found', 'no active binding for that account and device');
    deps.onBindingRevoked?.(accountId, deviceId);
    sendJson(res, 200, { ok: true, account_id: accountId, device_id: deviceId });
  }

  async function handleReadyz(res: ServerResponse): Promise<void> {
    const dbConfigured = deps.db !== null;
    const dbState = deps.db ? (deps.db.closed ? 'closed' : deps.db.state) : 'disabled';
    let dbOk = dbConfigured && !deps.db!.closed;
    if (dbOk) {
      try {
        await deps.db!.ping();
      } catch {
        dbOk = false;
      }
    }
    const oauthOk = deps.oauthState === 'disabled' || (deps.oauthState === 'ready' && deps.flows?.available === true);
    // Legacy-only relays (both layers off) are ready; a configured-but-broken
    // layer is not.
    const degradedConfigured = deps.oauthState === 'degraded' || (deps.oauthState === 'ready' && !oauthOk);
    const ready = !degradedConfigured && !(dbConfigured && !dbOk);
    sendJson(res, ready ? 200 : 503, {
      ok: ready,
      db: { configured: dbConfigured, state: dbState, reachable: dbOk },
      oauth: { state: deps.oauthState, strategy: deps.config?.verify ?? null, message: deps.oauthMessage || undefined },
    });
  }

  // --- dispatch -------------------------------------------------------------

  async function dispatch(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? 'GET';
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;

    if (path === '/readyz') {
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'GET only');
      return handleReadyz(res);
    }

    // Auth routes.
    if (path === `${API_PREFIX}auth/oauth/start`) {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'POST only');
      return handleAuthStart(req, res);
    }
    if (path === `${API_PREFIX}auth/oauth/complete`) {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'POST only');
      return handleAuthComplete(req, res);
    }
    if (path === `${API_PREFIX}auth/device/start`) {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'POST only');
      return handleDeviceStart(req, res);
    }
    if (path === `${API_PREFIX}auth/device/poll`) {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'POST only');
      return handleDevicePoll(req, res);
    }
    if (path === `${API_PREFIX}auth/token/refresh`) {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'POST only');
      return handleTokenRefresh(req, res);
    }
    if (path === `${API_PREFIX}auth/logout`) {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'POST only');
      return handleLogout(req, res);
    }

    if (path === `${API_PREFIX}devices`) {
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'GET only');
      return handleListDevices(req, res);
    }

    const bindingMatch = /^\/api\/v1\/devices\/([^/]+)\/bindings$/.exec(path);
    if (bindingMatch) {
      const deviceId = decodeURIComponent(bindingMatch[1]!);
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'POST only');
      return handleCreateBinding(req, res, deviceId);
    }
    const accountsMatch = /^\/api\/v1\/devices\/([^/]+)\/accounts$/.exec(path);
    if (accountsMatch) {
      const deviceId = decodeURIComponent(accountsMatch[1]!);
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'GET only');
      return handleListAccounts(req, res, deviceId);
    }
    const revokeMatch = /^\/api\/v1\/devices\/([^/]+)\/bindings\/([^/]+)$/.exec(path);
    if (revokeMatch) {
      const deviceId = decodeURIComponent(revokeMatch[1]!);
      const accountId = decodeURIComponent(revokeMatch[2]!);
      if (method !== 'DELETE') return sendError(res, 405, 'method_not_allowed', 'DELETE only');
      return handleRevokeBinding(req, res, deviceId, accountId);
    }

    sendError(res, 404, 'not_found', 'no such API route');
  }

  // Take over `request` as the first listener while preserving the existing
  // relay handler. The existing handler always writes a response (the 404
  // fallback), so it must not run for a path the API owns. Websocket upgrades
  // use a separate `upgrade` listener and are untouched.
  const existing = server.listeners('request').slice() as Array<
    (req: IncomingMessage, res: ServerResponse) => void
  >;
  server.removeAllListeners('request');
  const listener = (req: IncomingMessage, res: ServerResponse): void => {
    const path = (req.url ?? '').split('?')[0] ?? '';
    if (path === '/readyz' || path.startsWith(API_PREFIX)) {
      dispatch(req, res).catch((err) => {
        if (err instanceof BodyError) return sendError(res, err.status, err.code, err.message);
        log.error('api request failed', { path, err: (err as Error).message });
        sendError(res, 500, 'internal_error', 'the relay could not complete this request');
      });
      return;
    }
    for (const fn of existing) fn.call(server, req, res);
  };
  server.on('request', listener);

  log.info('api attached', { prefix: API_PREFIX, accountLayer: accountReady() ? 'ready' : deps.oauthState });

  return {
    detach() {
      server.removeListener('request', listener);
      // Restore the relay's original handler so the server keeps working.
      for (const fn of existing) server.on('request', fn as never);
    },
  };
}

function credentialsBody(credentials: {
  accountId: string;
  displayName: string | null;
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: string;
  refreshExpiresAt: string;
}): Json {
  return {
    account_id: credentials.accountId,
    display_name: credentials.displayName,
    access_token: credentials.accessToken,
    refresh_token: credentials.refreshToken,
    token_type: 'Bearer',
    access_expires_at: credentials.accessExpiresAt,
    refresh_expires_at: credentials.refreshExpiresAt,
  };
}

// Step 5: OAuth flow A (PKCE) and flow B (device authorization).
//
// A local `node:http` stub gateway answers the discovery, JWKS, token and
// device-authorization endpoints. The database is an in-memory fake matching
// the SQL shapes used by `db/*` and `src/oauth/flows.ts`, so the suite runs
// without MySQL. No real network is touched.

import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as rsaSign, createHash, type KeyObject } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { RowDataPacket, ResultSetHeader } from 'mysql2/promise';
import { after, before, describe, it } from 'node:test';

import type { DbPool } from '../src/db/pool.ts';
import { loadOauthConfig, type OauthConfig } from '../src/oauth/config.ts';
import { createFlows, type Flows } from '../src/oauth/flows.ts';
import { createVerifier } from '../src/oauth/verify.ts';
import { parseDiscoveryDocument } from '../src/oauth/discovery.ts';

const ISSUER = 'https://sso.test';
const AUDIENCE = 'cloudterminal-relay';

// --- in-memory database -----------------------------------------------------

type StateRow = {
  state: string;
  kind: string;
  code_verifier: string | null;
  device_id: string | null;
  user_code: string | null;
  expires_at: Date;
};

type FakeDatabase = DbPool & {
  accounts: Map<string, { displayName: string | null }>;
  devices: Map<string, { secretHash: string }>;
  bindings: Set<string>;
  tokens: Map<string, { accountId: string; deviceId: string | null; kind: string; expiresAt: Date; revoked: boolean }>;
  states: Map<string, StateRow>;
};

function likeDate(value: unknown): Date {
  return value instanceof Date ? value : new Date(Number(value));
}

function createFakeDatabase(): FakeDatabase {
  const accounts = new Map<string, { displayName: string | null }>();
  const devices = new Map<string, { secretHash: string }>();
  const bindings = new Set<string>();
  const tokens = new Map<string, { accountId: string; deviceId: string | null; kind: string; expiresAt: Date; revoked: boolean }>();
  const states = new Map<string, StateRow>();

  const db: FakeDatabase = {
    state: 'ready',
    accounts,
    devices,
    bindings,
    tokens,
    states,
    async query<Row extends RowDataPacket = RowDataPacket>(sql: string, values: readonly unknown[] = []): Promise<Row[]> {
      const s = sql.replace(/\s+/g, ' ').toLowerCase();
      if (s.includes('from ct_oauth_states') && s.includes('where state = ?')) {
        const row = states.get(String(values[0]));
        return (row ? [row] : []) as unknown as Row[];
      }
      if (s.includes('from ct_oauth_states') && s.includes('user_code = ?')) {
        const [deviceId, userCode] = values as [string, string];
        const row = [...states.values()].find((r) => r.kind === 'device' && r.device_id === deviceId && r.user_code === userCode);
        return (row ? [row] : []) as unknown as Row[];
      }
      if (s.includes('from ct_devices where device_id')) {
        const id = String(values[0]);
        return (devices.has(id) ? [{ device_id: id }] : []) as unknown as Row[];
      }
      if (s.includes('from ct_tokens') && s.includes('token_hash = ?')) {
        const hash = String(values[0]);
        const row = tokens.get(hash);
        if (!row || row.revoked || row.expiresAt.getTime() <= Date.now()) return [] as unknown as Row[];
        return [
          { account_id: row.accountId, device_id: row.deviceId, kind: row.kind, expires_at: row.expiresAt },
        ] as unknown as Row[];
      }
      return [] as unknown as Row[];
    },
    async execute(sql: string, values: readonly unknown[] = []): Promise<ResultSetHeader> {
      const s = sql.replace(/\s+/g, ' ').toLowerCase();
      if (s.startsWith('insert into ct_oauth_states')) {
        const [state, kind, codeVerifier, deviceId, userCode, expiresMs] = values as [
          string,
          string,
          string | null,
          string | null,
          string | null,
          number,
        ];
        states.set(state, {
          state,
          kind,
          code_verifier: codeVerifier,
          device_id: deviceId,
          user_code: userCode,
          expires_at: likeDate(expiresMs),
        });
        return { affectedRows: 1 } as ResultSetHeader;
      }
      if (s.startsWith('delete from ct_oauth_states')) {
        if (s.includes('where state = ?')) {
          const removed = states.delete(String(values[0]));
          return { affectedRows: removed ? 1 : 0 } as ResultSetHeader;
        }
        // purge: delete expired
        let removed = 0;
        for (const [key, row] of states) {
          if (row.expires_at.getTime() < Date.now()) {
            states.delete(key);
            removed++;
          }
        }
        return { affectedRows: removed } as ResultSetHeader;
      }
      if (s.startsWith('insert into ct_accounts')) {
        accounts.set(String(values[0]), { displayName: (values[2] as string | null) ?? null });
        return { affectedRows: 1 } as ResultSetHeader;
      }
      if (s.startsWith('insert into ct_devices')) {
        devices.set(String(values[0]), { secretHash: String(values[3]) });
        return { affectedRows: 1 } as ResultSetHeader;
      }
      if (s.startsWith('insert into ct_bindings')) {
        const [accountId, deviceId] = values as [string, string];
        bindings.add(`${accountId}\u0000${deviceId}`);
        return { affectedRows: 1 } as ResultSetHeader;
      }
      if (s.startsWith('insert into ct_tokens')) {
        const [hash, accountId, deviceId, kind, expiresMs] = values as [string, string, string | null, string, number];
        tokens.set(hash, { accountId, deviceId, kind, expiresAt: likeDate(expiresMs), revoked: false });
        return { affectedRows: 1 } as ResultSetHeader;
      }
      if (s.startsWith('update ct_tokens set revoked_at')) {
        const hash = String(values[0]);
        const row = tokens.get(hash);
        if (row) row.revoked = true;
        return { affectedRows: row ? 1 : 0 } as ResultSetHeader;
      }
      return { affectedRows: 0 } as ResultSetHeader;
    },
    async withTransaction<T>(fn: (tx: { query: DbPool['query']; execute: DbPool['execute'] }) => Promise<T>) {
      return fn({ query: db.query.bind(db), execute: db.execute.bind(db) });
    },
    async ping() {},
    async close() {},
    get closed() {
      return false;
    },
  };
  return db;
}

// --- stub gateway -----------------------------------------------------------

type Key = { kid: string; privateKey: KeyObject; publicJwk: Record<string, unknown> };

function makeKey(kid: string): Key {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  jwk.kid = kid;
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  return { kid, privateKey, publicJwk: jwk };
}

function b64(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function mint(key: Key, overrides: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const h = b64({ alg: 'RS256', typ: 'JWT', kid: key.kid });
  const p = b64({ sub: 'user-1', iss: ISSUER, aud: AUDIENCE, exp: now + 600, iat: now, name: 'Ada', ...overrides });
  return `${h}.${p}.${rsaSign('RSA-SHA256', Buffer.from(`${h}.${p}`), key.privateKey).toString('base64url')}`;
}

type StubOptions = {
  /** Include device_authorization_endpoint in discovery. */
  deviceEndpoint?: boolean;
  /** Token endpoint behavior: returns this JSON, or throws to simulate failure. */
  tokenHandler?: (params: URLSearchParams, calls: number) => { status: number; body: Record<string, unknown> };
};

type Gateway = {
  origin: string;
  tokenCalls: number;
  deviceCalls: number;
  lastDeviceBody: URLSearchParams | null;
  stop(): Promise<void>;
};

async function startGateway(key: Key, opts: StubOptions = {}): Promise<Gateway> {
  const gateway: Gateway = {
    origin: '',
    tokenCalls: 0,
    deviceCalls: 0,
    lastDeviceBody: null,
    async stop() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
  const server: Server = createServer((req, res) => {
    const path = (req.url ?? '').split('?')[0];
    if (path === '/.well-known/openid-configuration') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          issuer: ISSUER,
          authorization_endpoint: `${gateway.origin}/oauth2/authorize`,
          token_endpoint: `${gateway.origin}/oauth2/token`,
          jwks_uri: `${gateway.origin}/.well-known/jwks.json`,
          introspection_endpoint: `${gateway.origin}/oauth2/introspect`,
          ...(opts.deviceEndpoint ? { device_authorization_endpoint: `${gateway.origin}/oauth2/device_authorization` } : {}),
        }),
      );
      return;
    }
    if (path === '/.well-known/jwks.json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ keys: [key.publicJwk] }));
      return;
    }
    if (path === '/oauth2/token') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c as Buffer));
      req.on('end', () => {
        gateway.tokenCalls++;
        const params = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
        const result = opts.tokenHandler
          ? opts.tokenHandler(params, gateway.tokenCalls)
          : { status: 200, body: { access_token: mint(key), token_type: 'Bearer', expires_in: 3600 } };
        res.writeHead(result.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(result.body));
      });
      return;
    }
    if (path === '/oauth2/device_authorization') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c as Buffer));
      req.on('end', () => {
        gateway.deviceCalls++;
        gateway.lastDeviceBody = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            device_code: 'device-code-secret',
            user_code: 'ABCD-EFGH',
            verification_uri: `${gateway.origin}/activate`,
            verification_uri_complete: `${gateway.origin}/activate?code=ABCD-EFGH`,
            expires_in: 300,
            interval: 5,
          }),
        );
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const { port } = server.address() as AddressInfo;
  gateway.origin = `http://127.0.0.1:${port}`;
  return gateway;
}

async function buildFlows(
  db: FakeDatabase,
  gateway: Gateway,
  opts: { config?: OauthConfig; verify?: 'jwks' | 'introspect' } = {},
): Promise<Flows> {
  const configResult = loadOauthConfig({
    OAUTH_ISSUER: ISSUER,
    OAUTH_CLIENT_ID: 'relay',
    OAUTH_CLIENT_SECRET: 'secret',
    OAUTH_AUDIENCE: AUDIENCE,
    OAUTH_REDIRECT_URI: 'cloudterminal://oauth/callback',
    ...(opts.verify ? { OAUTH_VERIFY: opts.verify } : {}),
  });
  assert.equal(configResult.state, 'ready');
  if (configResult.state !== 'ready') throw new Error('config not ready');
  const config = opts.config ?? configResult.config;
  // Resolve discovery once, then hand the endpoints to the verifier.
  const discoveryResponse = await fetch(`${gateway.origin}/.well-known/openid-configuration`);
  const endpoints = parseDiscoveryDocument(await discoveryResponse.json());
  const verifier = createVerifier({ config, endpoints });
  return createFlows({
    db,
    config,
    verifier,
    endpoints,
    accessTtlMs: 3_600_000,
    refreshTtlMs: 2_592_000_000,
  });
}

describe('flow A (authorization code + PKCE)', () => {
  let gateway: Gateway;
  let key: Key;
  let db: FakeDatabase;

  before(async () => {
    key = makeKey('k1');
    gateway = await startGateway(key);
  });

  after(async () => {
    await gateway.stop();
  });

  it('resolves endpoints lazily through the verifier when none are passed', async () => {
    db = createFakeDatabase();
    const configResult = loadOauthConfig({
      OAUTH_ISSUER: ISSUER,
      OAUTH_CLIENT_ID: 'relay',
      OAUTH_CLIENT_SECRET: 'secret',
      OAUTH_AUDIENCE: AUDIENCE,
    });
    assert.equal(configResult.state, 'ready');
    if (configResult.state !== 'ready') return;
    const rewriteFetch = ((input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      return fetch(url.replace(ISSUER, gateway.origin), init);
    }) as typeof fetch;
    const verifier = createVerifier({ config: configResult.config, fetchFn: rewriteFetch });
    const flows = createFlows({
      db,
      config: configResult.config,
      verifier,
      // No `endpoints`: flows must fall back to `verifier.endpoints()`.
      accessTtlMs: 3_600_000,
      refreshTtlMs: 2_592_000_000,
      fetchFn: rewriteFetch,
    });
    const verifierCode = 'v'.repeat(43);
    const challenge = createHash('sha256').update(verifierCode).digest('base64url');
    const start = await flows.startFlowA({ codeChallenge: challenge });
    assert.equal(start.ok, true, start.ok ? '' : start.message);
    if (!start.ok) return;
    assert.match(start.authorizeUrl, /\/oauth2\/authorize/);
  });

  it('starts a login: stores state and returns a PKCE authorize URL', async () => {
    db = createFakeDatabase();
    const flows = await buildFlows(db, gateway);
    const verifier = 'verifier-'.repeat(10);
    const challenge = createHash('sha256').update(verifier).digest('base64url');

    const result = await flows.startFlowA({ codeChallenge: challenge });
    assert.equal(result.ok, true);
    if (!result.ok) return;
    const url = new URL(result.authorizeUrl);
    assert.equal(url.searchParams.get('response_type'), 'code');
    assert.equal(url.searchParams.get('client_id'), 'relay');
    assert.equal(url.searchParams.get('code_challenge'), challenge);
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('state'), result.state);
    // The pending state is persisted exactly once.
    assert.equal(db.states.size, 1);
    assert.equal([...db.states.values()][0]?.kind, 'pkce');
  });

  it('completes the flow: exchanges the code, caches the account and issues relay tokens', async () => {
    db = createFakeDatabase();
    const flows = await buildFlows(db, gateway);
    const verifier = 'v'.repeat(43);
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const start = await flows.startFlowA({ codeChallenge: challenge });
    assert.equal(start.ok, true);
    if (!start.ok) return;

    gateway.tokenCalls = 0;
    const complete = await flows.completeFlowA({ code: 'auth-code', state: start.state, codeVerifier: verifier });
    assert.equal(complete.ok, true);
    if (!complete.ok) return;
    assert.equal(gateway.tokenCalls, 1);
    assert.equal(complete.credentials.accountId, 'user-1');
    assert.match(complete.credentials.accessToken, /^ct_/);
    assert.match(complete.credentials.refreshToken, /^ct_/);
    assert.equal(db.accounts.has('user-1'), true);
    // The state row is consumed so a replay fails.
    assert.equal(db.states.size, 0);
  });

  it('rejects a replayed state (single use)', async () => {
    db = createFakeDatabase();
    const flows = await buildFlows(db, gateway);
    const verifier = 'v'.repeat(43);
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const start = await flows.startFlowA({ codeChallenge: challenge });
    if (!start.ok) throw new Error('start failed');
    await flows.completeFlowA({ code: 'c', state: start.state, codeVerifier: verifier });
    const replay = await flows.completeFlowA({ code: 'c', state: start.state, codeVerifier: verifier });
    assert.equal(replay.ok, false);
    if (!replay.ok) assert.equal(replay.code, 'unknown_state');
  });

  it('rejects a code_verifier that does not match the challenge', async () => {
    db = createFakeDatabase();
    const flows = await buildFlows(db, gateway);
    const challenge = createHash('sha256').update('right-verifier').digest('base64url');
    const start = await flows.startFlowA({ codeChallenge: challenge });
    if (!start.ok) throw new Error('start failed');
    const complete = await flows.completeFlowA({ code: 'c', state: start.state, codeVerifier: 'wrong-verifier' });
    assert.equal(complete.ok, false);
    if (!complete.ok) assert.equal(complete.code, 'invalid_request');
  });

  it('rejects an unknown state', async () => {
    db = createFakeDatabase();
    const flows = await buildFlows(db, gateway);
    const result = await flows.completeFlowA({ code: 'c', state: 'nope', codeVerifier: 'v' });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'unknown_state');
  });

  it('reports a gateway rejection as verification_failed (identity token rejected)', async () => {
    db = createFakeDatabase();
    const badKey = makeKey('k1');
    const badGateway = await startGateway(badKey, {
      // Token endpoint signs with a key the JWKS does not publish.
      tokenHandler: () => ({ status: 200, body: { access_token: mint(badKey, { aud: 'wrong-audience' }) } }),
    });
    try {
      const flows = await buildFlows(db, badGateway);
      const verifier = 'v'.repeat(43);
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      const start = await flows.startFlowA({ codeChallenge: challenge });
      if (!start.ok) throw new Error('start failed');
      const result = await flows.completeFlowA({ code: 'c', state: start.state, codeVerifier: verifier });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.code, 'verification_failed');
    } finally {
      await badGateway.stop();
    }
  });

  it('reports a 4xx from the token endpoint as gateway_rejected', async () => {
    db = createFakeDatabase();
    const rejecting = await startGateway(key, {
      tokenHandler: () => ({ status: 400, body: { error: 'invalid_grant' } }),
    });
    try {
      const flows = await buildFlows(db, rejecting);
      const verifier = 'v'.repeat(43);
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      const start = await flows.startFlowA({ codeChallenge: challenge });
      if (!start.ok) throw new Error('start failed');
      const result = await flows.completeFlowA({ code: 'c', state: start.state, codeVerifier: verifier });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.code, 'gateway_rejected');
    } finally {
      await rejecting.stop();
    }
  });
});

describe('flow B (device authorization, RFC 8628)', () => {
  let key: Key;

  before(() => {
    key = makeKey('k1');
  });

  it('reports device_flow_unsupported when discovery lacks the endpoint', async () => {
    const gateway = await startGateway(key, { deviceEndpoint: false });
    try {
      const db = createFakeDatabase();
      const flows = await buildFlows(db, gateway);
      const result = await flows.startDevice({ deviceId: 'device-1' });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.code, 'device_flow_unsupported');
      // Flow A still works when only the device endpoint is missing.
      const start = await flows.startFlowA({ codeChallenge: 'challenge' });
      assert.equal(start.ok, true);
    } finally {
      await gateway.stop();
    }
  });

  it('polls authorization_pending, then approves and binds the device', async () => {
    const gateway = await startGateway(key, {
      deviceEndpoint: true,
      tokenHandler: (_params, calls) =>
        calls < 2
          ? { status: 400, body: { error: 'authorization_pending' } }
          : { status: 200, body: { access_token: mint(key), token_type: 'Bearer' } },
    });
    try {
      const db = createFakeDatabase();
      // The computer registered itself before showing the code.
      db.devices.set('device-1', { secretHash: 'a'.repeat(64) });
      const flows = await buildFlows(db, gateway);

      const start = await flows.startDevice({ deviceId: 'device-1', label: 'desk' });
      assert.equal(start.ok, true);
      if (!start.ok) return;
      assert.equal(start.userCode, 'ABCD-EFGH');
      assert.match(start.verificationUri, /activate/);
      assert.equal(db.states.size, 1);

      const pending = await flows.pollDevice({ deviceId: 'device-1', userCode: start.userCode });
      assert.equal(pending.ok, false);
      if (!pending.ok) assert.equal(pending.code, 'authorization_pending');

      const approved = await flows.pollDevice({ deviceId: 'device-1', userCode: start.userCode });
      assert.equal(approved.ok, true);
      if (!approved.ok) return;
      assert.equal(approved.status, 'approved');
      assert.match(approved.credentials.accessToken, /^ct_/);
      assert.equal(db.bindings.has(`user-1\u0000device-1`), true);
      assert.equal(db.accounts.has('user-1'), true);
      // The pending state is cleaned up after approval.
      assert.equal(db.states.size, 0);
    } finally {
      await gateway.stop();
    }
  });

  it('surfaces slow_down without consuming the state', async () => {
    const gateway = await startGateway(key, {
      deviceEndpoint: true,
      tokenHandler: () => ({ status: 400, body: { error: 'slow_down' } }),
    });
    try {
      const db = createFakeDatabase();
      db.devices.set('device-1', { secretHash: 'a'.repeat(64) });
      const flows = await buildFlows(db, gateway);
      const start = await flows.startDevice({ deviceId: 'device-1' });
      if (!start.ok) throw new Error('start failed');
      const result = await flows.pollDevice({ deviceId: 'device-1', userCode: start.userCode });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.code, 'slow_down');
      assert.equal(db.states.size, 1, 'slow_down must not consume the pending state');
    } finally {
      await gateway.stop();
    }
  });

  it('surfaces expired_token and drops the state', async () => {
    const gateway = await startGateway(key, {
      deviceEndpoint: true,
      tokenHandler: () => ({ status: 400, body: { error: 'expired_token' } }),
    });
    try {
      const db = createFakeDatabase();
      db.devices.set('device-1', { secretHash: 'a'.repeat(64) });
      const flows = await buildFlows(db, gateway);
      const start = await flows.startDevice({ deviceId: 'device-1' });
      if (!start.ok) throw new Error('start failed');
      const result = await flows.pollDevice({ deviceId: 'device-1', userCode: start.userCode });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.code, 'expired_token');
      assert.equal(db.states.size, 0);
    } finally {
      await gateway.stop();
    }
  });

  it('surfaces access_denied', async () => {
    const gateway = await startGateway(key, {
      deviceEndpoint: true,
      tokenHandler: () => ({ status: 400, body: { error: 'access_denied' } }),
    });
    try {
      const db = createFakeDatabase();
      db.devices.set('device-1', { secretHash: 'a'.repeat(64) });
      const flows = await buildFlows(db, gateway);
      const start = await flows.startDevice({ deviceId: 'device-1' });
      if (!start.ok) throw new Error('start failed');
      const result = await flows.pollDevice({ deviceId: 'device-1', userCode: start.userCode });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.code, 'access_denied');
    } finally {
      await gateway.stop();
    }
  });

  it('refuses to bind a device that never registered', async () => {
    const gateway = await startGateway(key, {
      deviceEndpoint: true,
      tokenHandler: () => ({ status: 200, body: { access_token: mint(key) } }),
    });
    try {
      const db = createFakeDatabase();
      const flows = await buildFlows(db, gateway);
      const start = await flows.startDevice({ deviceId: 'ghost' });
      if (!start.ok) throw new Error('start failed');
      const result = await flows.pollDevice({ deviceId: 'ghost', userCode: start.userCode });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.code, 'device_unknown');
    } finally {
      await gateway.stop();
    }
  });

  it('registers a device when device/start supplies its secret hash', async () => {
    const gateway = await startGateway(key, {
      deviceEndpoint: true,
      tokenHandler: () => ({ status: 200, body: { access_token: mint(key) } }),
    });
    try {
      const db = createFakeDatabase();
      const flows = await buildFlows(db, gateway);
      const start = await flows.startDevice({ deviceId: 'fresh', secretHash: 'b'.repeat(64) });
      assert.equal(start.ok, true);
      assert.equal(db.devices.get('fresh')?.secretHash, 'b'.repeat(64));
      if (!start.ok) return;
      const result = await flows.pollDevice({ deviceId: 'fresh', userCode: start.userCode });
      assert.equal(result.ok, true);
      assert.equal(db.bindings.has('user-1\u0000fresh'), true);
    } finally {
      await gateway.stop();
    }
  });
});

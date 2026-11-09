// Step 6: the `/api/v1/` HTTP surface.
//
// The API is attached to a real relay HTTP server (the same one that serves
// `/ws` and `/healthz`). Accounts, bindings and tokens live in an in-memory
// fake matching the SQL shapes of `db/*`, so the suite runs without MySQL. A
// separate opt-in suite exercises the same routes against MySQL when
// `CT_TEST_MYSQL_URL` (or `DB_*`) is configured.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { RowDataPacket, ResultSetHeader } from 'mysql2/promise';
import { after, afterEach, before, describe, it } from 'node:test';

import type { DbPool } from '../src/db/pool.ts';
import { createBinding, isBound } from '../src/db/bindings.ts';
import { issueToken } from '../src/db/tokens.ts';
import { createRelay, type Relay } from '../src/relay/relay.ts';
import { createTenancy } from '../src/relay/tenancy.ts';
import { attachApi, type ApiDeps } from '../src/relay/api.ts';
import { loadOauthConfig } from '../src/oauth/config.ts';
import { sha256Hex } from '../src/shared/crypto.ts';
import { TestSocket } from './helpers.ts';
import {
  SKIP_MESSAGE,
  mysqlConfigured,
  openTestPool,
  seedAccountDevice,
  truncateAll,
} from './db-helpers.ts';

// --- in-memory database -----------------------------------------------------

type TokenRow = { accountId: string; deviceId: string | null; kind: string; expiresAt: Date; revoked: boolean };

type FakeDatabase = DbPool & {
  accounts: Map<string, { issuer: string; displayName: string | null }>;
  devices: Map<string, { label: string | null; platform: string | null }>;
  bindings: Map<string, { role: string; label: string | null; status: 'active' | 'revoked' }>;
  tokens: Map<string, TokenRow>;
  addToken(token: string, accountId: string, deviceId?: string | null, kind?: string): void;
  failNext: Error | null;
};

function createFakeDatabase(): FakeDatabase {
  const accounts = new Map<string, { issuer: string; displayName: string | null }>();
  const devices = new Map<string, { label: string | null; platform: string | null }>();
  const bindings = new Map<string, { role: string; label: string | null; status: 'active' | 'revoked' }>();
  const tokens = new Map<string, TokenRow>();

  const bindingKey = (accountId: string, deviceId: string) => `${accountId}\u0000${deviceId}`;

  const db: FakeDatabase = {
    state: 'ready',
    accounts,
    devices,
    bindings,
    tokens,
    failNext: null,
    addToken(token, accountId, deviceId = null, kind = 'access') {
      tokens.set(sha256Hex(token), { accountId, deviceId, kind, expiresAt: new Date(Date.now() + 3_600_000), revoked: false });
    },
    async query<Row extends RowDataPacket = RowDataPacket>(sql: string, values: readonly unknown[] = []): Promise<Row[]> {
      if (db.failNext) {
        const err = db.failNext;
        db.failNext = null;
        throw err;
      }
      const s = sql.replace(/\s+/g, ' ').toLowerCase();
      if (s.includes('from ct_tokens') && s.includes('token_hash = ?')) {
        const row = tokens.get(String(values[0]));
        if (!row || row.revoked || row.expiresAt.getTime() <= Date.now()) return [] as unknown as Row[];
        return [
          { account_id: row.accountId, device_id: row.deviceId, kind: row.kind, expires_at: row.expiresAt },
        ] as unknown as Row[];
      }
      if (s.includes('from ct_bindings') && s.includes('select 1 as present')) {
        const [accountId, deviceId] = values as [string, string];
        const row = bindings.get(bindingKey(accountId, deviceId));
        return (row && row.status === 'active' ? [{ present: 1 }] : []) as unknown as Row[];
      }
      if (s.includes('from ct_bindings b') && s.includes('join ct_devices d')) {
        const accountId = String(values[0]);
        const rows: Row[] = [];
        for (const [key, binding] of bindings) {
          const [acct, deviceId] = key.split('\u0000') as [string, string];
          if (acct !== accountId || binding.status !== 'active') continue;
          const device = devices.get(deviceId);
          rows.push({
            device_id: deviceId,
            label: device?.label ?? null,
            platform: device?.platform ?? null,
            role: binding.role,
            device_revoked: 0,
          } as unknown as Row);
        }
        return rows;
      }
      if (s.includes('from ct_bindings b') && s.includes('join ct_accounts a')) {
        const deviceId = String(values[0]);
        const rows: Row[] = [];
        for (const [key, binding] of bindings) {
          const [acct, dev] = key.split('\u0000') as [string, string];
          if (dev !== deviceId || binding.status !== 'active') continue;
          rows.push({
            account_id: acct,
            display_name: accounts.get(acct)?.displayName ?? null,
            role: binding.role,
            label: binding.label,
          } as unknown as Row);
        }
        return rows;
      }
      if (s.includes('from ct_accounts where account_id = ?')) {
        const account = accounts.get(String(values[0]));
        return (account
          ? [
              {
                account_id: String(values[0]),
                issuer: account.issuer,
                display_name: account.displayName,
                created_at: new Date(),
                updated_at: new Date(),
              },
            ]
          : []) as unknown as Row[];
      }
      return [] as unknown as Row[];
    },
    async execute(sql: string, values: readonly unknown[] = []): Promise<ResultSetHeader> {
      if (db.failNext) {
        const err = db.failNext;
        db.failNext = null;
        throw err;
      }
      const s = sql.replace(/\s+/g, ' ').toLowerCase();
      if (s.startsWith('insert into ct_bindings')) {
        const [accountId, deviceId, role, label] = values as [string, string, string, string | null];
        bindings.set(bindingKey(accountId, deviceId), { role, label, status: 'active' });
        return { affectedRows: 1 } as ResultSetHeader;
      }
      if (s.startsWith('update ct_bindings set status')) {
        const [accountId, deviceId] = values as [string, string];
        const row = bindings.get(bindingKey(accountId, deviceId));
        if (!row || row.status !== 'active') return { affectedRows: 0 } as ResultSetHeader;
        row.status = 'revoked';
        return { affectedRows: 1 } as ResultSetHeader;
      }
      if (s.startsWith('insert into ct_tokens')) {
        const [hash, accountId, deviceId, kind, expiresMs] = values as [string, string, string | null, string, number];
        tokens.set(hash, {
          accountId,
          deviceId,
          kind,
          expiresAt: new Date(Number(expiresMs)),
          revoked: false,
        });
        return { affectedRows: 1 } as ResultSetHeader;
      }
      if (s.startsWith('update ct_tokens set revoked_at')) {
        const row = tokens.get(String(values[0]));
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

// --- harness ----------------------------------------------------------------

type Harness = {
  relay: Relay;
  server: import('node:http').Server;
  origin: string;
  wsUrl: string;
  db: FakeDatabase;
  revoked: Array<{ accountId: string; deviceId: string }>;
  close(): Promise<void>;
};

async function startHarness(
  setup: (db: FakeDatabase) => void,
  depsOverrides: Partial<ApiDeps> = {},
): Promise<Harness> {
  const db = createFakeDatabase();
  setup(db);
  // The relay takes an injected account layer; `relay/main.ts` wires the same
  // tenancy around the real pool.
  const relay = createRelay({ accounts: createTenancy({ pool: db }), logger: undefined });
  const server = await relay.listen(0, '127.0.0.1');
  const { port } = server.address() as AddressInfo;
  const revoked: Array<{ accountId: string; deviceId: string }> = [];
  const configResult = loadOauthConfig({ OAUTH_ISSUER: 'https://sso.test', OAUTH_CLIENT_ID: 'relay' });
  assert.equal(configResult.state, 'ready');
  const deps: ApiDeps = {
    db,
    config: configResult.state === 'ready' ? configResult.config : null,
    oauthState: 'disabled',
    oauthMessage: 'no OAUTH_* settings configured; account login is off',
    verifier: null,
    flows: null,
    accessTtlMs: 3_600_000,
    refreshTtlMs: 2_592_000_000,
    onBindingRevoked: (accountId, deviceId) => revoked.push({ accountId, deviceId }),
    ...depsOverrides,
  };
  const api = attachApi(server, deps);
  return {
    relay,
    server,
    origin: `http://127.0.0.1:${port}`,
    wsUrl: `ws://127.0.0.1:${port}/ws`,
    db,
    revoked,
    async close() {
      api.detach();
      await relay.close();
    },
  };
}

type ApiResponse = { status: number; body: any; raw: string };

async function api(
  origin: string,
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<ApiResponse> {
  const base = new URL(origin);
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { hostname: base.hostname, port: base.port, method, path, headers: {
        ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed: unknown = raw;
          try {
            parsed = JSON.parse(raw);
          } catch {
            /* non-JSON (e.g. /healthz) */
          }
          resolve({ status: res.statusCode ?? 0, body: parsed, raw });
        });
      },
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const ACCT_A = 'acct-a';
const ACCT_B = 'acct-b';
const TOKEN_A = 'ct_token_a';
const TOKEN_B = 'ct_token_b';
const DEVICE_1 = 'device-1';
const DEVICE_2 = 'device-2';

function seedIsolation(db: FakeDatabase): void {
  db.accounts.set(ACCT_A, { issuer: 'https://sso.test', displayName: 'Alice' });
  db.accounts.set(ACCT_B, { issuer: 'https://sso.test', displayName: 'Bob' });
  db.devices.set(DEVICE_1, { label: 'desk', platform: 'linux' });
  db.devices.set(DEVICE_2, { label: 'laptop', platform: 'darwin' });
  db.addToken(TOKEN_A, ACCT_A);
  db.addToken(TOKEN_B, ACCT_B);
  // Account A: device-1 + device-2. Account B: device-1 only.
  db.bindings.set(`${ACCT_A}\u0000${DEVICE_1}`, { role: 'owner', label: null, status: 'active' });
  db.bindings.set(`${ACCT_A}\u0000${DEVICE_2}`, { role: 'owner', label: null, status: 'active' });
  db.bindings.set(`${ACCT_B}\u0000${DEVICE_1}`, { role: 'member', label: null, status: 'active' });
}

describe('api: auth requirements and legacy paths', () => {
  let h: Harness;
  before(async () => {
    h = await startHarness(seedIsolation);
  });
  after(async () => {
    await h.close();
  });

  it('rejects an unauthenticated device listing', async () => {
    const res = await api(h.origin, 'GET', '/api/v1/devices');
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'unauthorized');
  });

  it('rejects a bogus bearer token', async () => {
    const res = await api(h.origin, 'GET', '/api/v1/devices', undefined, 'ct_nope');
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'unauthorized');
  });

  it('serves JSON errors with a machine-readable code for unknown routes', async () => {
    const res = await api(h.origin, 'GET', '/api/v1/nope', undefined, TOKEN_A);
    assert.equal(res.status, 404);
    assert.equal(res.body.error.code, 'not_found');
  });

  it('keeps /healthz cheap and working', async () => {
    const res = await api(h.origin, 'GET', '/healthz');
    assert.equal(res.status, 200);
    assert.equal(res.raw.trim(), 'ok');
  });

  it('reports readiness including the OAuth state', async () => {
    const res = await api(h.origin, 'GET', '/readyz');
    assert.equal(res.status, 200);
    assert.equal(res.body.db.configured, true);
    assert.equal(res.body.oauth.state, 'disabled');
  });

  it('still upgrades /ws after the API is attached', async () => {
    const ws = await TestSocket.open(h.wsUrl);
    ws.send({ t: 'hello', role: 'client', agentId: DEVICE_1, relayToken: TOKEN_A });
    // No agent registered yet, so the account path reports the device offline;
    // the important part is that the upgrade happened and frames flow.
    const frame = await ws.next((f) => f.t === 'error' || f.t === 'hello_ok');
    assert.ok(frame.t === 'error' || frame.t === 'hello_ok');
    ws.close();
  });
});

describe('api: device listing isolation (AC1)', () => {
  let h: Harness;
  before(async () => {
    h = await startHarness(seedIsolation);
  });
  after(async () => {
    await h.close();
  });

  it('lists only the calling account\'s devices', async () => {
    const a = await api(h.origin, 'GET', '/api/v1/devices', undefined, TOKEN_A);
    assert.equal(a.status, 200);
    assert.deepEqual(
      (a.body.devices as Array<{ device_id: string }>).map((d) => d.device_id).sort(),
      [DEVICE_1, DEVICE_2],
    );

    const b = await api(h.origin, 'GET', '/api/v1/devices', undefined, TOKEN_B);
    assert.equal(b.status, 200);
    assert.deepEqual(
      (b.body.devices as Array<{ device_id: string }>).map((d) => d.device_id),
      [DEVICE_1],
    );
    assert.equal(a.body.account_id, ACCT_A);
    assert.equal(b.body.account_id, ACCT_B);
  });

  it('forbids listing the accounts of an unbound device', async () => {
    // B is not bound to device-2, so it must not see device-2's accounts.
    const res = await api(h.origin, 'GET', `/api/v1/devices/${DEVICE_2}/accounts`, undefined, TOKEN_B);
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'forbidden');
  });

  it('lets a bound account list the accounts of a shared device', async () => {
    const res = await api(h.origin, 'GET', `/api/v1/devices/${DEVICE_1}/accounts`, undefined, TOKEN_A);
    assert.equal(res.status, 200);
    assert.deepEqual(
      (res.body.accounts as Array<{ account_id: string }>).map((a) => a.account_id).sort(),
      [ACCT_A, ACCT_B],
    );
  });
});

describe('api: binding creation and revoke isolation (AC4)', () => {
  it('creates a binding only with a valid pair_code consent', async () => {
    const h = await startHarness(seedIsolation, {
      resolvePairCode: async (code) => (code === 'GOODCODE' ? DEVICE_2 : null),
    });
    try {
      const bad = await api(h.origin, 'POST', `/api/v1/devices/${DEVICE_2}/bindings`, { pair_code: 'WRONG' }, TOKEN_B);
      assert.equal(bad.status, 404);
      assert.equal(bad.body.error.code, 'pair_code_invalid');

      const ok = await api(h.origin, 'POST', `/api/v1/devices/${DEVICE_2}/bindings`, { pair_code: 'GOODCODE' }, TOKEN_B);
      assert.equal(ok.status, 201);
      assert.equal(h.db.bindings.get(`${ACCT_B}\u0000${DEVICE_2}`)?.status, 'active');
    } finally {
      await h.close();
    }
  });

  it('reports pair_code_unavailable when no resolver is wired', async () => {
    const h = await startHarness(seedIsolation);
    try {
      const res = await api(h.origin, 'POST', `/api/v1/devices/${DEVICE_2}/bindings`, { pair_code: 'X' }, TOKEN_B);
      assert.equal(res.status, 503);
      assert.equal(res.body.error.code, 'pair_code_unavailable');
    } finally {
      await h.close();
    }
  });

  it('revoking one binding leaves the other account on the device working', async () => {
    const h = await startHarness(seedIsolation);
    try {
      // A revokes its own binding to device-1.
      const res = await api(h.origin, 'DELETE', `/api/v1/devices/${DEVICE_1}/bindings/${ACCT_A}`, undefined, TOKEN_A);
      assert.equal(res.status, 200);
      assert.equal(h.db.bindings.get(`${ACCT_A}\u0000${DEVICE_1}`)?.status, 'revoked');
      assert.deepEqual(h.revoked, [{ accountId: ACCT_A, deviceId: DEVICE_1 }]);

      // B's binding on the same device is untouched.
      const bDevices = await api(h.origin, 'GET', '/api/v1/devices', undefined, TOKEN_B);
      assert.deepEqual(
        (bDevices.body.devices as Array<{ device_id: string }>).map((d) => d.device_id),
        [DEVICE_1],
      );

      // The revoked account no longer lists device-1.
      const aDevices = await api(h.origin, 'GET', '/api/v1/devices', undefined, TOKEN_A);
      assert.deepEqual(
        (aDevices.body.devices as Array<{ device_id: string }>).map((d) => d.device_id),
        [DEVICE_2],
      );
    } finally {
      await h.close();
    }
  });

  it('forbids revoking another account\'s binding without ownership', async () => {
    const h = await startHarness(seedIsolation);
    try {
      // B is a member, not an owner, of device-1; revoking A is forbidden.
      const res = await api(h.origin, 'DELETE', `/api/v1/devices/${DEVICE_1}/bindings/${ACCT_A}`, undefined, TOKEN_B);
      assert.equal(res.status, 403);
      assert.equal(h.db.bindings.get(`${ACCT_A}\u0000${DEVICE_1}`)?.status, 'active');
    } finally {
      await h.close();
    }
  });
});

describe('api: degraded and unavailable states', () => {
  it('returns 503 with an actionable body when account login is degraded', async () => {
    const h = await startHarness(seedIsolation, {
      config: null,
      oauthState: 'degraded',
      oauthMessage: 'incomplete OAUTH_* settings; missing OAUTH_CLIENT_ID',
      flows: null,
    });
    try {
      const res = await api(h.origin, 'POST', '/api/v1/auth/oauth/start', { code_challenge: 'x' });
      assert.equal(res.status, 503);
      assert.equal(res.body.error.code, 'auth_unavailable');
      assert.match(res.body.error.message, /OAUTH_CLIENT_ID/);
    } finally {
      await h.close();
    }
  });

  it('reports not-ready on /readyz when a configured layer is broken', async () => {
    const h = await startHarness(seedIsolation, {
      config: null,
      oauthState: 'degraded',
      oauthMessage: 'incomplete OAUTH_* settings',
    });
    try {
      const res = await api(h.origin, 'GET', '/readyz');
      assert.equal(res.status, 503);
      assert.equal(res.body.ok, false);
      assert.equal(res.body.oauth.state, 'degraded');
    } finally {
      await h.close();
    }
  });

  it('returns 503 when the database throws', async () => {
    const h = await startHarness((db) => {
      seedIsolation(db);
      db.failNext = new Error('connect ECONNREFUSED');
    });
    try {
      const res = await api(h.origin, 'GET', '/api/v1/devices', undefined, TOKEN_A);
      assert.equal(res.status, 503);
      assert.equal(res.body.error.code, 'db_unavailable');
    } finally {
      await h.close();
    }
  });

  it('does not require account login for logout itself', async () => {
    const h = await startHarness(seedIsolation, { config: null, oauthState: 'degraded', flows: null });
    try {
      const res = await api(h.origin, 'POST', '/api/v1/auth/logout', {}, TOKEN_A);
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);
    } finally {
      await h.close();
    }
  });
});

describe('api: refresh and logout rotate credentials', () => {
  it('refreshes a refresh token into a new pair and invalidates the old one', async () => {
    const h = await startHarness((db) => {
      seedIsolation(db);
      db.addToken('ct_refresh_a', ACCT_A, null, 'refresh');
    });
    try {
      const res = await api(h.origin, 'POST', '/api/v1/auth/token/refresh', { refresh_token: 'ct_refresh_a' });
      assert.equal(res.status, 200);
      assert.match(res.body.access_token, /^ct_/);
      assert.match(res.body.refresh_token, /^ct_/);
      // The old refresh token cannot be used twice.
      const again = await api(h.origin, 'POST', '/api/v1/auth/token/refresh', { refresh_token: 'ct_refresh_a' });
      assert.equal(again.status, 401);
      assert.equal(again.body.error.code, 'invalid_grant');
    } finally {
      await h.close();
    }
  });

  it('logs out by revoking the presented access token', async () => {
    const h = await startHarness(seedIsolation);
    try {
      const before = await api(h.origin, 'GET', '/api/v1/devices', undefined, TOKEN_A);
      assert.equal(before.status, 200);
      const out = await api(h.origin, 'POST', '/api/v1/auth/logout', {}, TOKEN_A);
      assert.equal(out.status, 200);
      assert.equal(h.db.tokens.get(sha256Hex(TOKEN_A))?.revoked, true);
      const after = await api(h.origin, 'GET', '/api/v1/devices', undefined, TOKEN_A);
      assert.equal(after.status, 401);
    } finally {
      await h.close();
    }
  });
});

describe('api: device flow unsupported', () => {
  it('returns 501 when the gateway does not advertise device authorization', async () => {
    const h = await startHarness(seedIsolation, {
      oauthState: 'ready',
      // A flows stub that reports the unsupported endpoint, mirroring the
      // real `flows.startDevice` behavior when discovery lacks the endpoint.
      flows: {
        available: true,
        async startFlowA() {
          return { ok: false, code: 'invalid_request' as const, message: 'unused' };
        },
        async completeFlowA() {
          return { ok: false, code: 'invalid_request' as const, message: 'unused' };
        },
        async startDevice() {
          return { ok: false, code: 'device_flow_unsupported' as const, message: 'gateway has no device endpoint' };
        },
        async pollDevice() {
          return { ok: false, code: 'device_flow_unsupported' as const, message: 'unused' };
        },
        async purgeExpiredStates() {
          return 0;
        },
      },
    });
    try {
      const res = await api(h.origin, 'POST', '/api/v1/auth/device/start', { device_id: DEVICE_1 });
      assert.equal(res.status, 501);
      assert.equal(res.body.error.code, 'device_flow_unsupported');
    } finally {
      await h.close();
    }
  });

  it('reports authorization_pending as a 202 poll result', async () => {
    const h = await startHarness(seedIsolation, {
      oauthState: 'ready',
      flows: {
        available: true,
        async startFlowA() {
          return { ok: false, code: 'invalid_request' as const, message: 'unused' };
        },
        async completeFlowA() {
          return { ok: false, code: 'invalid_request' as const, message: 'unused' };
        },
        async startDevice() {
          return { ok: false, code: 'invalid_request' as const, message: 'unused' };
        },
        async pollDevice() {
          return { ok: false, code: 'authorization_pending' as const, message: 'waiting' };
        },
        async purgeExpiredStates() {
          return 0;
        },
      },
    });
    try {
      const res = await api(h.origin, 'POST', '/api/v1/auth/device/poll', { device_id: DEVICE_1, user_code: 'ABCD' });
      assert.equal(res.status, 202);
      assert.equal(res.body.status, 'authorization_pending');
    } finally {
      await h.close();
    }
  });
});

// Sanity: the fake database itself must not diverge from the real one on the
// columns the API reads (guards against a silent test-only shape).
describe('api: fake database shape', () => {
  it('stores only hashed tokens', () => {
    const db = createFakeDatabase();
    db.addToken('plaintext-token', ACCT_A);
    assert.equal(db.tokens.has('plaintext-token'), false);
    assert.equal(db.tokens.has(sha256Hex('plaintext-token')), true);
  });
});

// Opt-in MySQL-backed suite: exercises the same routes against the real data
// layer so the fake's SQL assumptions cannot hide a regression. Skips cleanly
// without a configured database, exactly like the `db-*.test.ts` suites.
describe('api over MySQL (AC1/AC4)', { skip: mysqlConfigured() ? false : SKIP_MESSAGE }, () => {
  let pool: DbPool;
  let relay: Relay;
  let server: import('node:http').Server;
  let origin: string;
  const revoked: Array<{ accountId: string; deviceId: string }> = [];

  before(async () => {
    const opened = await openTestPool();
    assert.ok(opened, SKIP_MESSAGE);
    pool = opened;
  });

  after(async () => {
    await pool.close();
  });

  async function startMysqlHarness(): Promise<void> {
    await truncateAll(pool);
    await seedAccountDevice(pool, ACCT_A, DEVICE_1);
    await seedAccountDevice(pool, ACCT_B, DEVICE_1);
    await seedAccountDevice(pool, ACCT_A, DEVICE_2);
    await createBinding(pool, { accountId: ACCT_A, deviceId: DEVICE_1, role: 'owner', createdBy: 'admin' });
    await createBinding(pool, { accountId: ACCT_B, deviceId: DEVICE_1, role: 'member', createdBy: 'admin' });
    await createBinding(pool, { accountId: ACCT_A, deviceId: DEVICE_2, role: 'owner', createdBy: 'admin' });
    await issueToken(pool, { accountId: ACCT_A, kind: 'access', ttlMs: 3_600_000 });
    relay = createRelay({ accounts: createTenancy({ pool }) });
    server = await relay.listen(0, '127.0.0.1');
    const { port } = server.address() as AddressInfo;
    origin = `http://127.0.0.1:${port}`;
    const configResult = loadOauthConfig({ OAUTH_ISSUER: 'https://sso.test', OAUTH_CLIENT_ID: 'relay' });
    attachApi(server, {
      db: pool,
      config: configResult.state === 'ready' ? configResult.config : null,
      oauthState: 'disabled',
      oauthMessage: '',
      verifier: null,
      flows: null,
      accessTtlMs: 3_600_000,
      refreshTtlMs: 2_592_000_000,
      onBindingRevoked: (accountId, deviceId) => revoked.push({ accountId, deviceId }),
    });
  }

  async function tokenFor(accountId: string): Promise<string> {
    const issued = await issueToken(pool, { accountId, kind: 'access', ttlMs: 3_600_000 });
    return issued.token;
  }

  afterEach(async () => {
    revoked.length = 0;
    if (relay) await relay.close();
  });

  it('isolates the device list between two accounts', async () => {
    await startMysqlHarness();
    const tokenA = await tokenFor(ACCT_A);
    const tokenB = await tokenFor(ACCT_B);
    const a = await api(origin, 'GET', '/api/v1/devices', undefined, tokenA);
    const b = await api(origin, 'GET', '/api/v1/devices', undefined, tokenB);
    assert.deepEqual(
      (a.body.devices as Array<{ device_id: string }>).map((d) => d.device_id).sort(),
      [DEVICE_1, DEVICE_2],
    );
    assert.deepEqual((b.body.devices as Array<{ device_id: string }>).map((d) => d.device_id), [DEVICE_1]);
  });

  it('revokes one binding without touching the other account (AC4)', async () => {
    await startMysqlHarness();
    const tokenA = await tokenFor(ACCT_A);
    const tokenB = await tokenFor(ACCT_B);
    const res = await api(origin, 'DELETE', `/api/v1/devices/${DEVICE_1}/bindings/${ACCT_A}`, undefined, tokenA);
    assert.equal(res.status, 200);
    assert.equal(await isBound(pool, ACCT_A, DEVICE_1), false);
    assert.equal(await isBound(pool, ACCT_B, DEVICE_1), true, 'AC4: the other binding survives');
    const b = await api(origin, 'GET', '/api/v1/devices', undefined, tokenB);
    assert.deepEqual((b.body.devices as Array<{ device_id: string }>).map((d) => d.device_id), [DEVICE_1]);
  });
});

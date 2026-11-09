// Step 5: token verification (JWKS and introspection).
//
// A local `node:http` stub stands in for the gateway. Keys and tokens are
// generated in-process with `node:crypto`; no real network or gateway is used.

import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as rsaSign, type KeyObject } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';

import { createJwksVerifier } from '../src/oauth/jwks.ts';
import { createIntrospector } from '../src/oauth/introspect.ts';
import { createVerifier } from '../src/oauth/verify.ts';
import { loadOauthConfig, type OauthConfig } from '../src/oauth/config.ts';
import type { OidcEndpoints } from '../src/oauth/discovery.ts';

const ISSUER = 'https://sso.test';
const AUDIENCE = 'cloudterminal-relay';

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

type Claims = Record<string, unknown>;

function mint(key: Key, claims: Claims, header: Record<string, unknown> = {}): string {
  const h = b64({ alg: 'RS256', typ: 'JWT', kid: key.kid, ...header });
  const p = b64(claims);
  const signature = rsaSign('RSA-SHA256', Buffer.from(`${h}.${p}`), key.privateKey).toString('base64url');
  return `${h}.${p}.${signature}`;
}

function claimsFor(overrides: Claims = {}): Claims {
  const now = Math.floor(Date.now() / 1000);
  return { sub: 'user-1', iss: ISSUER, aud: AUDIENCE, exp: now + 600, iat: now, name: 'Ada', ...overrides };
}

type GatewayStub = {
  origin: string;
  keys: Key[];
  introspect: (token: string) => Record<string, unknown>;
  introspectRequests: number;
  stop(): Promise<void>;
};

async function startGateway(keys: Key[]): Promise<GatewayStub> {
  const gateway: GatewayStub = {
    origin: '',
    keys,
    introspect: () => ({ active: false }),
    introspectRequests: 0,
    async stop() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
  const server: Server = createServer((req, res) => {
    if (req.url?.startsWith('/.well-known/jwks.json')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ keys: gateway.keys.map((k) => k.publicJwk) }));
      return;
    }
    if (req.url?.startsWith('/oauth2/introspect')) {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c as Buffer));
      req.on('end', () => {
        gateway.introspectRequests++;
        const params = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
        const token = params.get('token') ?? '';
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(gateway.introspect(token)));
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

function endpointsFor(origin: string): OidcEndpoints {
  return {
    issuer: ISSUER,
    authorizationEndpoint: `${origin}/oauth2/authorize`,
    tokenEndpoint: `${origin}/oauth2/token`,
    jwksUri: `${origin}/.well-known/jwks.json`,
    introspectionEndpoint: `${origin}/oauth2/introspect`,
    deviceAuthorizationEndpoint: null,
  };
}

function config(overrides: Partial<NodeJS.ProcessEnv> = {}): OauthConfig {
  const result = loadOauthConfig({
    OAUTH_ISSUER: ISSUER,
    OAUTH_CLIENT_ID: 'relay',
    OAUTH_CLIENT_SECRET: 'secret',
    OAUTH_AUDIENCE: AUDIENCE,
    ...overrides,
  });
  assert.equal(result.state, 'ready');
  if (result.state !== 'ready') throw new Error('config not ready');
  return result.config;
}

describe('jwks verification', () => {
  let gateway: GatewayStub;
  let key: Key;

  before(async () => {
    key = makeKey('k1');
    gateway = await startGateway([key]);
  });

  after(async () => {
    await gateway.stop();
  });

  function verifier() {
    return createJwksVerifier({ endpoints: endpointsFor(gateway.origin), audience: AUDIENCE, issuer: ISSUER, ttlMs: 60_000 });
  }

  it('accepts a valid RS256 token and normalises the claims', async () => {
    const result = await verifier().verify(mint(key, claimsFor()));
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.claims.sub, 'user-1');
      assert.equal(result.claims.iss, ISSUER);
      assert.equal(result.claims.name, 'Ada');
    }
  });

  it('rejects an expired token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifier().verify(mint(key, claimsFor({ exp: now - 3600 })));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'expired');
  });

  it('rejects a token that is not valid yet', async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifier().verify(mint(key, claimsFor({ nbf: now + 3600 })));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'not_yet_valid');
  });

  it('rejects a wrong issuer', async () => {
    const result = await verifier().verify(mint(key, claimsFor({ iss: 'https://evil.test' })));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'wrong_issuer');
  });

  it('rejects a wrong audience', async () => {
    const result = await verifier().verify(mint(key, claimsFor({ aud: 'some-other-api' })));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'wrong_audience');
  });

  it('rejects an unknown kid', async () => {
    const result = await verifier().verify(mint(key, claimsFor(), { kid: 'ghost' }));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'unknown_key');
  });

  it('rejects a tampered signature', async () => {
    const token = mint(key, claimsFor());
    const parts = token.split('.');
    const forged = `${parts[0]}.${b64(claimsFor({ sub: 'attacker' }))}.${parts[2]}`;
    const result = await verifier().verify(forged);
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'bad_signature');
  });

  it('rejects a malformed token without throwing', async () => {
    const result = await verifier().verify('not-a-jwt');
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'malformed_token');
  });
});

describe('introspection verification', () => {
  let gateway: GatewayStub;

  before(async () => {
    gateway = await startGateway([]);
  });

  after(async () => {
    await gateway.stop();
  });

  function introspector(cacheMs = 0) {
    return createIntrospector({
      endpoints: endpointsFor(gateway.origin),
      clientId: 'relay',
      clientSecret: 'secret',
      audience: AUDIENCE,
      issuer: ISSUER,
      cacheMs,
    });
  }

  it('accepts an active token', async () => {
    gateway.introspect = () => ({ active: true, sub: 'user-1', iss: ISSUER, aud: AUDIENCE, name: 'Ada' });
    const result = await introspector().introspect('opaque-token');
    assert.equal(result.ok, true);
    if (result.ok) assert.equal(result.claims.sub, 'user-1');
  });

  it('rejects active:false', async () => {
    gateway.introspect = () => ({ active: false });
    const result = await introspector().introspect('revoked');
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'inactive');
  });

  it('rejects a wrong issuer or audience in the introspection response', async () => {
    gateway.introspect = () => ({ active: true, sub: 'u', iss: 'https://evil.test', aud: AUDIENCE });
    const wrongIss = await introspector().introspect('t1');
    assert.equal(wrongIss.ok, false);
    if (!wrongIss.ok) assert.equal(wrongIss.code, 'wrong_issuer');

    gateway.introspect = () => ({ active: true, sub: 'u', iss: ISSUER, aud: 'other' });
    const wrongAud = await introspector().introspect('t2');
    assert.equal(wrongAud.ok, false);
    if (!wrongAud.ok) assert.equal(wrongAud.code, 'wrong_audience');
  });

  it('caches an active result and does not refetch within the TTL', async () => {
    gateway.introspect = () => ({ active: true, sub: 'user-1', iss: ISSUER, aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 600 });
    const instance = introspector(60_000);
    gateway.introspectRequests = 0;
    await instance.introspect('cached-token');
    await instance.introspect('cached-token');
    assert.equal(gateway.introspectRequests, 1);
    assert.equal(instance.stats().hits, 1);
  });
});

describe('verifier strategy selection', () => {
  let gateway: GatewayStub;
  let key: Key;

  before(async () => {
    key = makeKey('k1');
    gateway = await startGateway([key]);
  });

  after(async () => {
    await gateway.stop();
  });

  it('verifies through JWKS when OAUTH_VERIFY=jwks', async () => {
    const verifier = createVerifier({
      config: config({ OAUTH_VERIFY: 'jwks' }),
      endpoints: endpointsFor(gateway.origin),
    });
    assert.equal(verifier.strategy, 'jwks');
    const result = await verifier.verify(mint(key, claimsFor()));
    assert.equal(result.ok, true);
    if (result.ok) assert.deepEqual(result.identity, { sub: 'user-1', issuer: ISSUER, name: 'Ada' });
  });

  it('maps a JWKS failure to a typed verify failure', async () => {
    const verifier = createVerifier({
      config: config({ OAUTH_VERIFY: 'jwks' }),
      endpoints: endpointsFor(gateway.origin),
    });
    const result = await verifier.verify(mint(key, claimsFor({ aud: 'nope' })));
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.code, 'wrong_audience');
      assert.equal(result.detail, 'wrong_audience');
    }
  });

  it('verifies through introspection when OAUTH_VERIFY=introspect', async () => {
    gateway.introspect = () => ({ active: true, sub: 'user-9', iss: ISSUER, aud: AUDIENCE });
    const verifier = createVerifier({
      config: config({ OAUTH_VERIFY: 'introspect' }),
      endpoints: endpointsFor(gateway.origin),
    });
    assert.equal(verifier.strategy, 'introspect');
    const result = await verifier.verify('opaque');
    assert.equal(result.ok, true);
    if (result.ok) assert.equal(result.identity.sub, 'user-9');
  });

  it('reports misconfiguration when introspection has no client secret', async () => {
    const verifier = createVerifier({
      config: config({ OAUTH_VERIFY: 'introspect', OAUTH_CLIENT_SECRET: '' }),
      endpoints: endpointsFor(gateway.origin),
    });
    const result = await verifier.verify('opaque');
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.code, 'misconfigured');
      assert.equal(result.detail, 'missing_client_secret');
    }
  });

  it('returns a typed failure when discovery is unavailable', async () => {
    const verifier = createVerifier({
      config: config(),
      fetchFn: (async () => {
        throw new Error('connect ECONNREFUSED');
      }) as unknown as typeof fetch,
    });
    const result = await verifier.verify('anything');
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'unavailable');
  });
});

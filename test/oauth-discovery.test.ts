// Step 5: OIDC discovery caching and tolerance.
//
// The gateway is a local `node:http` stub started inside this file. There is no
// real network dependency.

import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';

import { createDiscovery, parseDiscoveryDocument } from '../src/oauth/discovery.ts';

type Stub = {
  server: Server;
  origin: string;
  requests: number;
  document: Record<string, unknown>;
  status: number;
  stop(): Promise<void>;
};

async function startStub(document: Record<string, unknown>, status = 200): Promise<Stub> {
  const stub: Stub = {
    server: createServer((req, res) => {
      stub.requests++;
      if (req.url?.startsWith('/.well-known/openid-configuration')) {
        res.writeHead(stub.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(stub.document));
        return;
      }
      res.writeHead(404).end();
    }),
    origin: '',
    requests: 0,
    document,
    status,
    async stop() {
      await new Promise<void>((resolve) => stub.server.close(() => resolve()));
    },
  };
  await new Promise<void>((resolve) => stub.server.listen(0, '127.0.0.1', () => resolve()));
  const { port } = stub.server.address() as AddressInfo;
  stub.origin = `http://127.0.0.1:${port}`;
  return stub;
}

function documentFor(origin: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth2/authorize`,
    token_endpoint: `${origin}/oauth2/token`,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    introspection_endpoint: `${origin}/oauth2/introspect`,
    ...extra,
  };
}

describe('parseDiscoveryDocument', () => {
  it('maps the fields the relay needs', () => {
    const endpoints = parseDiscoveryDocument({
      issuer: 'https://sso.test/',
      authorization_endpoint: 'https://sso.test/oauth2/authorize',
      token_endpoint: 'https://sso.test/oauth2/token',
      jwks_uri: 'https://sso.test/.well-known/jwks.json',
      introspection_endpoint: 'https://sso.test/oauth2/introspect',
    });
    assert.equal(endpoints.issuer, 'https://sso.test');
    assert.equal(endpoints.tokenEndpoint, 'https://sso.test/oauth2/token');
    // Optional endpoint absent: flow B must report unsupported, not crash.
    assert.equal(endpoints.deviceAuthorizationEndpoint, null);
  });

  it('rejects a document without a jwks_uri', () => {
    assert.throws(
      () =>
        parseDiscoveryDocument({
          issuer: 'https://sso.test',
          authorization_endpoint: 'https://sso.test/authorize',
          token_endpoint: 'https://sso.test/token',
        }),
      /jwks_uri/,
    );
  });

  it('rejects a non-object document', () => {
    assert.throws(() => parseDiscoveryDocument('nope'), /not an object/);
  });
});

describe('createDiscovery', () => {
  let stub: Stub;

  before(async () => {
    stub = await startStub(documentFor('PLACEHOLDER'));
  });

  after(async () => {
    await stub.stop();
  });

  it('fetches once and serves the cache afterwards', async () => {
    stub.document = documentFor(stub.origin);
    stub.requests = 0;
    const discovery = createDiscovery({ issuer: stub.origin, ttlMs: 60_000 });
    const first = await discovery.get();
    assert.equal(first.ok, true);
    const second = await discovery.get();
    assert.equal(second.ok, true);
    assert.equal(stub.requests, 1, 'a fresh cache must not refetch');
    if (first.ok && second.ok) assert.deepEqual(first.endpoints, second.endpoints);
  });

  it('refetches after reset()', async () => {
    stub.requests = 0;
    const discovery = createDiscovery({ issuer: stub.origin, ttlMs: 60_000 });
    await discovery.get();
    discovery.reset();
    await discovery.get();
    assert.equal(stub.requests, 2);
  });

  it('coalesces concurrent misses into one request', async () => {
    stub.requests = 0;
    const discovery = createDiscovery({ issuer: stub.origin, ttlMs: 60_000 });
    await Promise.all([discovery.get(), discovery.get(), discovery.get()]);
    assert.equal(stub.requests, 1);
  });

  it('returns a typed failure for a non-2xx response', async () => {
    stub.status = 500;
    const discovery = createDiscovery({ issuer: stub.origin, ttlMs: 0 });
    const result = await discovery.get();
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'discovery_unavailable');
    stub.status = 200;
  });

  it('returns a typed failure when the issuer is unreachable', async () => {
    // Port 1 is not listening; connect fails quickly.
    const discovery = createDiscovery({ issuer: 'http://127.0.0.1:1', timeoutMs: 500 });
    const result = await discovery.get();
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'discovery_unavailable');
  });

  it('tolerates a missing device_authorization_endpoint', async () => {
    stub.document = documentFor(stub.origin);
    const discovery = createDiscovery({ issuer: stub.origin, ttlMs: 0 });
    const result = await discovery.get();
    assert.equal(result.ok, true);
    if (result.ok) assert.equal(result.endpoints.deviceAuthorizationEndpoint, null);
  });
});

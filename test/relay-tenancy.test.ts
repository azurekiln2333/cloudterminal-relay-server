// Step 4: account-bound client authorization and many-to-many routing.
//
// Covers AC1 (cross-account isolation), AC2 (two accounts on one device),
// AC4 (revoking one binding leaves the others) and the degraded path when the
// database is unreachable. Uses an in-memory pool so it runs without MySQL.

import assert from 'node:assert/strict';
import test from 'node:test';

import { startRelay } from './helpers.ts';
import { TestSocket } from './helpers.ts';
import { createFakeDb } from './fake-db.ts';
import { sha256Hex } from '../src/shared/crypto.ts';

const AGENT = { agentId: 'a'.repeat(16), secretHash: '0'.repeat(64) };

async function registerAgent(url: string, name = 'desktop'): Promise<TestSocket> {
  const agent = await TestSocket.open(url);
  agent.send({ t: 'hello', role: 'agent', agentId: AGENT.agentId, secretHash: AGENT.secretHash, name });
  assert.equal((await agent.next((f) => f.t === 'hello_ok')).t, 'hello_ok');
  return agent;
}

test('two accounts bound to one device can both connect and receive messages', async () => {
  const db = createFakeDb({
    bindings: [`acct-1\u0000${AGENT.agentId}`, `acct-2\u0000${AGENT.agentId}`],
    tokens: [
      { token: 'ct_token_one', accountId: 'acct-1' },
      { token: 'ct_token_two', accountId: 'acct-2' },
    ],
  });
  const { relay, url } = await startRelay({ db });
  const agent = await registerAgent(url);

  const c1 = await TestSocket.open(url);
  c1.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_token_one' });
  const hello1 = await c1.next((f) => f.t === 'hello_ok');
  assert.equal(hello1.online, true);

  const c2 = await TestSocket.open(url);
  c2.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_token_two' });
  const hello2 = await c2.next((f) => f.t === 'hello_ok');
  assert.notEqual(hello1.clientId, hello2.clientId);

  // The agent sees both joins and the two clients are distinct.
  const joined = new Set<string>();
  for (let i = 0; i < 2; i++) joined.add((await agent.next((f) => f.t === 'client_joined')).clientId);
  assert.deepEqual([...joined].sort(), [hello1.clientId, hello2.clientId].sort());

  // A broadcast reaches both accounts.
  agent.send({ t: 'msg', data: { kind: 'sessions', sessions: [] } });
  assert.equal((await c1.next((f) => f.t === 'msg')).data.kind, 'sessions');
  assert.equal((await c2.next((f) => f.t === 'msg')).data.kind, 'sessions');

  // Targeted delivery still reaches only the named client.
  agent.send({ t: 'msg', to: hello1.clientId, data: { kind: 'ack', id: 'only-one' } });
  assert.equal((await c1.next((f) => f.t === 'msg')).data.id, 'only-one');
  assert.equal(await c2.none((f) => f.t === 'msg'), true);

  // Requests route back to the agent with the right clientId stamped.
  c2.send({ t: 'msg', data: { type: 'list_sessions', id: 'r1' } });
  const inbound = await agent.next((f) => f.t === 'msg');
  assert.equal(inbound.clientId, hello2.clientId);
  assert.equal(inbound.data.id, 'r1');

  assert.deepEqual(relay.stats(), { agents: 1, online: 1, clients: 2 });

  c1.close();
  c2.close();
  agent.close();
  await relay.close();
});

test('an account cannot reach a device it is not bound to', async () => {
  const db = createFakeDb({
    bindings: [`acct-1\u0000${AGENT.agentId}`],
    tokens: [
      { token: 'ct_token_one', accountId: 'acct-1' },
      { token: 'ct_token_outsider', accountId: 'acct-outsider' },
    ],
  });
  const { relay, url } = await startRelay({ db });
  const agent = await registerAgent(url);

  const ok = await TestSocket.open(url);
  ok.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_token_one' });
  assert.equal((await ok.next((f) => f.t === 'hello_ok')).t, 'hello_ok');
  // Drain the legitimate join so the reject assertion below is unambiguous.
  const legitJoin = await agent.next((f) => f.t === 'client_joined');

  const outsider = await TestSocket.open(url);
  outsider.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_token_outsider' });
  const denied = await outsider.next((f) => f.t === 'error');
  assert.equal(denied.code, 'unauthorized');
  assert.equal((await outsider.closed).code, 1008);

  // The device never sees the rejected client.
  assert.equal(await agent.none((f) => f.t === 'client_joined' && f.clientId !== legitJoin.clientId), true);
  assert.deepEqual(relay.stats(), { agents: 1, online: 1, clients: 1 });

  ok.close();
  agent.close();
  await relay.close();
});

test('an unknown or revoked relay token is rejected without touching bindings', async () => {
  const db = createFakeDb({ bindings: [`acct-1\u0000${AGENT.agentId}`], tokens: [{ token: 'ct_live', accountId: 'acct-1' }] });
  const { relay, url } = await startRelay({ db });
  const agent = await registerAgent(url);

  const bad = await TestSocket.open(url);
  bad.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_never_issued' });
  assert.equal((await bad.next((f) => f.t === 'error')).code, 'unauthorized');

  db.revokeToken('ct_live');
  const revoked = await TestSocket.open(url);
  revoked.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_live' });
  assert.equal((await revoked.next((f) => f.t === 'error')).code, 'unauthorized');

  agent.close();
  await relay.close();
});

test('a device-scoped token only works for its own device', async () => {
  const other = 'b'.repeat(16);
  const db = createFakeDb({
    bindings: [`acct-1\u0000${AGENT.agentId}`, `acct-1\u0000${other}`],
    tokens: [{ token: 'ct_scoped', accountId: 'acct-1', deviceId: other }],
  });
  const { relay, url } = await startRelay({ db });
  const agent = await registerAgent(url);

  const wrong = await TestSocket.open(url);
  wrong.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_scoped' });
  assert.equal((await wrong.next((f) => f.t === 'error')).code, 'unauthorized');
  assert.equal(await agent.none((f) => f.t === 'client_joined'), true);

  agent.close();
  await relay.close();
});

test('revoking one binding leaves the other account on the device working', async () => {
  const db = createFakeDb({
    bindings: [`acct-1\u0000${AGENT.agentId}`, `acct-2\u0000${AGENT.agentId}`],
    tokens: [
      { token: 'ct_one', accountId: 'acct-1' },
      { token: 'ct_two', accountId: 'acct-2' },
    ],
  });
  // A zero TTL cache makes the revocation visible immediately.
  const { relay, url } = await startRelay({ db, bindingCacheMs: 0 });
  const agent = await registerAgent(url);

  db.unbind('acct-1', AGENT.agentId);

  const gone = await TestSocket.open(url);
  gone.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_one' });
  assert.equal((await gone.next((f) => f.t === 'error')).code, 'unauthorized');

  const stillThere = await TestSocket.open(url);
  stillThere.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_two' });
  assert.equal((await stillThere.next((f) => f.t === 'hello_ok')).t, 'hello_ok');

  stillThere.close();
  agent.close();
  await relay.close();
});

test('a cached binding is reused instead of querying per connection', async () => {
  const db = createFakeDb({
    bindings: [`acct-1\u0000${AGENT.agentId}`],
    tokens: [{ token: 'ct_one', accountId: 'acct-1' }],
  });
  const { relay, url } = await startRelay({ db, bindingCacheMs: 60_000 });
  const agent = await registerAgent(url);

  const first = await TestSocket.open(url);
  first.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_one' });
  await first.next((f) => f.t === 'hello_ok');
  const afterFirst = db.calls;

  const second = await TestSocket.open(url);
  second.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_one' });
  await second.next((f) => f.t === 'hello_ok');

  // Token lookup still runs, but the binding decision is served from cache.
  assert.equal(db.calls - afterFirst <= 1, true);

  first.close();
  second.close();
  agent.close();
  await relay.close();
});

test('with no database the relay still serves the legacy secret path', async () => {
  const { relay, url } = await startRelay({ db: null });
  const agent = await TestSocket.open(url);
  const legacySecret = 'legacy-secret';
  agent.send({
    t: 'hello',
    role: 'agent',
    agentId: AGENT.agentId,
    secretHash: sha256Hex(legacySecret),
    name: 'desktop',
  });
  assert.equal((await agent.next((f) => f.t === 'hello_ok')).t, 'hello_ok');

  // Legacy client: unchanged behavior, no database involved.
  const legacy = await TestSocket.open(url);
  legacy.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, secret: legacySecret });
  assert.equal((await legacy.next((f) => f.t === 'hello_ok')).t, 'hello_ok');

  // Account path reports a retryable, non-fatal error.
  const account = await TestSocket.open(url);
  account.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_one' });
  const err = await account.next((f) => f.t === 'error');
  assert.equal(err.code, 'account_unavailable');

  // The legacy client keeps working.
  agent.send({ t: 'msg', data: { kind: 'ack', id: 'ping' } });
  assert.equal((await legacy.next((f) => f.t === 'msg')).data.id, 'ping');

  legacy.close();
  agent.close();
  await relay.close();
});

test('an unreachable database fails closed and never grants access', async () => {
  const db = createFakeDb({
    bindings: [`acct-1\u0000${AGENT.agentId}`],
    tokens: [{ token: 'ct_one', accountId: 'acct-1' }],
    failWith: new Error('connect ECONNREFUSED'),
  });
  const { relay, url } = await startRelay({ db });
  const agent = await registerAgent(url);

  const client = await TestSocket.open(url);
  client.send({ t: 'hello', role: 'client', agentId: AGENT.agentId, relayToken: 'ct_one' });
  const err = await client.next((f) => f.t === 'error');
  assert.equal(err.code, 'account_unavailable');
  assert.equal(await agent.none((f) => f.t === 'client_joined'), true);

  agent.close();
  await relay.close();
});

test('a client hello carrying neither secret nor relayToken is a bad request', async () => {
  const { relay, url } = await startRelay();
  const agent = await registerAgent(url);

  const client = await TestSocket.open(url);
  client.send({ t: 'hello', role: 'client', agentId: AGENT.agentId });
  const err = await client.next((f) => f.t === 'error');
  assert.equal(err.code, 'bad_request');
  assert.equal(await agent.none((f) => f.t === 'client_joined'), true);

  agent.close();
  await relay.close();
});

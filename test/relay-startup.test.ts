// Relay startup contract.
//
// Split out of `deployment.test.ts` when the relay moved to its own repository.
// The test starts the real `src/relay/main.ts` process twice against the same
// key file and proves three things the deployment docs promise:
//
//   1. the registration key is generated once, persisted and reused on restart;
//   2. the key is accepted for agent registration and never appears in logs;
//   3. it can only be read back through `src/relay/show-key.ts`.

import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer, type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';

import { TestSocket } from './helpers.ts';

function childEnv(home: string, overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env = { ...process.env };
  for (const key of ['CLOUDTERMINAL_RELAY', 'CLOUDTERMINAL_RELAY_KEY', 'RELAY_KEY', 'RELAY_KEY_FILE', 'RELAY_TRUST_PROXY']) delete env[key];
  return { ...env, CLOUDTERMINAL_HOME: home, ...overrides };
}

function launch(script: string, env: NodeJS.ProcessEnv, args: string[] = []) {
  const child = spawn(process.execPath, [script, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (chunk: Buffer) => { output += chunk.toString(); });
  child.stderr.on('data', (chunk: Buffer) => { output += chunk.toString(); });
  return { child, output: () => output };
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, 'exit');
  child.kill();
  await exited;
}

async function waitFor(predicate: () => boolean, output: () => string): Promise<void> {
  const until = Date.now() + 7000;
  while (!predicate() && Date.now() < until) await delay(25);
  assert.ok(predicate(), output());
}

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
  return port;
}

test('relay startup persists registration key, authenticates and exposes it only via show-key', { timeout: 20000 }, async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'ct-relay-runtime-'));
  const file = path.join(home, 'relay-key');
  const port = await freePort();
  const env = childEnv(home, { RELAY_KEY_FILE: file, PORT: String(port), HOST: '127.0.0.1' });
  let key: string | undefined;
  try {
    for (let run = 0; run < 2; run++) {
      const relay = launch('src/relay/main.ts', env);
      try {
        await waitFor(() => relay.output().includes('listening'), relay.output);
        const stored = (await readFile(file, 'utf8')).trim();
        assert.ok(stored.length >= 32);
        if (key !== undefined) assert.equal(stored, key);
        key = stored;
        assert.equal(relay.output().includes(key), false);
        assert.match(relay.output(), /relayKey=required/);
        assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 200);
        const socket = await TestSocket.open(`ws://127.0.0.1:${port}/ws`);
        try {
          socket.send({ t: 'hello', role: 'agent', agentId: 'deployment-agent', secretHash: 'a'.repeat(64), relayKey: key, name: 'Deployment test', v: 1 });
          assert.equal((await socket.next()).t, 'hello_ok');
        } finally { socket.close(); await socket.closed; }
        const show = launch('src/relay/show-key.ts', env);
        const [code] = await once(show.child, 'exit');
        assert.equal(code, 0);
        assert.equal(show.output().trim(), key);
        assert.equal(relay.output().includes(key), false);
      } finally { await stop(relay.child); }
    }
    const invalid = launch('src/relay/main.ts', { ...env, PORT: '0', RELAY_KEY_FILE: path.join(home, 'not-created') });
    const [code] = await once(invalid.child, 'exit');
    assert.notEqual(code, 0);
    assert.match(invalid.output(), /PORT must be an integer/);
    await assert.rejects(readFile(path.join(home, 'not-created')), { code: 'ENOENT' });
  } finally { await rm(home, { recursive: true, force: true }); }
});

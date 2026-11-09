// Registration-key handling.
//
// Split out of `setup.test.ts` (which is about the desktop agent's interactive
// wizard) when the relay moved to its own repository. The key file is the only
// durable state a relay deployment has, so its exact semantics are pinned here:
// generate once, reuse, allow an explicit override, refuse empty values, and be
// race-safe when several starts happen at once.

import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { registrationKey } from '../src/relay/key.ts';

test('relay key generation persists, respects explicit override and rejects empty file', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'ct-key-'));
  try {
    const file = path.join(dir, 'relay-key');
    const key = await registrationKey({ RELAY_KEY_FILE: file });
    assert.ok(key && key.length >= 32);
    assert.equal(await registrationKey({ RELAY_KEY_FILE: file }), key);
    assert.equal(await registrationKey({ RELAY_KEY_FILE: file, RELAY_KEY: 'override' }), 'override');
    assert.equal((await readFile(file, 'utf8')).trim(), key);
    assert.equal(await registrationKey({}), undefined);
    await assert.rejects(registrationKey({ RELAY_KEY: '', RELAY_KEY_FILE: file }), /RELAY_KEY must not be empty/);
    await assert.rejects(registrationKey({ RELAY_KEY: ' ' }), /RELAY_KEY must not be empty/);
    await assert.rejects(registrationKey({ RELAY_KEY_FILE: '' }), /RELAY_KEY_FILE must not be empty/);
    const concurrent = path.join(dir, 'concurrent');
    const keys = await Promise.all(Array.from({ length: 5 }, () => registrationKey({ RELAY_KEY_FILE: concurrent })));
    assert.equal(new Set(keys).size, 1);
    const empty = path.join(dir, 'empty');
    await writeFile(empty, '');
    await assert.rejects(registrationKey({ RELAY_KEY_FILE: empty }), /empty/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

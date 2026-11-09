import { mkdir, writeFile, readFile, link, rm } from 'node:fs/promises';
import path from 'node:path';
import { randomToken } from '../shared/crypto.ts';

export async function registrationKey(env: NodeJS.ProcessEnv = process.env): Promise<string | undefined> {
  if (env.RELAY_KEY !== undefined) {
    if (!env.RELAY_KEY.trim()) throw new Error('RELAY_KEY must not be empty');
    return env.RELAY_KEY;
  }
  const file = env.RELAY_KEY_FILE;
  if (file === undefined) return undefined;
  if (!file.trim()) throw new Error('RELAY_KEY_FILE must not be empty');
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${randomToken(12)}.tmp`;
  try {
    await writeFile(temporary, randomToken(32) + '\n', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    // Publish a complete file without overwriting another process's key.
    try { await link(temporary, file); } catch (err) { if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err; }
  } finally { await rm(temporary, { force: true }); }
  const key = (await readFile(file, 'utf8')).trim();
  if (!key) throw new Error('Relay registration key file is empty');
  return key;
}

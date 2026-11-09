import { registrationKey } from './key.ts';

const key = await registrationKey();
if (!key) { console.error('No relay registration key configured'); process.exitCode = 1; }
else process.stdout.write(key + '\n');

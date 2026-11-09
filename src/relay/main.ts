// Relay server entrypoint.
//
//   PORT=8787 HOST=0.0.0.0 RELAY_KEY=... node src/relay/main.ts
//
// Put it behind a TLS terminator (Caddy / Nginx) for internet use and set
// RELAY_TRUST_PROXY=1 so per-IP rate limiting sees the real client address.
//
// Account login (OAuth2 + MySQL) is optional. Without DB_*/OAUTH_* settings the
// relay behaves exactly as before; with partial settings it starts in a
// degraded state and says so. See README.md.

import { consoleLogger } from '../shared/log.ts';
import { createDbPool } from '../db/pool.ts';
import { runMigrations } from '../db/migrate.ts';
import { loadOauthConfig } from '../oauth/config.ts';
import { createVerifier } from '../oauth/verify.ts';
import { createFlows } from '../oauth/flows.ts';
import { attachApi } from './api.ts';
import { createRelay } from './relay.ts';
import { createTenancy } from './tenancy.ts';
import { registrationKey } from './key.ts';

const log = consoleLogger('relay');
const port = Number(process.env.PORT ?? 8787);
const host = process.env.HOST ?? '0.0.0.0';
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be an integer between 1 and 65535');
const relayKey = await registrationKey();

// --- optional account layer -------------------------------------------------

const dbResult = createDbPool();
if (dbResult.state === 'disabled') {
  log.info('database not configured: account features disabled');
} else if (dbResult.state === 'degraded') {
  log.warn('database configuration incomplete: account features disabled', { detail: dbResult.message });
}
const db = dbResult.pool;

if (db) {
  if (process.env.RELAY_DB_AUTO_MIGRATE === '1') {
    try {
      const applied = await runMigrations(db);
      log.info('database ready', { applied: applied.applied.length });
    } catch (err) {
      // A migration failure is never safe to ignore: the schema and the code
      // disagree, so serving account traffic would be undefined.
      log.error('database migration failed; refusing to start', { err: (err as Error).message });
      await db.close();
      process.exit(1);
    }
  } else {
    // Do not create tables implicitly on a request path.
    log.info('migrations are not run automatically; run: node src/db/migrate.ts');
  }
}

// The relay itself knows nothing about the database: the optional account
// layer is injected as an `AccountAuthorizer`. Without a pool, tenancy reports
// `available === false` and the relay answers `account_unavailable`, exactly as
// it did before accounts existed.
const relay = createRelay({ relayKey, accounts: createTenancy({ pool: db, logger: log }), logger: log });

// --- optional OAuth2 account login ------------------------------------------

const oauth = loadOauthConfig();
if (oauth.state === 'degraded') log.warn('oauth configuration incomplete: account login disabled', { detail: oauth.message });
const accessTtlMs = positiveInt(process.env.RELAY_ACCESS_TTL_MS, 3_600_000);
const refreshTtlMs = positiveInt(process.env.RELAY_REFRESH_TTL_MS, 2_592_000_000);
const verifier = oauth.state === 'ready' ? createVerifier({ config: oauth.config, logger: log }) : null;
const flows =
  oauth.state === 'ready' && db ? createFlows({ db, config: oauth.config, verifier: verifier!, accessTtlMs, refreshTtlMs, logger: log }) : null;
if (oauth.state === 'ready' && !db) log.warn('oauth configured but the database is unavailable: account login disabled');

const server = await relay.listen(port, host);
attachApi(server, {
  db,
  verifier,
  flows,
  config: oauth.state === 'ready' ? oauth.config : null,
  oauthState: oauth.state,
  oauthMessage: oauth.message,
  accessTtlMs,
  refreshTtlMs,
  logger: log,
  isDeviceOnline: (deviceId) => relay.isDeviceOnline(deviceId),
  resolvePairCode: (code) => relay.resolvePairCode(code),
  onBindingRevoked: (accountId, deviceId) => relay.invalidateBinding(accountId, deviceId),
});

log.info('listening', { url: `ws://${host}:${port}/ws`, relayKey: relayKey ? 'required' : 'off', accounts: flows ? 'on' : 'off' });
if (!relayKey) log.warn('RELAY_KEY not set: any agent may register on this relay');

/** Parse a positive integer setting, falling back to a safe default. */
function positiveInt(raw: string | undefined, fallback: number): number {
  const value = Number(raw);
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

const shutdown = () => {
  log.info('shutting down');
  void relay
    .close()
    .then(() => db?.close())
    .then(() => process.exit(0));
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

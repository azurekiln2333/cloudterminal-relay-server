// MySQL connection settings parsed from `DB_*` environment variables.
//
// Parsing is pure: this module never opens a socket. `db/pool.ts` is the only
// place that dials out, and it does so lazily. A partially configured or
// invalid database therefore yields the `disabled` / `degraded` states instead
// of crashing the relay at import time (PRD R18).

export type DbState = 'disabled' | 'degraded' | 'ready';

export type DbTlsConfig =
  | { enabled: false }
  | { enabled: true; caFile: string | null };

export type DbConfig = {
  state: DbState;
  /** Actionable, secret-free explanation; empty when `state === 'ready'`. */
  message: string;
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  connectionLimit: number;
  connectTimeoutMs: number;
  tls: DbTlsConfig;
};

export type DbConfigResult =
  | { state: 'disabled' | 'degraded'; message: string; config: null }
  | { state: 'ready'; message: ''; config: DbConfig };

const DEFAULT_PORT = 3306;
const DEFAULT_CONNECTION_LIMIT = 10;
const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

/** True when at least one `DB_*` variable is present. */
function anyDbVarSet(env: NodeJS.ProcessEnv): boolean {
  return Object.keys(env).some((key) => key.startsWith('DB_'));
}

function parseBool(raw: string, name: string): boolean {
  const value = raw.trim().toLowerCase();
  if (value === 'true' || value === '1' || value === 'yes' || value === 'on') return true;
  if (value === 'false' || value === '0' || value === 'no' || value === 'off' || value === '') return false;
  throw new Error(`${name} must be a boolean (true/false), got ${JSON.stringify(raw)}`);
}

function parseInteger(raw: string, name: string, min: number, max: number): number {
  const text = raw.trim();
  if (!/^\d+$/.test(text)) throw new Error(`${name} must be an integer, got ${JSON.stringify(raw)}`);
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be between ${min} and ${max}, got ${text}`);
  }
  return value;
}

/**
 * Parse `DB_*`. With no `DB_*` variable at all the database is `disabled` and
 * the relay keeps its legacy in-memory behaviour. With a partial set of
 * variables the database is `degraded`: account features report it instead of
 * failing silently, and the legacy protocol still serves traffic.
 *
 * Throws on a syntactically invalid value so misconfiguration is loud rather
 * than silently ignored.
 */
export function loadDbConfig(env: NodeJS.ProcessEnv = process.env): DbConfigResult {
  if (!anyDbVarSet(env)) {
    return { state: 'disabled', message: 'no DB_* settings configured; database features are off', config: null };
  }

  const raw: Record<string, string> = {};
  for (const key of [
    'DB_HOST',
    'DB_PORT',
    'DB_USER',
    'DB_PASSWORD',
    'DB_NAME',
    'DB_CONNECTION_LIMIT',
    'DB_CONNECT_TIMEOUT_MS',
    'DB_TLS',
    'DB_TLS_CA_FILE',
  ]) {
    const value = env[key];
    if (value !== undefined) raw[key] = value;
  }

  const missing: string[] = [];
  for (const name of ['DB_HOST', 'DB_USER', 'DB_NAME']) {
    if (!raw[name]?.trim()) missing.push(name);
  }
  if (missing.length > 0) {
    return {
      state: 'degraded',
      message: `incomplete DB_* settings; missing ${missing.join(', ')}`,
      config: null,
    };
  }

  const host = raw.DB_HOST!.trim();
  const user = raw.DB_USER!.trim();
  const database = raw.DB_NAME!.trim();
  const port = raw.DB_PORT === undefined ? DEFAULT_PORT : parseInteger(raw.DB_PORT, 'DB_PORT', 1, 65535);
  const connectionLimit =
    raw.DB_CONNECTION_LIMIT === undefined
      ? DEFAULT_CONNECTION_LIMIT
      : parseInteger(raw.DB_CONNECTION_LIMIT, 'DB_CONNECTION_LIMIT', 1, 1000);
  const connectTimeoutMs =
    raw.DB_CONNECT_TIMEOUT_MS === undefined
      ? DEFAULT_CONNECT_TIMEOUT_MS
      : parseInteger(raw.DB_CONNECT_TIMEOUT_MS, 'DB_CONNECT_TIMEOUT_MS', 100, 600_000);

  const tlsRaw = raw.DB_TLS === undefined ? false : parseBool(raw.DB_TLS, 'DB_TLS');
  const caFile = raw.DB_TLS_CA_FILE?.trim() ?? '';
  if (caFile && !tlsRaw) {
    throw new Error('DB_TLS_CA_FILE is set but DB_TLS is false; enable DB_TLS or unset the CA file');
  }
  const tls: DbTlsConfig = tlsRaw ? { enabled: true, caFile: caFile || null } : { enabled: false };

  return {
    state: 'ready',
    message: '',
    config: {
      state: 'ready',
      message: '',
      host,
      port,
      user,
      password: raw.DB_PASSWORD ?? '',
      database,
      connectionLimit,
      connectTimeoutMs,
      tls,
    },
  };
}

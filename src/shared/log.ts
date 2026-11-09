export type Logger = {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
};

function fmt(fields?: Record<string, unknown>): string {
  if (!fields) return '';
  const parts = Object.entries(fields).map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`);
  return parts.length ? ' ' + parts.join(' ') : '';
}

export function consoleLogger(scope: string): Logger {
  const line = (level: string, msg: string, fields?: Record<string, unknown>) =>
    `${new Date().toISOString()} ${level} [${scope}] ${msg}${fmt(fields)}`;
  return {
    info: (m, f) => console.log(line('INFO', m, f)),
    warn: (m, f) => console.warn(line('WARN', m, f)),
    error: (m, f) => console.error(line('ERROR', m, f)),
  };
}

export const silentLogger: Logger = { info() {}, warn() {}, error() {} };

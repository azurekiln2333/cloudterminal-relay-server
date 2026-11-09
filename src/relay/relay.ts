import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer, type RawData, WebSocket } from 'ws';

import { hexDigestEquals, randomToken, sha256Hex } from '../shared/crypto.ts';
import { type Logger, silentLogger } from '../shared/log.ts';
import {
  MAX_FRAME_BYTES,
  PAIR_CODE_ALPHABET,
  PAIR_CODE_LENGTH,
  normalizePairCode,
  type Hello,
  type RelayErrorCode,
} from '../shared/relay-protocol.ts';
import type { AccountClientHello } from '../shared/protocol-account.ts';

/** Relay error codes, including the additive account-layer codes. */
type RelayError = RelayErrorCode | 'account_unavailable';

/** Client hello, with the optional account-bound variant. */
type AnyClientHello = Extract<Hello, { role: 'client' }> | AccountClientHello;

/**
 * Result of resolving an account token for `(token, deviceId)`.
 * `unavailable` is retryable, the other reasons are final for this attempt.
 */
export type AccountClientResult =
  | { ok: true; accountId: string }
  | { ok: false; reason: 'no_database' | 'invalid_token' | 'not_bound' | 'unavailable' };

/**
 * The account layer the relay needs, and nothing more. `tenancy.ts` implements
 * it on top of the optional database; the relay itself never imports `db/`.
 */
export type AccountAuthorizer = {
  readonly available: boolean;
  authorizeClient(token: string, deviceId: string): Promise<AccountClientResult>;
  invalidate(accountId: string, deviceId: string): void;
};

/** Behaviour of the legacy relay when no account layer is configured. */
const unavailableAccounts: AccountAuthorizer = {
  available: false,
  async authorizeClient() {
    return { ok: false, reason: 'no_database' };
  },
  invalidate() {},
};

export type RelayOptions = {
  /** When set, agents must present this key to register. */
  relayKey?: string;
  helloTimeoutMs?: number;
  heartbeatMs?: number;
  /** Failed client auths allowed per IP within `authWindowMs`. */
  maxAuthFailures?: number;
  authWindowMs?: number;
  /**
   * Optional account layer. When supplied and `available`, clients may present
   * `relayToken` instead of the device secret. Omitted keeps the relay
   * byte-identical to the pre-account behavior: account clients are rejected
   * with `account_unavailable`.
   */
  accounts?: AccountAuthorizer;
  logger?: Logger;
};

type AgentEntry = {
  agentId: string;
  secretHash: string;
  name: string;
  socket: WebSocket | null;
  clients: Map<string, WebSocket>;
  offlineSince: number;
};

type Alive = { alive: boolean };

export type Relay = {
  /** Attach to an existing HTTP server (upgrade on `/ws`). */
  attach(server: Server): void;
  /** Convenience: create an HTTP server with `/healthz` and listen. */
  listen(port: number, host?: string): Promise<Server>;
  close(): Promise<void>;
  /** For tests / diagnostics. */
  stats(): { agents: number; online: number; clients: number };
  /**
   * Resolve a one-time pairing code to the device that issued it, consuming it.
   * Used by the HTTP binding API to prove device consent (PRD R12). Resolves to
   * `null` when the code is unknown or expired.
   */
  resolvePairCode(code: string): Promise<string | null>;
  /** Whether a device currently holds a live agent socket. */
  isDeviceOnline(deviceId: string): boolean;
  /** Drop a cached binding decision after the HTTP API revokes it. */
  invalidateBinding(accountId: string, deviceId: string): void;
};

const CLOSE_POLICY = 1008;
const CLOSE_REPLACED = 4000;

export function createRelay(opts: RelayOptions = {}): Relay {
  const log = opts.logger ?? silentLogger;
  const helloTimeoutMs = opts.helloTimeoutMs ?? 10_000;
  const heartbeatMs = opts.heartbeatMs ?? 30_000;
  const maxAuthFailures = opts.maxAuthFailures ?? 10;
  const authWindowMs = opts.authWindowMs ?? 10 * 60_000;

  const accounts: AccountAuthorizer = opts.accounts ?? unavailableAccounts;
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES });
  const agents = new Map<string, AgentEntry>();
  const authFailures = new Map<string, { count: number; since: number }>();
  const pairCodes = new Map<string, { agentId: string; expiresAt: number }>();
  const pendingPairs = new Map<string, { ws: WebSocket; agentId: string; timer: NodeJS.Timeout }>();
  const servers: Server[] = [];

  const heartbeat = setInterval(() => {
    // Forget agents that have been offline for a day with nobody waiting.
    const now = Date.now();
    for (const [code, p] of pairCodes) if (p.expiresAt < now) pairCodes.delete(code);
    for (const [id, a] of agents) {
      if (!a.socket && a.clients.size === 0 && now - a.offlineSince > 24 * 3600_000) agents.delete(id);
    }
    for (const ws of wss.clients) {
      const state = ws as WebSocket & Alive;
      if (state.alive === false) {
        ws.terminate();
        continue;
      }
      state.alive = false;
      ws.ping();
    }
  }, heartbeatMs);
  heartbeat.unref();

  function send(ws: WebSocket, frame: unknown): void {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(frame));
  }

  function fail(ws: WebSocket, code: RelayError, message: string): void {
    send(ws, { t: 'error', code, message });
    ws.close(CLOSE_POLICY, code);
  }

  function isRateLimited(ip: string): boolean {
    const entry = authFailures.get(ip);
    if (!entry) return false;
    if (Date.now() - entry.since > authWindowMs) {
      authFailures.delete(ip);
      return false;
    }
    return entry.count >= maxAuthFailures;
  }

  function recordAuthFailure(ip: string): void {
    const now = Date.now();
    const entry = authFailures.get(ip);
    if (!entry || now - entry.since > authWindowMs) {
      authFailures.set(ip, { count: 1, since: now });
    } else {
      entry.count++;
    }
  }

  function parseHello(raw: RawData): Hello | null {
    try {
      const v = JSON.parse(raw.toString()) as Record<string, unknown>;
      if (v.t === 'hello' && v.role === 'pair' && typeof v.code === 'string' && v.code.length <= 32) {
        return v as unknown as Hello;
      }
      if (v.t !== 'hello' || typeof v.agentId !== 'string' || v.agentId.length < 8 || v.agentId.length > 128) {
        return null;
      }
      if (v.role === 'agent' && typeof v.secretHash === 'string' && /^[0-9a-f]{64}$/.test(v.secretHash)) {
        return v as unknown as Hello;
      }
      if (v.role === 'client' && typeof v.secret === 'string' && v.secret.length > 0 && v.secret.length <= 512) {
        return v as unknown as Hello;
      }
      // Account-bound client: no device secret, only a relay-issued token.
      if (
        v.role === 'client' &&
        typeof v.relayToken === 'string' &&
        v.relayToken.length > 0 &&
        v.relayToken.length <= 512
      ) {
        return v as unknown as Hello;
      }
      return null;
    } catch {
      return null;
    }
  }

  function onAgent(ws: WebSocket, hello: Extract<Hello, { role: 'agent' }>, ip: string): void {
    if (opts.relayKey) {
      const ok = typeof hello.relayKey === 'string' && hexDigestEquals(sha256Hex(hello.relayKey), sha256Hex(opts.relayKey));
      if (!ok) {
        log.warn('agent rejected: bad relay key', { ip });
        return fail(ws, 'unauthorized', 'invalid relay key');
      }
    }

    let entry = agents.get(hello.agentId);
    if (entry && !hexDigestEquals(entry.secretHash, hello.secretHash)) {
      log.warn('agent rejected: id conflict', { agentId: hello.agentId, ip });
      return fail(ws, 'agent_conflict', 'agentId already registered with a different secret');
    }
    if (!entry) {
      entry = { agentId: hello.agentId, secretHash: hello.secretHash, name: '', socket: null, clients: new Map(), offlineSince: 0 };
      agents.set(hello.agentId, entry);
    }
    const previous = entry.socket;
    entry.socket = ws;
    entry.name = (hello.name ?? '').slice(0, 64);
    if (previous && previous !== ws) previous.close(CLOSE_REPLACED, 'replaced');

    const agent = entry;
    send(ws, { t: 'hello_ok' });
    log.info('agent online', { agentId: agent.agentId, name: agent.name, ip });
    for (const [clientId, client] of agent.clients) {
      send(client, { t: 'presence', online: true, name: agent.name });
      send(ws, { t: 'client_joined', clientId });
    }

    ws.on('message', (raw, isBinary) => {
      if (isBinary) return;
      let frame: { t?: unknown; data?: unknown; to?: unknown };
      try {
        frame = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (frame.t === 'pair_code') return onPairCode(agent, frame as { code?: unknown; ttlMs?: unknown });
      if (frame.t === 'pair_response') return onPairResponse(agent, frame as { pairId?: unknown; secret?: unknown });
      if (frame.t !== 'msg' || frame.data === undefined) return;
      const out = JSON.stringify({ t: 'msg', data: frame.data });
      if (typeof frame.to === 'string') {
        const target = agent.clients.get(frame.to);
        if (target?.readyState === WebSocket.OPEN) target.send(out);
      } else {
        for (const client of agent.clients.values()) {
          if (client.readyState === WebSocket.OPEN) client.send(out);
        }
      }
    });

    ws.on('close', () => {
      if (agent.socket !== ws) return; // replaced by a newer connection
      agent.socket = null;
      agent.offlineSince = Date.now();
      log.info('agent offline', { agentId: agent.agentId });
      for (const client of agent.clients.values()) send(client, { t: 'presence', online: false });
    });
  }

  // --- pairing codes --------------------------------------------------------

  function onPairCode(agent: AgentEntry, frame: { code?: unknown; ttlMs?: unknown }): void {
    if (!agent.socket) return;
    const code = typeof frame.code === 'string' ? normalizePairCode(frame.code) : '';
    if (code.length !== PAIR_CODE_LENGTH || [...code].some((c) => !PAIR_CODE_ALPHABET.includes(c))) {
      send(agent.socket, { t: 'error', code: 'bad_request', message: 'invalid pairing code' });
      return;
    }
    for (const [c, p] of pairCodes) if (p.agentId === agent.agentId) pairCodes.delete(c);
    const ttl = Math.min(Math.max(Number(frame.ttlMs) || 0, 10_000), 15 * 60_000);
    const expiresAt = Date.now() + ttl;
    pairCodes.set(code, { agentId: agent.agentId, expiresAt });
    send(agent.socket, { t: 'pair_code_ok', code, expiresAt });
  }

  function onPairResponse(agent: AgentEntry, frame: { pairId?: unknown; secret?: unknown }): void {
    if (typeof frame.pairId !== 'string' || typeof frame.secret !== 'string') return;
    const pending = pendingPairs.get(frame.pairId);
    if (!pending || pending.agentId !== agent.agentId) return;
    pendingPairs.delete(frame.pairId);
    clearTimeout(pending.timer);
    // Only hand out a secret that actually matches this agent's registration.
    if (!hexDigestEquals(agent.secretHash, sha256Hex(frame.secret))) {
      return fail(pending.ws, 'unauthorized', 'agent returned mismatched credentials');
    }
    send(pending.ws, { t: 'paired', agentId: agent.agentId, secret: frame.secret, name: agent.name });
    pending.ws.close(1000, 'paired');
  }

  function onPair(ws: WebSocket, hello: Extract<Hello, { role: 'pair' }>, ip: string): void {
    if (isRateLimited(ip)) return fail(ws, 'rate_limited', 'too many failed attempts, try again later');
    const code = normalizePairCode(hello.code);
    const entry = pairCodes.get(code);
    if (!entry || entry.expiresAt < Date.now()) {
      if (entry) pairCodes.delete(code);
      recordAuthFailure(ip);
      log.warn('pairing rejected: bad code', { ip });
      return fail(ws, 'unauthorized', 'pairing code is invalid or expired');
    }
    const agent = agents.get(entry.agentId);
    if (!agent?.socket) return fail(ws, 'agent_offline', 'device is offline');
    pairCodes.delete(code); // single use
    const pairId = randomToken(12);
    const timer = setTimeout(() => {
      pendingPairs.delete(pairId);
      fail(ws, 'timeout', 'device did not respond');
    }, 10_000);
    pendingPairs.set(pairId, { ws, agentId: agent.agentId, timer });
    ws.once('close', () => {
      clearTimeout(timer);
      pendingPairs.delete(pairId);
    });
    send(agent.socket, { t: 'pair_request', pairId });
    log.info('pairing requested', { agentId: agent.agentId, ip });
  }

  function onClient(
    ws: WebSocket,
    hello: AnyClientHello,
    ip: string,
  ): void {
    if (isRateLimited(ip)) {
      log.warn('client rejected: rate limited', { ip });
      return fail(ws, 'rate_limited', 'too many failed attempts, try again later');
    }
    if ('relayToken' in hello && typeof hello.relayToken === 'string') {
      return void onAccountClient(ws, hello.agentId, hello.relayToken, ip);
    }
    if (!('secret' in hello)) return fail(ws, 'bad_request', 'client hello needs secret or relayToken');
    const entry = agents.get(hello.agentId);
    if (!entry) {
      // Nothing to authenticate against until the agent registers (e.g. right
      // after a relay restart). Not counted as an auth failure: the app keeps
      // retrying, and there is no secret to brute-force here.
      return fail(ws, 'agent_offline', 'device has not connected to this relay yet');
    }
    if (!hexDigestEquals(entry.secretHash, sha256Hex(hello.secret))) {
      recordAuthFailure(ip);
      log.warn('client rejected: bad credentials', { ip });
      return fail(ws, 'unauthorized', 'invalid pairing secret');
    }

    const agent = entry;
    joinClient(ws, agent, ip, null);
  }

  /**
   * Account-bound client. The relay resolves the token, checks that the account
   * is actively bound to the requested device, then joins the client to that
   * device exactly like the legacy path. Several accounts may be attached to
   * one device at the same time (PRD R7/AC2).
   */
  async function onAccountClient(
    ws: WebSocket,
    deviceId: string,
    relayToken: string,
    ip: string,
  ): Promise<void> {
    if (!accounts.available) {
      log.warn('account client rejected: tenancy unavailable', { deviceId, ip });
      return fail(ws, 'account_unavailable', 'account login is not configured on this relay');
    }
    let result;
    try {
      result = await accounts.authorizeClient(relayToken, deviceId);
    } catch (err) {
      log.warn('account client rejected: lookup threw', { deviceId, ip, err: (err as Error).message });
      return fail(ws, 'account_unavailable', 'account lookup failed, retry shortly');
    }
    if (!result.ok) {
      if (result.reason === 'unavailable') {
        log.warn('account client rejected: database unavailable', { deviceId, ip });
        return fail(ws, 'account_unavailable', 'account lookup failed, retry shortly');
      }
      recordAuthFailure(ip);
      log.warn('account client rejected', { deviceId, ip, reason: result.reason });
      return fail(ws, 'unauthorized', 'invalid account token for this device');
    }
    if (ws.readyState !== WebSocket.OPEN) return; // closed while we awaited
    const entry = agents.get(deviceId);
    if (!entry) {
      // The device has never registered on this relay instance.
      return fail(ws, 'agent_offline', 'device has not connected to this relay yet');
    }
    joinClient(ws, entry, ip, { accountId: result.accountId });
  }

  /** Shared client-registration tail used by both auth paths. */
  function joinClient(
    ws: WebSocket,
    agent: AgentEntry,
    ip: string,
    account: { accountId: string } | null,
  ): void {
    const clientId = randomToken(9);
    agent.clients.set(clientId, ws);
    send(ws, { t: 'hello_ok', clientId, online: agent.socket !== null, name: agent.name });
    if (agent.socket) send(agent.socket, { t: 'client_joined', clientId });
    log.info('client joined', { agentId: agent.agentId, clientId, ip, accountId: account?.accountId });

    ws.on('message', (raw, isBinary) => {
      if (isBinary) return;
      let frame: { t?: unknown; data?: unknown };
      try {
        frame = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (frame.t !== 'msg' || typeof frame.data !== 'object' || frame.data === null) return;
      if (!agent.socket || agent.socket.readyState !== WebSocket.OPEN) {
        send(ws, { t: 'error', code: 'agent_offline', message: 'device is offline' });
        return;
      }
      agent.socket.send(JSON.stringify({ t: 'msg', clientId, data: frame.data }));
    });

    ws.on('close', () => {
      agent.clients.delete(clientId);
      if (agent.socket) send(agent.socket, { t: 'client_left', clientId });
      log.info('client left', { agentId: agent.agentId, clientId, accountId: account?.accountId });
    });
  }

  wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
    const ip = clientIp(req);
    (ws as WebSocket & Alive).alive = true;
    ws.on('pong', () => {
      (ws as WebSocket & Alive).alive = true;
    });
    ws.on('error', (err) => log.warn('socket error', { ip, err: err.message }));

    const timer = setTimeout(() => fail(ws, 'timeout', 'hello not received'), helloTimeoutMs);
    ws.once('message', (raw) => {
      clearTimeout(timer);
      const hello = parseHello(raw);
      if (!hello) return fail(ws, 'bad_request', 'expected hello frame');
      if (hello.role === 'agent') onAgent(ws, hello, ip);
      else if (hello.role === 'pair') onPair(ws, hello, ip);
      else onClient(ws, hello, ip);
    });
    ws.once('close', () => clearTimeout(timer));
  });

  function handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    const path = (req.url ?? '').split('?')[0];
    if (path !== '/ws') {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  }

  return {
    attach(server) {
      server.on('upgrade', handleUpgrade);
      servers.push(server);
    },
    async listen(port, host) {
      const server = createServer((req, res) => {
        if (req.url === '/healthz') {
          res.writeHead(200, { 'content-type': 'text/plain' });
          res.end('ok\n');
          return;
        }
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found\n');
      });
      this.attach(server);
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => resolve());
      });
      return server;
    },
    async close() {
      clearInterval(heartbeat);
      for (const ws of wss.clients) ws.terminate();
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      await Promise.all(
        servers.map(
          (s) =>
            new Promise<void>((resolve) => {
              s.off('upgrade', handleUpgrade);
              if (!s.listening) return resolve();
              s.close(() => resolve());
              s.closeAllConnections?.();
            }),
        ),
      );
    },
    stats() {
      let online = 0;
      let clients = 0;
      for (const a of agents.values()) {
        if (a.socket) online++;
        clients += a.clients.size;
      }
      return { agents: agents.size, online, clients };
    },

    async resolvePairCode(code) {
      const normalized = normalizePairCode(code);
      const entry = pairCodes.get(normalized);
      if (!entry) return null;
      pairCodes.delete(normalized); // single use, same as the websocket pair path
      if (entry.expiresAt < Date.now()) return null;
      return entry.agentId;
    },

    isDeviceOnline(deviceId) {
      return agents.get(deviceId)?.socket !== null && agents.get(deviceId) !== undefined;
    },

    invalidateBinding(accountId, deviceId) {
      accounts.invalidate(accountId, deviceId);
    },
  };
}

function clientIp(req: IncomingMessage): string {
  // Only trust X-Forwarded-For when explicitly told we're behind a proxy.
  if (process.env.RELAY_TRUST_PROXY === '1') {
    const fwd = req.headers['x-forwarded-for'];
    const first = (Array.isArray(fwd) ? fwd[0] : fwd)?.split(',')[0]?.trim();
    if (first) return first;
  }
  return req.socket.remoteAddress ?? 'unknown';
}

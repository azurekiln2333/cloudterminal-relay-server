// Relay envelope: the frames exchanged between agents, clients and the relay.
//
// This file is the relay-side half of the wire protocol. The desktop agent and
// the Flutter app also carry the agent payload types (`ClientMessage`,
// `AgentMessage`, ...) in `protocol.ts`; the relay never inspects those
// payloads, so here they are typed as `unknown`.
//
// This file is mirrored into the main `cloudterminal` repository as
// `server/src/shared/relay-protocol.ts` and is kept byte-identical by
// `server/test/relay-core-sync.test.ts` there. Edit it here, then run
// `npm run sync-relay -- <this repo>` in the main repository.

/** Frames that are larger than this are dropped by the relay. */
export const MAX_FRAME_BYTES = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Relay envelope
// ---------------------------------------------------------------------------

export type AgentHello = {
  t: 'hello';
  role: 'agent';
  agentId: string;
  /** sha256(secret) as lowercase hex. The relay never sees the secret. */
  secretHash: string;
  relayKey?: string;
  name?: string;
  v?: number;
};

export type ClientHello = {
  t: 'hello';
  role: 'client';
  agentId: string;
  secret: string;
  v?: number;
};

/** Exchange a short pairing code for the agent's credentials. */
export type PairHello = {
  t: 'hello';
  role: 'pair';
  code: string;
  v?: number;
};

export type Hello = AgentHello | ClientHello | PairHello;

/** Pairing codes: 8 chars from an alphabet without look-alikes (0/O, 1/I/L). */
export const PAIR_CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
export const PAIR_CODE_LENGTH = 8;

export function normalizePairCode(code: string): string {
  return code.toUpperCase().replace(/[^0-9A-Z]/g, '');
}

export type RelayErrorCode =
  | 'bad_request'
  | 'unauthorized'
  | 'rate_limited'
  | 'agent_conflict'
  /** Non-fatal: a client message could not be delivered. */
  | 'agent_offline'
  | 'timeout';

export type RelayFrame =
  | { t: 'hello_ok'; clientId?: string; online?: boolean; name?: string }
  | { t: 'error'; code: RelayErrorCode; message: string }
  | { t: 'presence'; online: boolean; name?: string }
  | { t: 'client_joined'; clientId: string }
  | { t: 'client_left'; clientId: string }
  /** agent → relay: register a one-time pairing code. */
  | { t: 'pair_code'; code: string; ttlMs: number }
  | { t: 'pair_code_ok'; code: string; expiresAt: number }
  /** relay → agent: someone presented the code; reply with pair_response. */
  | { t: 'pair_request'; pairId: string }
  | { t: 'pair_response'; pairId: string; secret: string }
  /** relay → pairing socket, then closed. */
  | { t: 'paired'; agentId: string; secret: string; name?: string }
  /** client → agent (relay stamps clientId); `data` is an agent-protocol ClientMessage. */
  | { t: 'msg'; clientId: string; data: unknown }
  /** agent → client(s); `to` limits delivery to one client; `data` is an AgentMessage. */
  | { t: 'msg'; data: unknown; to?: string };

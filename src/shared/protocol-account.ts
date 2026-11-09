// Account-layer wire additions (task 10-13-relay-multitenant).
//
// Kept in a separate module so this task never has to touch the shared
// `protocol.ts` file while other agents have unreleased work in it. Everything
// here is additive and optional: a legacy agent or client that omits these
// fields observes byte-identical behavior, and PROTOCOL_VERSION stays 1.
//
// Mirrored by the Dart clients (apps/ and lib/); when they adopt account login
// these types must be mirrored in `lib/models/protocol.dart`.

/**
 * Account-bound client hello. A client may present a relay-issued access token
 * instead of the device secret; the relay then checks that the account is
 * actively bound to `agentId` (see design §5).
 */
export type AccountClientHello = {
  t: 'hello';
  role: 'client';
  agentId: string;
  relayToken: string;
  v?: number;
};

/**
 * Error code added to the relay's `{ t: 'error' }` envelope.
 *
 * Deliberately distinct from `unauthorized`: it means the account layer is
 * disabled, degraded or temporarily unreachable, so clients should retry
 * rather than discard their stored credentials.
 */
export type AccountRelayErrorCode =
  | 'bad_request'
  | 'unauthorized'
  | 'rate_limited'
  | 'agent_conflict'
  | 'agent_offline'
  | 'timeout'
  | 'account_unavailable';

/** Additive relay frames. Inert unless a client opts in. */
export type AccountRelayFrame =
  | { t: 'devices'; devices: { deviceId: string; label?: string; online: boolean }[] }
  | { t: 'accounts'; deviceId: string; accounts: { accountId: string; label?: string }[] }
  | { t: 'bind_revoked'; deviceId: string; accountId: string };

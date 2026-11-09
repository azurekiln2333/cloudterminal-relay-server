import type { AddressInfo } from 'node:net';
import { WebSocket } from 'ws';

import type { DbPool } from '../src/db/pool.ts';
import { createRelay, type Relay, type RelayOptions } from '../src/relay/relay.ts';
import { createTenancy } from '../src/relay/tenancy.ts';

/**
 * Relay options plus the account-layer knobs the tests configure.
 *
 * The relay takes an `AccountAuthorizer`, not a database, so the harness wires
 * `createTenancy` here: production does the same thing in `relay/main.ts`.
 */
export type TestRelayOptions = RelayOptions & {
  /** A ready pool (or an in-memory fake), or null for the legacy relay. */
  db?: DbPool | null;
  /** Cache TTL for binding decisions. */
  bindingCacheMs?: number;
};

export async function startRelay(opts: TestRelayOptions = {}): Promise<{ relay: Relay; url: string }> {
  const { db, bindingCacheMs, ...relayOptions } = opts;
  const accounts = relayOptions.accounts ?? createTenancy({ pool: db ?? null, bindingCacheMs });
  const relay = createRelay({ ...relayOptions, accounts });
  const server = await relay.listen(0, '127.0.0.1');
  const { port } = server.address() as AddressInfo;
  return { relay, url: `ws://127.0.0.1:${port}/ws` };
}

/** A WebSocket with an inbox so tests can await specific frames. */
export class TestSocket {
  readonly ws: WebSocket;
  private readonly inbox: any[] = [];
  private waiters: Array<{ pred: (f: any) => boolean; resolve: (f: any) => void }> = [];
  closed: Promise<{ code: number; reason: string }>;

  constructor(url: string) {
    this.ws = new WebSocket(url);
    this.ws.on('message', (raw) => {
      const frame = JSON.parse(raw.toString());
      const i = this.waiters.findIndex((w) => w.pred(frame));
      if (i >= 0) {
        const [w] = this.waiters.splice(i, 1);
        w!.resolve(frame);
      } else {
        this.inbox.push(frame);
      }
    });
    this.closed = new Promise((resolve) =>
      this.ws.on('close', (code, reason) => resolve({ code, reason: reason.toString() })),
    );
  }

  static async open(url: string): Promise<TestSocket> {
    const s = new TestSocket(url);
    await new Promise<void>((resolve, reject) => {
      s.ws.once('open', () => resolve());
      s.ws.once('error', reject);
    });
    return s;
  }

  send(frame: unknown): void {
    this.ws.send(JSON.stringify(frame));
  }

  next(pred: (f: any) => boolean = () => true, timeoutMs = 2000): Promise<any> {
    const i = this.inbox.findIndex(pred);
    if (i >= 0) return Promise.resolve(this.inbox.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const waiter = { pred, resolve: (f: any) => (clearTimeout(timer), resolve(f)) };
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        reject(new Error('timed out waiting for frame; inbox=' + JSON.stringify(this.inbox)));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  /** Resolves true if no matching frame arrives within `ms`. */
  async none(pred: (f: any) => boolean, ms = 150): Promise<boolean> {
    try {
      await this.next(pred, ms);
      return false;
    } catch {
      return true;
    }
  }

  close(): void {
    this.ws.close();
  }
}

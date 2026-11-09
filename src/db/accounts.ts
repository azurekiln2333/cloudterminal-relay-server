// Account cache: relay-side rows keyed by the gateway `sub` claim.
//
// The gateway is the identity source of truth; this table only caches the
// display name and records first/last seen. No password or email is stored
// (PRD R1).

import type { RowDataPacket } from 'mysql2';

import type { DbExecutor } from './pool.ts';

export type Account = {
  accountId: string;
  issuer: string;
  displayName: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type UpsertAccountInput = {
  accountId: string;
  issuer: string;
  displayName?: string | null;
};

type AccountRow = RowDataPacket & {
  account_id: string;
  issuer: string;
  display_name: string | null;
  created_at: Date;
  updated_at: Date;
};

function toAccount(row: AccountRow): Account {
  return {
    accountId: row.account_id,
    issuer: row.issuer,
    displayName: row.display_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Insert or refresh an account cache row. Idempotent on `account_id`. */
export async function upsertAccount(db: DbExecutor, input: UpsertAccountInput): Promise<void> {
  await db.execute(
    `insert into ct_accounts (account_id, issuer, display_name)
     values (?, ?, ?)
     on duplicate key update
       issuer = values(issuer),
       display_name = coalesce(values(display_name), ct_accounts.display_name)`,
    [input.accountId, input.issuer, input.displayName ?? null],
  );
}

export async function getAccount(db: DbExecutor, accountId: string): Promise<Account | null> {
  const rows = await db.query<AccountRow>(
    'select account_id, issuer, display_name, created_at, updated_at from ct_accounts where account_id = ?',
    [accountId],
  );
  const row = rows[0];
  return row ? toAccount(row) : null;
}

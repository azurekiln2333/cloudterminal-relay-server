// Binding registry: the many-to-many account <-> device relation.
//
// A binding is a row in `ct_bindings` with a status. Revoking one binding must
// not affect the device's other accounts (PRD R9/R10, AC4), so revocation is a
// per-row status flip rather than a delete.

import type { RowDataPacket } from 'mysql2';

import type { DbExecutor } from './pool.ts';

export type BindingRole = 'owner' | 'member';
export type BindingStatus = 'active' | 'revoked';
export type BindingCreatedBy = 'pair_code' | 'device_auth' | 'admin';

export type Binding = {
  id: number;
  accountId: string;
  deviceId: string;
  role: BindingRole;
  label: string | null;
  status: BindingStatus;
  createdBy: string;
  createdAt: Date;
  revokedAt: Date | null;
};

export type DeviceSummary = {
  deviceId: string;
  label: string | null;
  platform: string | null;
  role: BindingRole;
  deviceRevoked: boolean;
};

export type AccountSummary = {
  accountId: string;
  displayName: string | null;
  role: BindingRole;
  label: string | null;
};

export type CreateBindingInput = {
  accountId: string;
  deviceId: string;
  role?: BindingRole;
  label?: string | null;
  createdBy: BindingCreatedBy;
};

const ROLES = new Set<BindingRole>(['owner', 'member']);
const CREATED_BY = new Set<BindingCreatedBy>(['pair_code', 'device_auth', 'admin']);

function assertRole(role: string): BindingRole {
  if (!ROLES.has(role as BindingRole)) throw new Error(`invalid binding role: ${role}`);
  return role as BindingRole;
}

function assertCreatedBy(value: string): BindingCreatedBy {
  if (!CREATED_BY.has(value as BindingCreatedBy)) throw new Error(`invalid created_by: ${value}`);
  return value as BindingCreatedBy;
}

type BindingRow = RowDataPacket & {
  id: number;
  account_id: string;
  device_id: string;
  role: string;
  label: string | null;
  status: string;
  created_by: string;
  created_at: Date;
  revoked_at: Date | null;
};

function toBinding(row: BindingRow): Binding {
  return {
    id: Number(row.id),
    accountId: row.account_id,
    deviceId: row.device_id,
    role: assertRole(row.role),
    label: row.label,
    status: row.status === 'revoked' ? 'revoked' : 'active',
    createdBy: row.created_by,
    createdAt: row.created_at,
    revokedAt: row.revoked_at,
  };
}

/**
 * Create a binding, or reactivate an existing revoked one. Idempotent on the
 * `(account_id, device_id)` unique key. The account and device rows must
 * already exist (the foreign keys enforce this).
 */
export async function createBinding(db: DbExecutor, input: CreateBindingInput): Promise<void> {
  const role = input.role === undefined ? 'member' : assertRole(input.role);
  const createdBy = assertCreatedBy(input.createdBy);
  await db.execute(
    `insert into ct_bindings (account_id, device_id, role, label, status, created_by)
     values (?, ?, ?, ?, 'active', ?)
     on duplicate key update
       role = values(role),
       label = coalesce(values(label), ct_bindings.label),
       status = 'active',
       created_by = values(created_by),
       revoked_at = null`,
    [input.accountId, input.deviceId, role, input.label ?? null, createdBy],
  );
}

/** Active bindings of an account, joined with device metadata. */
export async function listDevicesForAccount(db: DbExecutor, accountId: string): Promise<DeviceSummary[]> {
  const rows = await db.query<
    RowDataPacket & {
      device_id: string;
      label: string | null;
      platform: string | null;
      role: string;
      device_revoked: number | null;
    }
  >(
    `select b.device_id, d.label, d.platform, b.role, (d.revoked_at is not null) as device_revoked
       from ct_bindings b
       join ct_devices d on d.device_id = b.device_id
      where b.account_id = ? and b.status = 'active'
      order by b.created_at asc`,
    [accountId],
  );
  return rows.map((row) => ({
    deviceId: row.device_id,
    label: row.label,
    platform: row.platform,
    role: assertRole(row.role),
    deviceRevoked: Number(row.device_revoked) === 1,
  }));
}

/** Active bindings of a device, joined with account metadata. */
export async function listAccountsForDevice(db: DbExecutor, deviceId: string): Promise<AccountSummary[]> {
  const rows = await db.query<
    RowDataPacket & {
      account_id: string;
      display_name: string | null;
      role: string;
      label: string | null;
    }
  >(
    `select b.account_id, a.display_name, b.role, b.label
       from ct_bindings b
       join ct_accounts a on a.account_id = b.account_id
      where b.device_id = ? and b.status = 'active'
      order by b.created_at asc`,
    [deviceId],
  );
  return rows.map((row) => ({
    accountId: row.account_id,
    displayName: row.display_name,
    role: assertRole(row.role),
    label: row.label,
  }));
}

/** Revoke exactly one binding; other bindings on the device are untouched. */
export async function revokeBinding(db: DbExecutor, accountId: string, deviceId: string): Promise<boolean> {
  const result = await db.execute(
    `update ct_bindings set status = 'revoked', revoked_at = current_timestamp
      where account_id = ? and device_id = ? and status = 'active'`,
    [accountId, deviceId],
  );
  return result.affectedRows > 0;
}

/** True when an active binding exists. Used by relay authorization (step 4). */
export async function isBound(db: DbExecutor, accountId: string, deviceId: string): Promise<boolean> {
  const rows = await db.query<RowDataPacket & { present: number }>(
    `select 1 as present from ct_bindings
      where account_id = ? and device_id = ? and status = 'active' limit 1`,
    [accountId, deviceId],
  );
  return rows.length > 0;
}

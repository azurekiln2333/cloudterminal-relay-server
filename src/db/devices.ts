// Device registry: one row per computer (agentId).
//
// The device secret is stored only as `sha256(secret)` hex. Callers hash the
// secret before calling `upsertDevice`; this module never receives plaintext
// (PRD R17).

import type { RowDataPacket } from 'mysql2';

import type { DbExecutor } from './pool.ts';

export type Device = {
  deviceId: string;
  label: string | null;
  platform: string | null;
  secretHash: string;
  createdAt: Date;
  lastSeenAt: Date | null;
  revokedAt: Date | null;
};

export type UpsertDeviceInput = {
  deviceId: string;
  label?: string | null;
  platform?: string | null;
  secretHash: string;
};

type DeviceRow = RowDataPacket & {
  device_id: string;
  label: string | null;
  platform: string | null;
  secret_hash: string;
  created_at: Date;
  last_seen_at: Date | null;
  revoked_at: Date | null;
};

function toDevice(row: DeviceRow): Device {
  return {
    deviceId: row.device_id,
    label: row.label,
    platform: row.platform,
    secretHash: row.secret_hash,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    revokedAt: row.revoked_at,
  };
}

/**
 * Insert or refresh a device. The secret hash is replaced when provided (agent
 * rotation), and a previously revoked device is revived on re-registration.
 */
export async function upsertDevice(db: DbExecutor, input: UpsertDeviceInput): Promise<void> {
  await db.execute(
    `insert into ct_devices (device_id, label, platform, secret_hash, last_seen_at)
     values (?, ?, ?, ?, current_timestamp)
     on duplicate key update
       label = coalesce(values(label), ct_devices.label),
       platform = coalesce(values(platform), ct_devices.platform),
       secret_hash = values(secret_hash),
       last_seen_at = current_timestamp,
       revoked_at = null`,
    [input.deviceId, input.label ?? null, input.platform ?? null, input.secretHash],
  );
}

/** Record activity without touching the secret. */
export async function touchDevice(db: DbExecutor, deviceId: string): Promise<void> {
  await db.execute('update ct_devices set last_seen_at = current_timestamp where device_id = ?', [deviceId]);
}

export async function getDevice(db: DbExecutor, deviceId: string): Promise<Device | null> {
  const rows = await db.query<DeviceRow>(
    `select device_id, label, platform, secret_hash, created_at, last_seen_at, revoked_at
       from ct_devices where device_id = ?`,
    [deviceId],
  );
  const row = rows[0];
  return row ? toDevice(row) : null;
}

/** Soft-revoke (`revokedAt = now`) or revive (`revokedAt = null`) a device. */
export async function setRevoked(db: DbExecutor, deviceId: string, revoked: boolean): Promise<void> {
  await db.execute(
    'update ct_devices set revoked_at = case when ? then current_timestamp else null end where device_id = ?',
    [revoked, deviceId],
  );
}

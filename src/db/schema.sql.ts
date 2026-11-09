// Versioned DDL for the `ct_*` tables (design §3).
//
// Every statement is idempotent so migrations can be re-run safely. Keep
// statements as plain strings; the migration runner executes them one at a
// time and records the version.

export type Migration = {
  version: number;
  name: string;
  statements: readonly string[];
};

const V1_STATEMENTS: readonly string[] = [
  `create table if not exists ct_accounts (
     account_id     varchar(191) not null,
     issuer         varchar(255) not null,
     display_name   varchar(191) null,
     created_at     timestamp not null default current_timestamp,
     updated_at     timestamp not null default current_timestamp on update current_timestamp,
     primary key (account_id),
     key ct_accounts_issuer (issuer)
   ) engine=InnoDB default charset=utf8mb4`,

  `create table if not exists ct_devices (
     device_id      varchar(128) not null,
     label          varchar(191) null,
     platform       varchar(64)  null,
     secret_hash    char(64) not null,
     created_at     timestamp not null default current_timestamp,
     last_seen_at   timestamp null,
     revoked_at     timestamp null,
     primary key (device_id)
   ) engine=InnoDB default charset=utf8mb4`,

  `create table if not exists ct_bindings (
     id             bigint unsigned not null auto_increment,
     account_id     varchar(191) not null,
     device_id      varchar(128) not null,
     role           enum('owner','member') not null default 'member',
     label          varchar(191) null,
     status         enum('active','revoked') not null default 'active',
     created_by     varchar(64)  not null,
     created_at     timestamp not null default current_timestamp,
     revoked_at     timestamp null,
     primary key (id),
     unique key ct_bindings_account_device (account_id, device_id),
     key ct_bindings_device (device_id, status),
     constraint ct_bindings_account_fk foreign key (account_id) references ct_accounts(account_id) on delete cascade,
     constraint ct_bindings_device_fk  foreign key (device_id)  references ct_devices(device_id)  on delete cascade
   ) engine=InnoDB default charset=utf8mb4`,

  `create table if not exists ct_tokens (
     token_hash     char(64) not null,
     account_id     varchar(191) not null,
     device_id      varchar(128) null,
     kind           enum('access','refresh','device') not null,
     expires_at     timestamp not null,
     created_at     timestamp not null default current_timestamp,
     revoked_at     timestamp null,
     primary key (token_hash),
     key ct_tokens_account (account_id, kind),
     key ct_tokens_expiry (expires_at)
   ) engine=InnoDB default charset=utf8mb4`,

  `create table if not exists ct_oauth_states (
     state          varchar(128) not null,
     kind           enum('pkce','device') not null,
     code_verifier  varchar(128) null,
     device_id      varchar(128) null,
     user_code      varchar(32)  null,
     expires_at     timestamp not null,
     created_at     timestamp not null default current_timestamp,
     primary key (state),
     key ct_oauth_states_expiry (expires_at)
   ) engine=InnoDB default charset=utf8mb4`,
];

/** All migrations in ascending version order. */
export const MIGRATIONS: readonly Migration[] = [
  { version: 1, name: 'initial_ct_tables', statements: V1_STATEMENTS },
];

/** Bookkeeping table created before any versioned DDL runs. */
export const MIGRATIONS_TABLE_SQL = `create table if not exists ct_schema_migrations (
  version    int unsigned not null,
  name       varchar(191) not null,
  applied_at timestamp not null default current_timestamp,
  primary key (version)
) engine=InnoDB default charset=utf8mb4`;

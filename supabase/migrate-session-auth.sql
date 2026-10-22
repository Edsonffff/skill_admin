-- Add bearer session storage to an existing bigint-license database.
-- Run after migrate-usage-summary.sql and before enabling the session-based extension.
begin;

create extension if not exists pgcrypto;

create table if not exists public.sessions (
  id uuid primary key default gen_random_uuid(),
  license_id bigint not null references public.licenses(id) on delete cascade,
  device_id_hash text not null,
  refresh_token_hash text not null unique,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);

create index if not exists sessions_license_id_idx on public.sessions(license_id);
alter table public.sessions enable row level security;
revoke all on table public.sessions from public, anon, authenticated;
grant usage on schema public to service_role;
grant select, insert, update, delete on public.sessions to service_role;

commit;

-- Verify the existing bigint license key and session foreign key:
-- select table_name, column_name, data_type
-- from information_schema.columns
-- where table_schema = 'public' and table_name in ('licenses', 'sessions')
-- order by table_name, ordinal_position;

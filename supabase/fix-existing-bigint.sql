-- Use this when public.licenses already exists with id bigint/int8,
-- as in the original table shown in the Supabase Table Editor.

drop table if exists public.usage_events cascade;

alter table public.licenses add column if not exists key_hash text not null default '';
alter table public.licenses add column if not exists key_suffix text not null default '';
alter table public.licenses add column if not exists user_name text not null default '';
alter table public.licenses add column if not exists status text not null default 'active';
alter table public.licenses add column if not exists created_at timestamptz not null default now();
alter table public.licenses add column if not exists expires_at timestamptz;
alter table public.licenses add column if not exists last_used_at timestamptz;
alter table public.licenses add column if not exists device_id_hash text not null default '';
alter table public.licenses add column if not exists total_programs integer not null default 0;
alter table public.licenses add column if not exists solved_programs integer not null default 0;
alter table public.licenses add column if not exists lock_reason text not null default '';
alter table public.licenses add column if not exists locked_at timestamptz;

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'licenses' and column_name = 'license_key'
  ) then
    execute 'alter table public.licenses alter column license_key drop not null';
    execute $sql$
      update public.licenses
      set key_hash = encode(digest(upper(regexp_replace(license_key, '\s', '', 'g')), 'sha256'), 'hex'),
          key_suffix = right(upper(regexp_replace(license_key, '\s', '', 'g')), 4)
      where coalesce(license_key, '') <> '' and key_hash = ''
    $sql$;
  end if;
end $$;

create table public.usage_events (
  id uuid primary key default gen_random_uuid(),
  license_id bigint not null references public.licenses(id) on delete cascade,
  run_id text not null,
  event text not null check (event in ('run', 'ai_request', 'insert')),
  result text not null default 'unknown',
  language text not null default 'unknown',
  occurred_at timestamptz not null default now(),
  unique (license_id, run_id)
);

alter table public.licenses enable row level security;
alter table public.usage_events enable row level security;
revoke all on table public.licenses, public.usage_events from anon, authenticated;
grant usage on schema public to service_role;
grant select, insert, update, delete on public.licenses, public.usage_events to service_role;

create or replace function public.record_license_usage(
  p_license_id bigint,
  p_run_id text,
  p_event text,
  p_result text,
  p_language text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  inserted boolean := false;
  license_row public.licenses;
begin
  select * into license_row from public.licenses where id = p_license_id for update;
  if license_row.id is null then raise exception 'LICENSE_NOT_FOUND'; end if;
  if license_row.status <> 'active' or license_row.expires_at <= now() then raise exception 'LICENSE_NOT_ACTIVE'; end if;

  insert into public.usage_events (license_id, run_id, event, result, language)
  values (p_license_id, p_run_id, p_event, coalesce(p_result, 'unknown'), coalesce(p_language, 'unknown'))
  on conflict (license_id, run_id) do nothing;
  inserted := found;

  if inserted and p_event = 'run' then
    update public.licenses
    set total_programs = total_programs + 1,
        solved_programs = solved_programs + case when p_result = 'success' then 1 else 0 end,
        last_used_at = now()
    where id = p_license_id;
  elsif inserted then
    update public.licenses set last_used_at = now() where id = p_license_id;
  end if;

  select * into license_row from public.licenses where id = p_license_id;
  return jsonb_build_object(
    'duplicate', not inserted,
    'total_programs', license_row.total_programs,
    'solved_programs', license_row.solved_programs,
    'last_used_at', license_row.last_used_at
  );
end;
$$;

revoke all on function public.record_license_usage(bigint, text, text, text, text) from public, anon, authenticated;
grant execute on function public.record_license_usage(bigint, text, text, text, text) to service_role;

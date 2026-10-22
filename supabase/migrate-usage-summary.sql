-- Safe migration for the existing bigint licenses/usage_events database.
-- It preserves usage_events. Run once before deploying the summary-only API.
begin;
set local timezone = 'UTC';

select pg_catalog.pg_advisory_xact_lock(730019002::bigint);

create table if not exists public.usage_summary_migrations (
  version text primary key,
  applied_at timestamptz not null default now()
);
alter table public.usage_summary_migrations enable row level security;
revoke all on table public.usage_summary_migrations from public, anon, authenticated, service_role;

alter table public.licenses add column if not exists total_runs bigint not null default 0;
alter table public.licenses add column if not exists successful_runs bigint not null default 0;
alter table public.licenses add column if not exists last_activity_at timestamptz;

do $migration$
begin
  if not exists (select 1 from public.usage_summary_migrations where version = '001_usage_summary') then
    -- Preserve counters from the previous dashboard schema when present.
    if exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'licenses' and column_name = 'total_programs')
       and exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'licenses' and column_name = 'solved_programs') then
      execute 'update public.licenses set total_runs = greatest(total_runs, coalesce(total_programs, 0)), successful_runs = greatest(successful_runs, coalesce(solved_programs, 0))';
    end if;
    if to_regclass('public.usage_events') is not null then
      -- Existing counters are authoritative when they are ahead. The history
      -- backfill fills missing/zero counters without doubling known totals.
      update public.licenses as l
      set total_runs = greatest(l.total_runs, coalesce(h.total_runs, 0)),
          successful_runs = greatest(l.successful_runs, coalesce(h.successful_runs, 0)),
          last_activity_at = greatest(l.last_activity_at, h.last_activity_at)
      from (
        select license_id,
               count(*)::bigint as total_runs,
               count(*) filter (where succeeded)::bigint as successful_runs,
               max(last_run_at) as last_activity_at
        from (
          select license_id, run_id,
                 bool_or(result = 'success') as succeeded,
                 max(occurred_at) as last_run_at
          from public.usage_events
          where event = 'run' and run_id is not null
          group by license_id, run_id
        ) distinct_runs
        group by license_id
      ) h
      where l.id = h.license_id;
    end if;
    insert into public.usage_summary_migrations(version) values ('001_usage_summary');
  end if;
end;
$migration$;

alter table public.licenses enable row level security;
revoke all on table public.licenses from anon, authenticated;
grant usage on schema public to service_role;
grant select, insert, update, delete on public.licenses to service_role;

create or replace function public.record_license_usage(p_license_id bigint, p_result text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare license_row public.licenses;
begin
  if p_result not in ('success', 'failure') then raise exception 'INVALID_RESULT'; end if;
  select * into license_row from public.licenses where id = p_license_id for update;
  if license_row.id is null then raise exception 'LICENSE_NOT_FOUND'; end if;
  if license_row.status <> 'active' or license_row.expires_at is null or license_row.expires_at <= now() then
    raise exception 'LICENSE_NOT_ACTIVE';
  end if;
  update public.licenses
  set total_runs = total_runs + 1,
      successful_runs = successful_runs + case when p_result = 'success' then 1 else 0 end,
      last_activity_at = clock_timestamp(),
      last_used_at = clock_timestamp()
  where id = p_license_id;
  select * into license_row from public.licenses where id = p_license_id;
  return jsonb_build_object(
    'totalRuns', license_row.total_runs,
    'successfulRuns', license_row.successful_runs,
    'lastActivityAt', license_row.last_activity_at
  );
end;
$$;

create or replace function public.record_license_usage(
  p_license_id bigint, p_run_id text, p_event text, p_result text, p_language text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_event <> 'run' then raise exception 'INVALID_EVENT'; end if;
  return public.record_license_usage(p_license_id, p_result);
end;
$$;

revoke all on function public.record_license_usage(bigint, text) from public, anon, authenticated;
revoke all on function public.record_license_usage(bigint, text, text, text, text) from public, anon, authenticated;
grant execute on function public.record_license_usage(bigint, text) to service_role;
grant execute on function public.record_license_usage(bigint, text, text, text, text) to service_role;

commit;

-- Verify before removing old history later:
-- select id, total_runs, successful_runs, last_activity_at from public.licenses order by id;

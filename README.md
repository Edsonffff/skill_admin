# Local license and admin dashboard

This folder contains the Vercel-hosted license API and admin dashboard used by the browser extension. The API stores license records and three usage totals in Supabase. It no longer writes a row for every run. `server.cjs` is retained as a local filesystem-only development fallback; Vercel uses the files inside `api`.

## Deploy to Vercel

Set the Vercel project root to this `admin-dashboard` folder. Vercel automatically deploys functions inside the root `api` directory and serves the static files in `public`.

1. Create a Supabase project.
2. For a fresh project, open Supabase SQL Editor and run `supabase/schema.sql`. For the existing project shown in the screenshot, run `supabase/migrate-usage-summary.sql` and then `supabase/migrate-session-auth.sql`. Back up first and pause the old usage writer during cutover.
3. Create Vercel environment variables:

```text
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SECRET_KEY=your-server-only-secret-key
ADMIN_TOKEN=your-long-random-admin-token
SESSION_SIGNING_SECRET=your-long-random-session-signing-secret
REFRESH_TOKEN_TTL_DAYS=30
ACCESS_TOKEN_TTL_SECONDS=900
```

Use a Supabase secret key or legacy service-role key only in Vercel environment variables. Never put it in `public`, the browser extension, or source control; it bypasses Row Level Security. `SESSION_SIGNING_SECRET` must be at least 32 random characters and must remain stable across deployments.

4. Deploy the folder.
5. Open `https://your-project.vercel.app/admin`.
6. In the extension popup, set **License server URL** to `https://your-project.vercel.app`.

If you later use a custom domain instead of `*.vercel.app`, add that domain to `host_permissions` in the extension `manifest.json` and reload the extension.

The extension talks to the Vercel API, while only the Vercel API talks to Supabase.

### Existing database migration

Run this check before migration:

```sql
select to_regclass('public.licenses'), to_regclass('public.usage_events'),
       (select data_type from information_schema.columns where table_schema = 'public' and table_name = 'licenses' and column_name = 'id') as license_id_type;
```

Run `supabase/migrate-usage-summary.sql` for the existing bigint schema. It:

- adds `total_runs`, `successful_runs`, and `last_activity_at` to `licenses`;
- backfills from existing `usage_events` without double-counting counters already ahead;
- keeps `usage_events` untouched for rollback;
- installs the summary-only RPC and a compatibility overload for older clients;
- uses a migration ledger so rerunning it does not backfill again.

Then run `supabase/migrate-session-auth.sql`. It adds only the `sessions` table, keyed by the existing bigint `licenses.id`, so the extension can use short-lived bearer access tokens and rotating refresh tokens without changing the license schema.

Do **not** run the old destructive `fix-existing-bigint.sql`; it is now only a warning file. After deployment and verification, old `usage_events` can be archived or deleted manually if you no longer need rollback data.

After applying SQL, make sure the `public` schema is exposed in Supabase's Data API settings, then refresh the schema cache:

```sql
NOTIFY pgrst, 'reload schema';
NOTIFY pgrst, 'reload config';
```

## Local fallback

From the extension folder:

```bash
ADMIN_TOKEN=replace-this-token node admin-dashboard/server.cjs
```

Then open `http://127.0.0.1:8787/admin` and sign in with the same token. This fallback uses local JSON storage and is not the production deployment path.

For Windows PowerShell:

```powershell
$env:ADMIN_TOKEN = "replace-this-token"
node admin-dashboard/server.cjs
```

The default token is `dev-admin-token` for local testing only. The server binds to `127.0.0.1`, so it is not intended to be a public production licensing service.

## Workflow

1. Open the dashboard and generate a license.
2. Copy the generated key into the extension popup.
3. Activate it with the license key only. When the user opens a SkillRack page, the extension reads the visible logged-in account chip and binds the license to that account.
4. The extension validates the account-bound license before opening the helper and before protected actions. A different SkillRack account is rejected.
5. Successful and failed extension Run actions update `totalRuns`, `successfulRuns`, and `lastActivityAt` on the matching license. Run ID and language are accepted only for client compatibility and are not stored.
6. Lock or unlock a license from the dashboard. A locked license is blocked on the next validation.

Runtime state is intentionally excluded from source control. Do not put Gemini API keys, Supabase secret keys, or admin tokens in this folder.

### Usage semantics

The dashboard shows total accepted runs, successful runs, and last activity per license. Repeated accepted reports count again because no run IDs are stored. The endpoint is not idempotent; do not automatically retry an ambiguous response. Missing reports caused by a client/network failure are not recoverable from history after cutover.

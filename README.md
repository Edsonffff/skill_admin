# Local license and admin dashboard

This folder contains the Vercel-hosted license API and admin dashboard used by the browser extension. The API stores licenses and usage events in Supabase. `server.cjs` is retained as a local filesystem-only development fallback; Vercel uses the files inside `api`.

## Deploy to Vercel

Set the Vercel project root to this `admin-dashboard` folder. Vercel automatically deploys functions inside the root `api` directory and serves the static files in `public`.

1. Create a Supabase project.
2. Open Supabase SQL Editor and run `supabase/schema.sql`.
3. Create Vercel environment variables:

```text
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SECRET_KEY=your-server-only-secret-key
ADMIN_TOKEN=your-long-random-admin-token
```

Use a Supabase secret key or legacy service-role key only in Vercel environment variables. Never put it in `public`, the browser extension, or source control; it bypasses Row Level Security.

4. Deploy the folder.
5. Open `https://your-project.vercel.app/admin`.
6. In the extension popup, set **License server URL** to `https://your-project.vercel.app`.

If you later use a custom domain instead of `*.vercel.app`, add that domain to `host_permissions` in the extension `manifest.json` and reload the extension.

The extension talks to the Vercel API, while only the Vercel API talks to Supabase.

### If the dashboard says `public.usage_events` is missing

Run this check in Supabase SQL Editor:

```sql
select to_regclass('public.licenses'), to_regclass('public.usage_events');
```

If either value is `null`, run `supabase/schema.sql` for a fresh database. If your existing `licenses.id` column is `int8`/`bigint` like the original table, run `supabase/fix-existing-bigint.sql` instead. If both tables exist, make sure the `public` schema is exposed in Supabase's Data API settings, then refresh the schema cache:

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
5. Successful and failed extension Run actions are recorded as `programsSolved` and `programsDone`.
6. Lock or unlock a license from the dashboard. A locked license is blocked on the next validation.

Runtime state is intentionally excluded from source control. Do not put Gemini API keys, Supabase secret keys, or admin tokens in this folder.

# Keymaker

> *The Keymaker makes the keys.* — environment & secret management for CiteMed.

A small server where developers and AI agents read key/values per **environment**
(staging, production, per-dev, local); admins update them. Secrets are
**encrypted at rest**. A **Dokku sync client** pushes changes to the right app,
and a **reconcile client** finds env bloat by diffing the store against a
codebase.

- **UI** — env tabs + a side-by-side **compare matrix** (keys down the left, one
  column per environment, differing rows highlighted), plus a **Cleanup** view of
  suspected-unused keys.
- **Auth** — a shared team password for the UI today (Bitbucket OAuth wired but
  dormant); bearer **API tokens** for agents and the clients.
- **Stack** — Django + DRF, Postgres, server-rendered templates + HTMX/Alpine.

## Two clients (`client/`)

- **`dokku_sync.py`** — runs on a Dokku host; applies env changes via
  `dokku config:set`. See [`client/README.md`](client/README.md).
- **`keymaker_scan.py`** — the **env-bloat reconciler**. Pulls an environment's
  keys, scans a codebase (and optionally its installed packages) for references,
  and classifies each key **used / unused / uncertain**, plus **missing** (read
  in code but absent from the store). Ambiguous keys (dynamic access, prefix
  siblings like `AWS_*`) go to an optional Claude tie-breaker. With `--submit` it
  flags unused keys in the store (a human prunes them in the Cleanup UI — it
  never deletes). See [`client/RECONCILE.md`](client/RECONCILE.md).

  ```bash
  KEYMAKER_URL=https://keymaker.citemed.com KEYMAKER_TOKEN=... KEYMAKER_ENV=staging \
    python3 client/keymaker_scan.py --path ../citemed_web \
      --packages ../citemed_web/.venv --llm --submit
  ```

  The cleanup process: reconcile in CI → flag orphans (don't auto-delete) →
  humans review flagged keys in the Cleanup UI after a grace period → delete.

## Run locally

```bash
cp .env.example .env
# generate a master key and paste it into .env as KEYMAKER_MASTER_KEY:
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

docker compose up --build
```

Open http://localhost:8000 (the committed compose maps host **8010** here to
avoid a local port clash — adjust `docker-compose.yml` if 8000 is free for you).
Log in with the **shared password** (`KEYMAKER_SHARED_PASSWORD`) — everyone who
enters is an admin (per-user Bitbucket OAuth is wired but dormant until
configured). `SEED_DEMO=1` seeds staging/production/local environments so the
compare matrix has data immediately.

Run tests:

```bash
docker compose exec web python manage.py test vars
```

## Configuration (env vars)

| Var | Purpose |
| --- | --- |
| `KEYMAKER_MASTER_KEY` | Fernet key(s), comma-separated. **First is primary for new writes; keep old keys to decrypt during rotation. Back this up — losing it loses all secrets.** |
| `DJANGO_SECRET_KEY` | Django session/signing key |
| `DATABASE_URL` | Postgres connection string |
| `KEYMAKER_SHARED_PASSWORD` | Shared UI password (blank = passwordless). Everyone who logs in is an admin. |
| `KEYMAKER_ADMIN_USERNAMES` | Bitbucket usernames who get write access (only when OAuth is enabled) |
| `BITBUCKET_WORKSPACE` | Workspace slug (`citemed`) |
| `BITBUCKET_CLIENT_ID` / `BITBUCKET_CLIENT_SECRET` | OAuth consumer creds |
| `KEYMAKER_BASE_URL` | Public URL, used for the OAuth callback + CSRF origin |
| `KEYMAKER_MANAGED_KEYS` | Keys never synced/edited (default `DATABASE_URL,REDIS_URL`) |

## Roles

- **Admins** (everyone, under the shared-password login today): create
  environments/targets, edit variables, archive/restore, issue API tokens.
- Read access is for token holders and (once OAuth is on) non-admin users.

## Archive, never delete

Variables are **soft-deleted**: archiving records who/when/why and hides the key
from the active list, exports, and sync — but keeps the encrypted value. Each
environment page has an expandable **Archived** section to review and **Restore**.
Nothing is ever hard-deleted, so a mistaken removal is always recoverable.

## API (for agents & the sync client)

Authenticate with `Authorization: Bearer <token>`. Tokens are issued in the UI
(Tokens page), scoped to one environment or all, read-only or read/write. All
list/read endpoints serve **active** (non-archived) variables.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/environments/<slug>/revision` | Cheap change poll; `{revision}` + ETag |
| `GET` | `/api/v1/environments/<slug>/variables` | JSON; `?format=dotenv` for `.env` text; managed keys excluded unless `?include_managed=1` |
| `PUT` | `/api/v1/environments/<slug>/variables/<KEY>` | Upsert (needs write token). Body `{"value": "...", "is_secret": true}` |
| `DELETE` | `/api/v1/environments/<slug>/variables/<KEY>` | **Archives** the key (soft delete, restorable in UI). Optional body `{"reason": "..."}` |
| `POST` | `/api/v1/environments/<slug>/audit` | Reconciler submits scan results; flags unused (see `client/RECONCILE.md`) |

Example — pull an environment as a `.env` file:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://keymaker.citemed.com/api/v1/environments/staging/variables?format=dotenv"
```

UI users can also click **⬇ Download .env** on any environment page (with an
"incl. managed" toggle).

## For Claude / agents — quickstart

Keymaker is built to be driven by agents. The whole surface is one base URL + a
bearer token; everything below is copy-pasteable.

```bash
export KEYMAKER_URL=https://keymaker.citemed.com
export KEYMAKER_TOKEN=...   # issued in the UI → Tokens (scope + read/write)

# read an environment as JSON or .env
curl -s -H "Authorization: Bearer $KEYMAKER_TOKEN" "$KEYMAKER_URL/api/v1/environments/staging/variables"
curl -s -H "Authorization: Bearer $KEYMAKER_TOKEN" "$KEYMAKER_URL/api/v1/environments/staging/variables?format=dotenv"

# set / archive a key (write token)
curl -s -X PUT  -H "Authorization: Bearer $KEYMAKER_TOKEN" -H "Content-Type: application/json" \
  -d '{"value":"abc","is_secret":true}' "$KEYMAKER_URL/api/v1/environments/staging/variables/MY_KEY"
curl -s -X DELETE -H "Authorization: Bearer $KEYMAKER_TOKEN" \
  -d '{"reason":"removed in PR #123"}' "$KEYMAKER_URL/api/v1/environments/staging/variables/MY_KEY"
```

Two CLIs in `client/` (stdlib-only, run with `python3`, each has `--help`):

- **`keymaker_scan.py`** — reconcile a codebase against an environment; finds
  unused (bloat) and missing keys. `--json` for CI gating. See `client/RECONCILE.md`.
- **`dokku_sync.py`** — apply an environment to a Dokku app. See `client/README.md`.

Agent rules of thumb: use a **read-only** token for scanning/reading and a
**write** token only when mutating; `DELETE` archives (recoverable), it never
destroys; `revision` is a cheap change check before doing expensive work.

## Dokku sync client

See [`client/README.md`](client/README.md). It runs on each Dokku host, polls
`/revision`, and applies changes via `dokku config:set` — never touching
`DATABASE_URL`/`REDIS_URL`.

## Deploying on Dokku

Deploys as its own app with its own Postgres (same playbook as the other CiteMed
apps in `citemed_web/infra/dokku/`):

```bash
dokku apps:create keymaker
dokku postgres:create keymaker-db && dokku postgres:link keymaker-db keymaker
dokku config:set keymaker \
  KEYMAKER_MASTER_KEY=... DJANGO_SECRET_KEY=... \
  KEYMAKER_ADMIN_USERNAMES=... BITBUCKET_CLIENT_ID=... BITBUCKET_CLIENT_SECRET=... \
  KEYMAKER_BASE_URL=https://keymaker.citemed.com DJANGO_ALLOWED_HOSTS=keymaker.citemed.com
dokku domains:add keymaker keymaker.citemed.com
dokku letsencrypt:enable keymaker
# then `git push dokku main` (Dockerfile deploy)
```

Register the Bitbucket OAuth consumer under the `citemed` workspace with callback
`https://keymaker.citemed.com/oauth/callback`.

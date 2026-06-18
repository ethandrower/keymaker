# Keymaker

> *The Keymaker makes the keys.* — environment & secret management for CiteMed.

A small server where developers and AI agents read key/values per **environment**
(staging, production, per-dev, local); admins update them. Secrets are
**encrypted at rest**. A **Dokku sync client** pushes changes to the right app,
and a **reconcile client** finds env bloat by diffing the store against a
codebase.

- **UI** — env tabs + a side-by-side **compare matrix** (keys down the left, one
  column per environment, differing rows highlighted), plus a **Cleanup** view of
  suspected-unused keys. Variables are **grouped by label** and show their
  **scope** (all targets, or a per-target override).
- **Auth** — **one key** (`KEYMAKER_KEY`). Paste it to log into the UI, or send it
  as `Authorization: Bearer <key>` from agents/CLIs. Everyone who has it is an
  admin. No per-agent tokens, no scopes, no external identity provider. Rotate by
  changing the env var.
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
  KEYMAKER_URL=https://keymaker.citemed.com KEYMAKER_KEY=... KEYMAKER_ENV=staging \
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
Log in with your **`KEYMAKER_KEY`** (or leave it blank locally for passwordless
entry). `SEED_DEMO=1` seeds demo environments so the compare matrix has data
immediately.

Run tests:

```bash
docker compose exec web python manage.py test vars
```

## Configuration (env vars)

| Var | Purpose |
| --- | --- |
| `KEYMAKER_MASTER_KEY` | Fernet key(s), comma-separated. **First is primary for new writes; keep old keys to decrypt during rotation. Back this up — losing it loses all secrets.** |
| `KEYMAKER_KEY` | The single auth key for UI login **and** API bearer. Blank = open (local dev only); production MUST set a strong value. |
| `DJANGO_SECRET_KEY` | Django session/signing key |
| `DATABASE_URL` | Postgres connection string |
| `KEYMAKER_BASE_URL` | Public URL, used as the CSRF trusted origin in production |
| `KEYMAKER_MANAGED_KEYS` | Keys never synced/edited (default `DATABASE_URL,REDIS_URL`) |

## Auth — one key

There is a single secret, `KEYMAKER_KEY`. It logs you into the UI (paste it as the
password) and authenticates agents/CLIs as `Authorization: Bearer <key>`. Everyone
who holds it has full read/write/admin access. To rotate, change the env var and
restart. (Trade-off: no per-agent revocation or scoping — deliberately simple for
an internal tool. If you ever need per-user accountability, add an identity layer
in front; the code path is intentionally minimal.)

## Variable scope & labels

Each variable applies to **all targets** (the base value) or to **one target** (an
override). When resolving config for a target, the target-specific value wins over
the base — so you keep a shared `SECRET_KEY` but give one box its own `SITE_URL`.
Reads, exports, and the Dokku sync resolve per target via `?target=<label|dokku_app>`
(the sync client defaults the target to the Dokku app name).

Variables also carry an optional **label** (e.g. "Django", "Mail") that sections
the variable table for visual context — purely organizational, no ownership implied.

## Archive, never delete

Variables are **soft-deleted**: archiving records who/when/why and hides the key
from the active list, exports, and sync — but keeps the encrypted value. Each
environment page has an expandable **Archived** section to review and **Restore**.
Nothing is ever hard-deleted, so a mistaken removal is always recoverable.

## API (for agents & the sync client)

Authenticate with `Authorization: Bearer <KEYMAKER_KEY>` — the same key you log in
with. All list/read endpoints serve **active** (non-archived) variables.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/environments/<slug>/revision` | Cheap change poll; `{revision}` + ETag |
| `GET` | `/api/v1/environments/<slug>/variables` | JSON; `?format=dotenv` for `.env` text; managed keys excluded unless `?include_managed=1` |
| `PUT` | `/api/v1/environments/<slug>/variables/<KEY>` | Upsert. Body `{"value": "...", "is_secret": true}` |
| `DELETE` | `/api/v1/environments/<slug>/variables/<KEY>` | **Archives** the key (soft delete, restorable in UI). Optional body `{"reason": "..."}` |
| `POST` | `/api/v1/environments/<slug>/audit` | Reconciler submits scan results; flags unused (see `client/RECONCILE.md`) |

Example — pull an environment as a `.env` file:

```bash
curl -H "Authorization: Bearer $KEYMAKER_KEY" \
  "https://keymaker.citemed.com/api/v1/environments/staging/variables?format=dotenv"
```

UI users can also click **⬇ Download .env** on any environment page (with an
"incl. managed" toggle).

## For Claude / agents — quickstart

Keymaker is built to be driven by agents. The whole surface is one base URL + the
one key; everything below is copy-pasteable.

```bash
export KEYMAKER_URL=https://keymaker.citemed.com
export KEYMAKER_KEY=...   # the same key humans log in with

# read an environment as JSON or .env
curl -s -H "Authorization: Bearer $KEYMAKER_KEY" "$KEYMAKER_URL/api/v1/environments/staging/variables"
curl -s -H "Authorization: Bearer $KEYMAKER_KEY" "$KEYMAKER_URL/api/v1/environments/staging/variables?format=dotenv"

# set / archive a key
curl -s -X PUT  -H "Authorization: Bearer $KEYMAKER_KEY" -H "Content-Type: application/json" \
  -d '{"value":"abc","is_secret":true}' "$KEYMAKER_URL/api/v1/environments/staging/variables/MY_KEY"
curl -s -X DELETE -H "Authorization: Bearer $KEYMAKER_KEY" \
  -d '{"reason":"removed in PR #123"}' "$KEYMAKER_URL/api/v1/environments/staging/variables/MY_KEY"
```

Two CLIs in `client/` (stdlib-only, run with `python3`, each has `--help`); both
read `KEYMAKER_KEY` from the environment:

- **`keymaker_scan.py`** — reconcile a codebase against an environment; finds
  unused (bloat) and missing keys. `--json` for CI gating. See `client/RECONCILE.md`.
- **`dokku_sync.py`** — apply an environment to a Dokku app. See `client/README.md`.

Agent rules of thumb: `DELETE` archives (recoverable), it never destroys;
`revision` is a cheap change check before doing expensive work.

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
  DJANGO_DEBUG=0 KEYMAKER_MASTER_KEY=... DJANGO_SECRET_KEY=... \
  KEYMAKER_KEY=<strong-key> \
  KEYMAKER_BASE_URL=https://keymaker.citemed.com DJANGO_ALLOWED_HOSTS=keymaker.citemed.com
dokku domains:set keymaker keymaker.citemed.com
# then `git push dokku main` (Dockerfile deploy), then:
dokku letsencrypt:enable keymaker
```

**Back up `KEYMAKER_MASTER_KEY`** in the team password manager — it's not
recoverable and decrypts every stored secret.

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
| `KEYMAKER_KEY` | The single auth key for UI login **and** API bearer (`km_…`). **Not** the master key above — mixing the two is the usual cause of a `401`. Blank = open (local dev only); production MUST set a strong value. |
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
| `GET` | `/api/v1/inventory` | One-shot fleet snapshot: every env + its servers (targets), revision, var counts, latest drift per server. **Names/counts only, no values.** `?include_archived=1` |
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

Keymaker is built to be driven by agents: one base URL, one key, native MCP tools.
Setup is **once per machine** and takes a minute.

### 1. Get the right key

`KEYMAKER_KEY` is the **API bearer token / UI password**. It starts with `km_`.

> **Don't confuse it with `KEYMAKER_MASTER_KEY`** — the 44-character Fernet key
> ending in `=` that encrypts values at rest. They are different secrets with
> similar names. Sending the master key as the bearer gets you
> `401 {"error": "Invalid or missing key"}`, which is the single most common
> setup failure.

Ask an admin, or read it off the host:

```bash
ssh dokku@<keymaker-host> config:get keymaker KEYMAKER_KEY
```

### 2. Give every Claude session the key

Add it to `~/.claude/settings.json`. This reaches **all projects and all agents on
the machine**, including sessions not launched from an interactive shell:

```json
{
  "env": { "KEYMAKER_KEY": "km_your_key_here" }
}
```

```bash
chmod 600 ~/.claude/settings.json
```

A `export KEYMAKER_KEY=...` in `~/.zshrc` also works, but only for sessions started
from a shell that sourced it — background jobs and some IDE launches miss it.

### 3. Register the MCP server

**Per repo** (commit it — the key stays out of the file). Create `.mcp.json` in the
repo root; Claude Code picks it up automatically:

```json
{
  "mcpServers": {
    "keymaker": {
      "type": "http",
      "url": "https://keymaker.citemed.com/mcp",
      "headers": { "Authorization": "Bearer ${KEYMAKER_KEY}" }
    }
  }
}
```

**Or once for every project on the machine:**

```bash
claude mcp add --scope user --transport http keymaker \
  https://keymaker.citemed.com/mcp -H 'Authorization: Bearer ${KEYMAKER_KEY}'
```

Keep the literal `${KEYMAKER_KEY}` — Claude Code expands it per session, so the
secret never lands in a config file or a repo.

### 4. Verify

```bash
# 200 = working, 401 = wrong or missing key
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $KEYMAKER_KEY" https://keymaker.citemed.com/api/v1/inventory
```

In Claude Code, `/mcp` should list **keymaker** as connected. Then just ask:
*"what environments exist in keymaker?"*

**Restart the session after changing the key or the MCP config** — running sessions
pick up neither.

| Symptom | Cause |
| --- | --- |
| `401 Invalid or missing key` | Master key used instead of the `km_` bearer, or `KEYMAKER_KEY` was unset when the session started |
| `keymaker` missing from `/mcp` | Config added after the session started — restart it |
| Server receives a literal `${KEYMAKER_KEY}` | The var isn't in the session's environment — use the `settings.json` `env` block in step 2 |

### REST, if you'd rather curl

```bash
export KEYMAKER_URL=https://keymaker.citemed.com

# read an environment as JSON or .env
curl -s -H "Authorization: Bearer $KEYMAKER_KEY" "$KEYMAKER_URL/api/v1/environments/staging/variables"
curl -s -H "Authorization: Bearer $KEYMAKER_KEY" "$KEYMAKER_URL/api/v1/environments/staging/variables?format=dotenv"

# set / archive a key
curl -s -X PUT  -H "Authorization: Bearer $KEYMAKER_KEY" -H "Content-Type: application/json" \
  -d '{"value":"abc","is_secret":true}' "$KEYMAKER_URL/api/v1/environments/staging/variables/MY_KEY"
curl -s -X DELETE -H "Authorization: Bearer $KEYMAKER_KEY" \
  -d '{"reason":"removed in PR #123"}' "$KEYMAKER_URL/api/v1/environments/staging/variables/MY_KEY"
```

### MCP tools

Keymaker speaks **MCP** at `POST /mcp` (streamable HTTP transport) — not a separate
process, just one more route in the same Django app behind the same bearer key.

Tools exposed (discoverable via `tools/list`):

| Tool | Does |
| --- | --- |
| `keymaker_inventory` | Whole-fleet snapshot — envs, servers, revisions, var counts, drift. **No values.** Start here. |
| `keymaker_list_environments` | Lighter env list (slug, name, revision). |
| `keymaker_get_variables` | Resolved key/values for an env (optional `target`, `include_managed`). |
| `keymaker_check_revision` | Current revision — cheap change check. |
| `keymaker_set_variable` | Upsert a key (optional `target`, `label`). Bumps revision. |
| `keymaker_archive_variable` | Soft-delete a key (restorable in the UI). Bumps revision. |

The MCP tools wrap the same logic as the REST API, so behavior never diverges:
managed keys (`DATABASE_URL`/`REDIS_URL`) are read-only, `archive` never destroys,
and the inventory tool returns key *names* and counts only — never secret values.

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

## Drift detection

A scheduled job compares each target's **live** Dokku config against what Keymaker
holds and records the differences as `DriftCheck` rows (key **names** only, never
values). Every environment page then shows, per key, how it compares to each box
it belongs on — in sync, value differs, in Keymaker but not on the box, on the box
but not in Keymaker, or **not checked** (no check in 48h; never rendered as green).

Three actions close the loop, all from the environment page:

| Situation | Action | What it does |
|---|---|---|
| On the box, not in Keymaker | **Store in Keymaker** | Reads the live value off the box and stores it (checks carry names only, so this is the one path that fetches a value from a server) |
| On the box, and we don't want it | **Ignore** | Records a reversible decision so deploy-injected keys stop being reported |
| In Keymaker, box missing it or disagreeing | **send →** | `dokku config:set --no-restart` — the value lands now, the app picks it up on its next restart or deploy |

Adopt and push re-run the check on the box they touched, so the status you land
back on is measured rather than assumed. Only keys a check actually flagged can
be pushed, so this can't be used to blanket-overwrite a box.

- **Schedule** — defined in [`app.json`](app.json)'s `cron` block (daily 07:00
  UTC), applied automatically by Dokku on deploy. No host crontab to maintain.
  Verify with `dokku cron:list keymaker`; run on demand with
  `dokku run keymaker python manage.py drift_check`.
- **SSH access** — the command SSHes into each Dokku host as a restricted `dokku`
  user. Set `KEYMAKER_SSH_KEY_B64` (base64 of the private key) on the Keymaker
  app, and run [`client/setup-drift.sh`](client/setup-drift.sh) **once** to
  register the matching public key on the hosts. Without this, drift checks
  record an error instead of data.
- **Working on this locally** — `KEYMAKER_SIM_BOX_DIR` (set for you in
  `docker-compose.yml`) points drift at a directory of `<host>__<app>.json` files
  instead of SSH, so the whole check → adopt → push loop works with no real hosts:

  ```bash
  docker compose exec web python manage.py seed_sim_boxes   # fake boxes with planted drift
  docker compose exec web python manage.py drift_check
  ```

  Production must never set this variable; `sim_dir()` is off unless it's present.

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

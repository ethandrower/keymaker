# Keymaker → Dokku sync client

`dokku_sync.py` applies a Keymaker environment's variables to a Dokku app with
`dokku config:set`. It **never** touches Dokku-managed keys (`DATABASE_URL`,
`REDIS_URL`, `PORT`, …) — those are excluded by the server and by a local safety
ignore-list. Pure Python stdlib — no pip install needed on the host.

Two ways to run it — pick one (or both):

| Mode | How | When env propagates |
| --- | --- | --- |
| **Runtime daemon** | `--watch 60` (systemd timer) on the Dokku host | continuously — a value edited in the UI lands within the poll interval, no redeploy |
| **Deploy-time** | `--once` from your deploy pipeline (Ansible, CI) | at each deploy only — env is pinned to the release |

`--help` documents every flag; config can come from flags or the `KEYMAKER_*` /
`DOKKU_*` env vars.

## Setup

1. Copy `dokku_sync.py` to the host (e.g. `/usr/local/bin/`).
2. Configure via env vars:

```bash
export KEYMAKER_URL=https://keymaker.citemed.com
export KEYMAKER_KEY=<the keymaker key>   # same key used to log into the UI
export KEYMAKER_ENV=staging          # environment slug
export DOKKU_APP=dev-ada             # target dokku app
# optional:
export SYNC_RESTART=1                 # restart app after changes (default on)
export SYNC_IGNORE=SOME_KEY,OTHER     # extra keys to never touch
```

## Usage

```bash
# Preview what would change without applying:
python3 dokku_sync.py --once --dry-run

# Apply once:
python3 dokku_sync.py --once

# Daemon: poll every 30s:
python3 dokku_sync.py --watch 30
```

The dry run prints the exact `dokku config:set` it would run, with **values
masked**, and confirms managed keys are left alone.

## Install as a systemd timer (recommended)

`/etc/systemd/system/keymaker-sync.service`:

```ini
[Unit]
Description=keymaker -> Dokku sync
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/keymaker-sync.env
ExecStart=/usr/bin/python3 /usr/local/bin/dokku_sync.py --once
User=root
```

`/etc/systemd/system/keymaker-sync.timer`:

```ini
[Unit]
Description=Run keymaker sync periodically

[Timer]
OnBootSec=60
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now keymaker-sync.timer
```

(`/etc/keymaker-sync.env` holds the `KEYMAKER_*` / `DOKKU_APP` vars above.)

## Deploy-time (build-side) integration

You already deploy via Ansible + Bitbucket Pipelines, so the natural build-side
hook is an Ansible task that runs `--once` on the Dokku host right before/after
the app deploy. Add to your `deploy*.yml`:

```yaml
- name: Sync env from Keymaker
  ansible.builtin.command:
    cmd: python3 /usr/local/bin/dokku_sync.py --once --force
  environment:
    KEYMAKER_URL: "https://keymaker.citemed.com"
    KEYMAKER_KEY: "{{ keymaker_key }}"       # from vault
    KEYMAKER_ENV: "{{ keymaker_env }}"       # e.g. staging
    DOKKU_APP: "{{ dokku_app }}"             # e.g. dev-ethan
  delegate_to: "{{ dokku_host }}"
```

This replaces the manual `env.j2` → `dokku config:set` step. `--force` applies
even if the revision is unchanged (deploys should be idempotent). Use `--dry-run`
in a check/--check run to preview.

> The host needs the `dokku` CLI, so run this **on the Dokku host** (the Ansible
> `delegate_to`/host you already target), not on the CI runner. If you must drive
> it from CI without local `dokku`, wrap it in `ssh <dokku-host> 'python3 …'`.

## How change detection works

The client stores the last-applied revision in
`~/.keymaker-sync-<env>.json` (override with `STATE_FILE`). Each run it compares
that to `GET /revision`; if unchanged it does nothing. Use `--force` to apply
regardless (deploy-time runs should pass `--force`).

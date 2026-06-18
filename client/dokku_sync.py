#!/usr/bin/env python3
"""keymaker → Dokku sync client.

Runs on a Dokku host. Polls keymaker for an environment's revision and, when it
changes, fetches the variables and applies them to the mapped Dokku app via
`dokku config:set`. Dokku-managed keys (DATABASE_URL, REDIS_URL) are excluded by
the server, and an extra local ignore-list is honored as a safety net.

Config via environment variables (or flags):
  KEYMAKER_URL        base URL, e.g. https://keymaker.citemed.com
  KEYMAKER_KEY        the Keymaker key (same one used to log into the UI)
  KEYMAKER_ENV        environment slug to sync, e.g. staging
  DOKKU_APP           target Dokku app name, e.g. dev-ethan
  DOKKU_BIN           path to dokku (default: dokku)
  SYNC_IGNORE         extra comma-separated keys to never touch
  SYNC_RESTART        "1" to restart the app after changes (default: 1)
  STATE_FILE          where to record the last-applied revision
                      (default: ~/.keymaker-sync-<env>.json)

Usage:
  python3 dokku_sync.py --once          # check + apply once, then exit
  python3 dokku_sync.py --watch 30      # poll every 30s
  python3 dokku_sync.py --once --dry-run
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ALWAYS_IGNORE = {"DATABASE_URL", "REDIS_URL", "PORT", "DOKKU_PROXY_PORT_MAP"}


def cfg(name, default=None):
    return os.environ.get(name, default)


def http_get(url, token, accept="application/json"):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "Accept": accept,
    })
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8"), resp.headers


def get_revision(base, env, token):
    body, _ = http_get(f"{base}/api/v1/environments/{env}/revision", token)
    return json.loads(body)["revision"]


def get_variables(base, env, token, target=None):
    """Return desired {KEY: VALUE} resolved for this target (base + overrides).
    Managed keys are excluded server-side."""
    url = f"{base}/api/v1/environments/{env}/variables"
    if target:
        url += "?target=" + urllib.parse.quote(target)
    body, _ = http_get(url, token)
    return json.loads(body)["variables"]


def dokku_current_config(dokku_bin, app):
    """Return current {KEY: VALUE} from the Dokku app."""
    out = subprocess.run(
        [dokku_bin, "config:export", "--format", "json", app],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        # Fall back to plain listing if config:export json isn't available.
        out2 = subprocess.run([dokku_bin, "config:export", "--format", "envfile", app],
                              capture_output=True, text=True)
        if out2.returncode != 0:
            raise RuntimeError(f"dokku config:export failed: {out.stderr or out2.stderr}")
        result = {}
        for line in out2.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip("'\"")
        return result
    return json.loads(out.stdout)


def state_path(env):
    return cfg("STATE_FILE") or os.path.expanduser(f"~/.keymaker-sync-{env}.json")


def load_state(env):
    try:
        with open(state_path(env)) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(env, revision):
    with open(state_path(env), "w") as fh:
        json.dump({"revision": revision}, fh)


def compute_changes(desired, current, ignore):
    """Return (to_set: dict, to_unset: list) excluding ignored keys."""
    to_set = {}
    for k, v in desired.items():
        if k in ignore:
            continue
        if current.get(k) != v:
            to_set[k] = v
    to_unset = [k for k in current if k not in desired and k not in ignore]
    return to_set, to_unset


def apply_changes(dokku_bin, app, to_set, to_unset, restart, dry_run):
    if not to_set and not to_unset:
        print("  no changes")
        return False
    cmds = []
    if to_set:
        pairs = [f"{k}={v}" for k, v in to_set.items()]
        cmds.append([dokku_bin, "config:set", "--no-restart", app, *pairs])
    if to_unset:
        cmds.append([dokku_bin, "config:unset", "--no-restart", app, *to_unset])
    if restart:
        cmds.append([dokku_bin, "ps:restart", app])

    for k in to_set:
        print(f"  set   {k}")
    for k in to_unset:
        print(f"  unset {k}")

    if dry_run:
        print("  [dry-run] would run:")
        for c in cmds:
            # Mask values in printed command.
            printable = [a.split("=")[0] + "=***" if "=" in a and not a.startswith("-") else a for a in c]
            print("    " + " ".join(printable))
        return False

    for c in cmds:
        res = subprocess.run(c, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"command failed: {' '.join(c[:3])}…: {res.stderr}")
    return True


def sync_once(args):
    base = args.url.rstrip("/")
    env = args.env
    ignore = ALWAYS_IGNORE | set(
        x.strip() for x in (cfg("SYNC_IGNORE", "") or "").split(",") if x.strip()
    )

    remote_rev = get_revision(base, env, args.key)
    last_rev = load_state(env).get("revision")
    if remote_rev == last_rev and not args.force:
        print(f"[{env}] revision {remote_rev} unchanged — nothing to do")
        return

    print(f"[{env}] revision {last_rev} → {remote_rev}; syncing app '{args.app}'")
    # Resolve for this target so per-target overrides win (defaults to the app name).
    desired = get_variables(base, env, args.key, target=args.target or args.app)
    current = dokku_current_config(args.dokku_bin, args.app)
    to_set, to_unset = compute_changes(desired, current, ignore)
    changed = apply_changes(args.dokku_bin, args.app, to_set, to_unset, args.restart, args.dry_run)
    if not args.dry_run:
        save_state(env, remote_rev)
        if changed:
            print(f"[{env}] applied {len(to_set)} set, {len(to_unset)} unset")


def main():
    p = argparse.ArgumentParser(
        description="Sync a Keymaker environment to a Dokku app via `dokku config:set`. "
                    "Run --once at deploy time, or --watch as a daemon. Managed keys "
                    "(DATABASE_URL, REDIS_URL) are never touched.",
        epilog="Config can also come from env vars: KEYMAKER_URL, KEYMAKER_KEY, "
               "KEYMAKER_ENV, DOKKU_APP, DOKKU_BIN, SYNC_RESTART, SYNC_IGNORE, STATE_FILE.",
    )
    p.add_argument("--url", default=cfg("KEYMAKER_URL"), help="Keymaker base URL (env: KEYMAKER_URL)")
    p.add_argument("--key", default=cfg("KEYMAKER_KEY"), help="Keymaker key (env: KEYMAKER_KEY)")
    p.add_argument("--env", default=cfg("KEYMAKER_ENV"), help="environment slug to sync (env: KEYMAKER_ENV)")
    p.add_argument("--app", default=cfg("DOKKU_APP"), help="target Dokku app name (env: DOKKU_APP)")
    p.add_argument("--target", default=cfg("KEYMAKER_TARGET"),
                   help="Keymaker target to resolve overrides for (label/dokku_app; default: --app)")
    p.add_argument("--dokku-bin", default=cfg("DOKKU_BIN", "dokku"), help="path to dokku (default: dokku)")
    p.add_argument("--restart", action="store_true", default=cfg("SYNC_RESTART", "1") == "1",
                   help="restart the app after changes (default: on)")
    p.add_argument("--no-restart", dest="restart", action="store_false",
                   help="apply config without restarting the app")
    p.add_argument("--dry-run", action="store_true",
                   help="print the dokku commands (values masked) without running them")
    p.add_argument("--force", action="store_true", help="apply even if the revision is unchanged")
    p.add_argument("--once", action="store_true", help="run a single sync and exit (use at deploy time)")
    p.add_argument("--watch", type=int, metavar="SECONDS", help="run as a daemon, polling every N seconds")
    args = p.parse_args()

    missing = [n for n in ("url", "key", "env", "app") if not getattr(args, n)]
    if missing:
        p.error("missing required config: " + ", ".join(missing))

    if args.watch:
        print(f"watching {args.env} every {args.watch}s (Ctrl-C to stop)")
        while True:
            try:
                sync_once(args)
            except (urllib.error.URLError, RuntimeError) as exc:
                print(f"error: {exc}", file=sys.stderr)
            time.sleep(args.watch)
    else:
        sync_once(args)


if __name__ == "__main__":
    main()

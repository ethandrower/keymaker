"""Shared drift-check logic — one target's live Dokku config vs. what Keymaker holds.

Used by both the scheduled `drift_check` management command and the on-demand
"Check now" buttons on the Checks page, so the two can never diverge. Reads a
target's live config over SSH, compares against Keymaker's resolved values, and
records a DriftCheck row (key NAMES only, never values).

Also the only place that *writes* to a box (`push_values`, used by "send to app
server"). Writes default to --no-restart: a click in a web UI must never bounce
production on its own.

SSH auth: a private key from config var KEYMAKER_SSH_KEY_B64 (base64), whose
public half is registered as a `dokku` ssh-key on each Dokku host (see
client/setup-drift.sh). Falls back to the ambient SSH config when unset.

Local development: set KEYMAKER_SIM_BOX_DIR to a directory of
`<host>__<app>.json` files and every read/write hits those files instead of
SSH, so the whole check → adopt → push → re-check loop is exercisable without a
real Dokku host. Unset in production, where it must stay unset.
"""
import base64
import json
import os
import shlex
import subprocess
import tempfile
import time

from .models import AuditLog, DriftCheck

# Keys Dokku sets/manages itself — surfaced for visibility but never compared or
# synced. Must match the sync client (client/dokku_sync.py) and the API.
SKIP = {"DATABASE_URL", "REDIS_URL", "PORT", "GIT_REV", "DATABASE_DEFAULT_URL"}
SKIP_PREFIX = ("DOKKU_",)


def meaningful(cfg):
    """Keys Keymaker actually owns and compares (drops Dokku-managed/auto keys)."""
    return {k: v for k, v in cfg.items() if k not in SKIP and not k.startswith(SKIP_PREFIX)}


def dokku_managed(cfg):
    """Dokku-owned/auto keys present on the box (complement of meaningful()).
    Surfaced so a change to the box's own config is never invisible; NAMES only,
    never fed into the drift comparison."""
    return sorted(k for k in cfg if k in SKIP or k.startswith(SKIP_PREFIX))


def build_ssh_base(key_path=None, connect_timeout=15):
    """Return (ssh_base_argv, tmp_key_path_or_None). Caller must os.unlink the
    tmp path when done. Uses KEYMAKER_SSH_KEY_B64 if no explicit key_path is given."""
    tmp = None
    if not key_path and os.environ.get("KEYMAKER_SSH_KEY_B64"):
        tmp = tempfile.NamedTemporaryFile("wb", suffix=".key", delete=False)
        tmp.write(base64.b64decode(os.environ["KEYMAKER_SSH_KEY_B64"]))
        tmp.close()
        os.chmod(tmp.name, 0o600)
        key_path = tmp.name
    base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={connect_timeout}"]
    if key_path:
        base += ["-i", key_path]
    return base, (tmp.name if tmp else None)


# --- simulated boxes (local dev only) -------------------------------------

def sim_dir():
    """Directory of fake box configs, or "" when we talk to real hosts."""
    return os.environ.get("KEYMAKER_SIM_BOX_DIR", "").strip()


def _sim_path(host, app):
    safe = f"{host}__{app}".replace("/", "_")
    return os.path.join(sim_dir(), f"{safe}.json")


def _sim_read(host, app):
    try:
        with open(_sim_path(host, app)) as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise RuntimeError(f"simulated box {host}/{app} does not exist")


def _sim_write(host, app, values):
    cfg = _sim_read(host, app)
    cfg.update(values)
    with open(_sim_path(host, app), "w") as fh:
        json.dump(cfg, fh, indent=2, sort_keys=True)


# --- real box I/O ---------------------------------------------------------

def dokku_config(ssh_base, host, app):
    """Return the full live {KEY: VALUE} for a Dokku app over SSH (json, envfile
    fallback). Raises RuntimeError if the read fails."""
    if sim_dir():
        return _sim_read(host, app)
    cmd = ssh_base + [f"dokku@{host}", "config:export", "--format", "json", app]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    if r.returncode == 0:
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            pass
    cmd = ssh_base + [f"dokku@{host}", "config:export", "--format", "envfile", app]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "ssh/dokku failed")
    cfg = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[7:]
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            cfg[k.strip()] = v.strip().strip("'\"")
    return cfg


def read_values(ssh_base, host, app, keys):
    """Pull the live values for specific keys off a box.

    Drift checks record key names only, so adopting an on-box key has to come
    back here for the value. Keys absent from the box are simply omitted — the
    caller reports them rather than storing an empty string as if it were real.
    """
    cfg = dokku_config(ssh_base, host, app)
    return {k: cfg[k] for k in keys if k in cfg}


def push_values(ssh_base, host, app, values, restart=False):
    """Set keys on a box: `dokku config:set [--no-restart] <app> K=V …`.

    The only write Keymaker makes to a box. Defaults to --no-restart so a UI
    click can't bounce production; the caller tells the user the app needs a
    restart or deploy for the change to take effect.
    """
    if not values:
        return
    bad = sorted(k for k, v in values.items() if "\n" in v or "\r" in v)
    if bad:
        # Dokku takes config over a single shell command line; a newline would
        # truncate the value on the box rather than fail loudly.
        raise RuntimeError(f"can't push multi-line values: {', '.join(bad)}")
    if sim_dir():
        _sim_write(host, app, values)
        return
    args = ["config:set"] + ([] if restart else ["--no-restart"]) + [app]
    args += [f"{k}={v}" for k, v in sorted(values.items())]
    cmd = ssh_base + [f"dokku@{host}"] + [shlex.quote(a) for a in args]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "dokku config:set failed")


def check_one(env, target, ssh_base, actor="drift-cron"):
    """Compare one target's live config to Keymaker, record a DriftCheck + audit
    entry, and return (drift_check, managed_added, managed_gone).

    Raises RuntimeError / subprocess.TimeoutExpired if the box can't be read —
    the caller decides whether to log-and-continue (cron) or surface it (UI)."""
    raw = dokku_config(ssh_base, target.host, target.dokku_app)
    live = meaningful(raw)
    managed = dokku_managed(raw)  # Dokku's own keys — surfaced, not compared
    km = {k: v.value for k, v in env.resolved_for(target).items() if not v.is_managed}
    on_box = sorted(set(live) - set(km))
    km_only = sorted(set(km) - set(live))
    mismatch = sorted(k for k in (set(live) & set(km)) if live[k] != km[k])
    in_sync = not (on_box or km_only or mismatch)
    # Compare Dokku-managed keys against the previous check so a change to the
    # box's own config surfaces even though we never sync it.
    prev = env.drift_checks.filter(target_label=target.label).first()
    prev_managed = set(prev.dokku_managed) if prev else set()
    mgd_added = sorted(set(managed) - prev_managed)
    mgd_gone = sorted(prev_managed - set(managed))
    dc = DriftCheck.objects.create(
        environment=env, target_label=target.label,
        on_box_only=on_box, in_keymaker_only=km_only,
        value_mismatch=mismatch, dokku_managed=managed, in_sync=in_sync,
    )
    mgd_note = ""
    if prev and (mgd_added or mgd_gone):
        mgd_note = f"; dokku-managed +{len(mgd_added)}/-{len(mgd_gone)}"
    AuditLog.record(
        actor=actor, action="drift_check", environment=env.slug,
        detail=(f"{target.label}: " + ("in sync" if in_sync else
                f"{len(on_box)} new on box, {len(km_only)} missing, {len(mismatch)} changed")
                + mgd_note),
    )
    return dc, mgd_added, mgd_gone


def run_checks(env, targets, actor, budget_s=22.0, connect_timeout=8):
    """Check a list of targets now, bounded by a wall-clock budget.

    Shared by the Checks page, the environment page, and every write action
    (adopt/push re-check the box they just touched, so the status a user sees
    afterwards is a fresh measurement rather than an optimistic assumption).

    Returns (checked_labels, errors, not_reached).
    """
    targets = [t for t in targets if t.host and t.dokku_app]
    if not targets:
        return [], [], 0
    ssh_base, tmp = build_ssh_base(connect_timeout=connect_timeout)
    start = time.monotonic()
    checked, errors, not_reached = [], [], 0
    try:
        for t in targets:
            if time.monotonic() - start > budget_s:
                not_reached = len(targets) - len(checked) - len(errors)
                break
            try:
                check_one(env, t, ssh_base, actor=actor)
                checked.append(t.label)
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                errors.append(f"{t.label}: {str(exc)[:200]}")
    finally:
        if tmp:
            os.unlink(tmp)
    return checked, errors, not_reached

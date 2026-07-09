"""Shared drift-check logic — one target's live Dokku config vs. what Keymaker holds.

Used by both the scheduled `drift_check` management command and the on-demand
"Check now" buttons on the Checks page, so the two can never diverge. Reads a
target's live config over SSH, compares against Keymaker's resolved values, and
records a DriftCheck row (key NAMES only, never values).

SSH auth: a private key from config var KEYMAKER_SSH_KEY_B64 (base64), whose
public half is registered as a `dokku` ssh-key on each Dokku host (see
client/setup-drift.sh). Falls back to the ambient SSH config when unset.
"""
import base64
import json
import os
import subprocess
import tempfile

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


def dokku_config(ssh_base, host, app):
    """Return the full live {KEY: VALUE} for a Dokku app over SSH (json, envfile
    fallback). Raises RuntimeError if the read fails."""
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

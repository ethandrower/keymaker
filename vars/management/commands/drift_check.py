"""Drift detection — runs ON the Keymaker host (cron/scheduler).

Walks every active environment's targets, SSHes to each target's Dokku host to read
its LIVE config, and compares against what Keymaker holds (resolved for that
target). Differences are recorded as DriftCheck rows (key NAMES only, never
values) so the Checks page can show new keys set directly on boxes, missing keys,
and value drift — plus prove the check ran.

No remote client or distributed key: Keymaker already stores each target's host +
dokku_app, so it knows exactly what to check.

SSH: set config var KEYMAKER_SSH_KEY_B64 (base64 of a private key authorized as a
`dokku` ssh-key on the Dokku hosts). Falls back to the ambient SSH config.

Schedule on the Keymaker host, e.g. daily:
    0 7 * * *  dokku run keymaker python manage.py drift_check
"""
import base64
import json
import os
import subprocess
import tempfile

from django.core.management.base import BaseCommand

from vars.models import AuditLog, DriftCheck, Environment

SKIP = {"DATABASE_URL", "REDIS_URL", "PORT", "GIT_REV", "DATABASE_DEFAULT_URL"}
SKIP_PREFIX = ("DOKKU_",)


def _meaningful(cfg):
    return {k: v for k, v in cfg.items() if k not in SKIP and not k.startswith(SKIP_PREFIX)}


def _ssh_base(key_path):
    base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15"]
    if key_path:
        base += ["-i", key_path]
    return base


def _dokku_config(ssh_base, host, app):
    """Return the live {KEY: VALUE} for a Dokku app over SSH (json, envfile fallback)."""
    cmd = ssh_base + [f"dokku@{host}", "config:export", "--format", "json", app]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    if r.returncode == 0:
        try:
            return _meaningful(json.loads(r.stdout))
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
    return _meaningful(cfg)


class Command(BaseCommand):
    help = "Compare each target's live Dokku config to Keymaker and record drift."

    def add_arguments(self, parser):
        parser.add_argument("--env", help="only check this environment slug")
        parser.add_argument("--ssh-key", help="path to an SSH private key (overrides KEYMAKER_SSH_KEY_B64)")

    def handle(self, *args, **opts):
        key_path = opts.get("ssh_key")
        tmp = None
        if not key_path and os.environ.get("KEYMAKER_SSH_KEY_B64"):
            tmp = tempfile.NamedTemporaryFile("wb", suffix=".key", delete=False)
            tmp.write(base64.b64decode(os.environ["KEYMAKER_SSH_KEY_B64"]))
            tmp.close()
            os.chmod(tmp.name, 0o600)
            key_path = tmp.name
        ssh_base = _ssh_base(key_path)

        envs = Environment.objects.filter(archived=False)
        if opts.get("env"):
            envs = envs.filter(slug=opts["env"])

        checked = 0
        try:
            for env in envs:
                for target in env.targets.all():
                    if not target.host or not target.dokku_app:
                        continue  # nowhere to check
                    try:
                        live = _dokku_config(ssh_base, target.host, target.dokku_app)
                    except (RuntimeError, subprocess.TimeoutExpired) as exc:
                        self.stderr.write(f"  {env.slug}/{target.label}: SSH error — {exc}")
                        continue
                    km = {k: v.value for k, v in env.resolved_for(target).items() if not v.is_managed}
                    on_box = sorted(set(live) - set(km))
                    km_only = sorted(set(km) - set(live))
                    mismatch = sorted(k for k in (set(live) & set(km)) if live[k] != km[k])
                    in_sync = not (on_box or km_only or mismatch)
                    DriftCheck.objects.create(
                        environment=env, target_label=target.label,
                        on_box_only=on_box, in_keymaker_only=km_only,
                        value_mismatch=mismatch, in_sync=in_sync,
                    )
                    AuditLog.record(
                        actor="drift-cron", action="drift_check", environment=env.slug,
                        detail=(f"{target.label}: " + ("in sync" if in_sync else
                                f"{len(on_box)} new on box, {len(km_only)} missing, {len(mismatch)} changed")),
                    )
                    checked += 1
                    flag = "OK" if in_sync else f"DRIFT (+{len(on_box)} new, -{len(km_only)}, ~{len(mismatch)})"
                    self.stdout.write(f"  {env.slug}/{target.label}: {flag}"
                                      + (f"  new: {', '.join(on_box)}" if on_box else ""))
        finally:
            if tmp:
                os.unlink(tmp.name)
        self.stdout.write(self.style.SUCCESS(f"Checked {checked} target(s)."))

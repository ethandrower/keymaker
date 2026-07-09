"""Drift detection — runs ON the Keymaker host (cron/scheduler).

Walks every active environment's targets, SSHes to each target's Dokku host to read
its LIVE config, and compares against what Keymaker holds (resolved for that
target). Differences are recorded as DriftCheck rows (key NAMES only, never
values) so the Checks page can show new keys set directly on boxes, missing keys,
and value drift — plus prove the check ran.

The per-target comparison lives in vars/drift.py and is shared with the on-demand
"Check now" buttons on the Checks page, so the scheduled and manual paths never
diverge.

SSH: set config var KEYMAKER_SSH_KEY_B64 (base64 of a private key authorized as a
`dokku` ssh-key on the Dokku hosts). Falls back to the ambient SSH config.

Scheduled by Dokku from the `cron` block in app.json (daily 07:00 UTC) — no
host crontab needed. Verify with `dokku cron:list keymaker`. Run by hand any
time with `dokku run keymaker python manage.py drift_check`.
"""
import os
import subprocess

from django.core.management.base import BaseCommand

from vars import drift
from vars.models import Environment


class Command(BaseCommand):
    help = "Compare each target's live Dokku config to Keymaker and record drift."

    def add_arguments(self, parser):
        parser.add_argument("--env", help="only check this environment slug")
        parser.add_argument("--ssh-key", help="path to an SSH private key (overrides KEYMAKER_SSH_KEY_B64)")

    def handle(self, *args, **opts):
        ssh_base, tmp = drift.build_ssh_base(key_path=opts.get("ssh_key"))

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
                        dc, mgd_added, mgd_gone = drift.check_one(env, target, ssh_base)
                    except (RuntimeError, subprocess.TimeoutExpired) as exc:
                        self.stderr.write(f"  {env.slug}/{target.label}: SSH error — {exc}")
                        continue
                    checked += 1
                    flag = ("OK" if dc.in_sync else
                            f"DRIFT (+{len(dc.on_box_only)} new, -{len(dc.in_keymaker_only)}, ~{len(dc.value_mismatch)})")
                    self.stdout.write(f"  {env.slug}/{target.label}: {flag}"
                                      + (f"  new: {', '.join(dc.on_box_only)}" if dc.on_box_only else "")
                                      + (f"  dokku-managed changed: +{', '.join(mgd_added) or '—'}"
                                         f" -{', '.join(mgd_gone) or '—'}" if (mgd_added or mgd_gone) else ""))
        finally:
            if tmp:
                os.unlink(tmp)
        self.stdout.write(self.style.SUCCESS(f"Checked {checked} target(s)."))

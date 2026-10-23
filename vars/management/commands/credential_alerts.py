"""Credential expiry alerts — runs ON the Keymaker host (cron/scheduler).

Posts one Slack digest of every tracked credential that has moved into a new
warning stage (warn window, 7 days, 1 day, expired) since the last post, and
re-reminds about expired ones weekly. Quiet days post nothing.

Scheduled by Dokku from the `cron` block in app.json (daily 07:30 UTC). Run by
hand with `dokku run keymaker python manage.py credential_alerts --dry-run`.
"""
from django.core.management.base import BaseCommand

from vars import credentials


class Command(BaseCommand):
    help = "Post a Slack digest of credentials that are about to expire or have expired."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="print the digest, post nothing")

    def handle(self, *args, **opts):
        r = credentials.send_alerts(dry_run=opts["dry_run"])
        if not r["credentials"]:
            self.stdout.write("Nothing newly due.")
            return
        self.stdout.write(r["text"])
        if opts["dry_run"]:
            self.stdout.write("(dry run: not posted)")
        elif r["posted"]:
            self.stdout.write(self.style.SUCCESS(f"Posted {len(r['credentials'])} credential(s)."))
        else:
            self.stdout.write(self.style.WARNING(
                "Not posted (Slack unset or the post failed); will retry on the next run."))

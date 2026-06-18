"""Seed a couple of demo environments for local development.

Idempotent: safe to run repeatedly. Uses placeholder hosts/values and shows off
the model: variables grouped by label, scoped to all-targets (base) or a single
target (override). All IPs/domains are documentation placeholders (TEST-NET /
example.com) — not real infrastructure.
"""
from django.conf import settings
from django.core.management.base import BaseCommand

from vars.models import Environment, Target, Variable


def V(key, value, *, secret=False, managed=False, group="", target=None):
    return {"key": key, "value": value, "secret": secret, "managed": managed,
            "group": group, "target": target}


DEMO = {
    "staging": {
        "name": "Staging",
        "kind": "shared",
        "description": "Shared staging box with per-dev apps under *.staging.example.com",
        "targets": [
            {"label": "dev-ada", "host": "203.0.113.10", "dokku_app": "dev-ada",
             "domain": "dev-ada.staging.example.com"},
            {"label": "dev-bo", "host": "203.0.113.10", "dokku_app": "dev-bo",
             "domain": "dev-bo.staging.example.com"},
        ],
        "vars": [
            # Base values shared by all targets
            V("ENV", "STAGING", group="Django"),
            V("SECRET_KEY", "staging-django-secret-abc123", secret=True, group="Django"),
            V("AWS_ACCESS_KEY_ID", "AKIASTAGINGEXAMPLE", secret=True, group="AWS / S3"),
            V("AWS_SECRET_ACCESS_KEY", "staging-aws-secret-xxxx", secret=True, group="AWS / S3"),
            V("MAILGUN_ACCESS_KEY", "key-staging-mailgun-xyz", secret=True, group="Mail"),
            V("DATABASE_URL", "postgres://auto@db/app", managed=True),  # Dokku-managed
            # Per-target overrides (differ per dev box)
            V("SITE_URL", "https://dev-ada.staging.example.com", group="Django", target="dev-ada"),
            V("ALLOWED_HOSTS", "dev-ada.staging.example.com,dev-ada", group="Django", target="dev-ada"),
            V("SITE_URL", "https://dev-bo.staging.example.com", group="Django", target="dev-bo"),
            V("ALLOWED_HOSTS", "dev-bo.staging.example.com,dev-bo", group="Django", target="dev-bo"),
        ],
    },
    "production": {
        "name": "Production",
        "kind": "shared",
        "description": "Single multi-tenant app at cloud.example.com",
        "targets": [
            {"label": "prod", "host": "203.0.113.20", "dokku_app": "web-production",
             "domain": "cloud.example.com"},
        ],
        "vars": [
            V("ENV", "PRODUCTION", group="Django"),
            V("SITE_URL", "https://cloud.example.com", group="Django"),
            V("ALLOWED_HOSTS", "cloud.example.com", group="Django"),
            V("SECRET_KEY", "prod-django-secret-DIFFERENT", secret=True, group="Django"),
            V("AWS_ACCESS_KEY_ID", "AKIAPRODEXAMPLE", secret=True, group="AWS / S3"),
            V("MAILGUN_ACCESS_KEY", "key-prod-mailgun-xyz", secret=True, group="Mail"),
            V("DATABASE_URL", "postgres://auto@db/app", managed=True),
        ],
    },
    "local": {
        "name": "Local dev",
        "kind": "local",
        "description": "Developer Docker Compose stack",
        "targets": [{"label": "localhost", "local_only": True}],
        "vars": [
            V("ENV", "LOCAL", group="Django"),
            V("SITE_URL", "http://localhost:8000", group="Django"),
            V("ALLOWED_HOSTS", "localhost,127.0.0.1", group="Django"),
            V("SECRET_KEY", "local-insecure-secret", secret=True, group="Django"),
        ],
    },
}


class Command(BaseCommand):
    help = "Seed demo environments, targets and variables (idempotent)."

    def handle(self, *args, **options):
        if not settings.KEYMAKER_MASTER_KEYS:
            self.stderr.write("KEYMAKER_MASTER_KEY not set — cannot encrypt values. Skipping.")
            return
        for slug, spec in DEMO.items():
            env, created = Environment.objects.get_or_create(
                slug=slug,
                defaults={"name": spec["name"], "kind": spec["kind"],
                          "description": spec["description"]},
            )
            self.stdout.write(f"{'Created' if created else 'Exists'}: {slug}")
            targets = {}
            for t in spec["targets"]:
                obj, _ = Target.objects.get_or_create(environment=env, label=t["label"], defaults=t)
                targets[t["label"]] = obj
            for v in spec["vars"]:
                target = targets.get(v["target"]) if v["target"] else None
                var, _ = Variable.objects.get_or_create(environment=env, key=v["key"], target=target)
                var.is_secret = v["secret"]
                var.is_managed = v["managed"]
                var.group = v["group"]
                var.set_value(v["value"])
                var.updated_by = "seed"
                var.save()
        self.stdout.write(self.style.SUCCESS("Demo data ready."))

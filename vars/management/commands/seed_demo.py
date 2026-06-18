"""Seed a couple of demo environments for local development.

Idempotent: safe to run repeatedly. Uses placeholder hosts/values (a shared
staging box, a production host, and a per-dev box) so the compare matrix has
something meaningful to show out of the box. All IPs/domains below are
documentation placeholders (TEST-NET / example.com) — not real infrastructure.
"""
from django.conf import settings
from django.core.management.base import BaseCommand

from vars.models import Environment, Target, Variable


DEMO = {
    "staging": {
        "name": "Staging",
        "kind": "shared",
        "description": "Shared staging box, per-dev apps under *.staging.example.com",
        "targets": [
            {"label": "Staging server", "host": "203.0.113.10",
             "dokku_app": "dev-ada", "domain": "dev-ada.staging.example.com"},
        ],
        "vars": {
            "ENV": ("STAGING", False, False),
            "SITE_URL": ("https://dev-ada.staging.example.com", False, False),
            "ALLOWED_HOSTS": ("dev-ada.staging.example.com,dev-ada", False, False),
            "SECRET_KEY": ("staging-django-secret-abc123", True, False),
            "AWS_ACCESS_KEY_ID": ("AKIASTAGINGEXAMPLE", True, False),
            "MAILGUN_ACCESS_KEY": ("key-staging-mailgun-xyz", True, False),
            "DATABASE_URL": ("postgres://auto@db/app", False, True),  # managed by Dokku
        },
    },
    "production": {
        "name": "Production",
        "kind": "shared",
        "description": "Single multi-tenant app at cloud.example.com",
        "targets": [
            {"label": "Production server", "host": "203.0.113.20",
             "dokku_app": "web-production", "domain": "cloud.example.com"},
        ],
        "vars": {
            "ENV": ("PRODUCTION", False, False),
            "SITE_URL": ("https://cloud.example.com", False, False),
            "ALLOWED_HOSTS": ("cloud.example.com", False, False),
            "SECRET_KEY": ("prod-django-secret-DIFFERENT", True, False),
            "AWS_ACCESS_KEY_ID": ("AKIAPRODEXAMPLE", True, False),
            "MAILGUN_ACCESS_KEY": ("key-prod-mailgun-xyz", True, False),
            "DATABASE_URL": ("postgres://auto@db/app", False, True),
        },
    },
    "local": {
        "name": "Local dev",
        "kind": "local",
        "description": "Developer Docker Compose stack",
        "targets": [{"label": "localhost", "local_only": True}],
        "vars": {
            "ENV": ("LOCAL", False, False),
            "SITE_URL": ("http://localhost:8000", False, False),
            "ALLOWED_HOSTS": ("localhost,127.0.0.1", False, False),
            "SECRET_KEY": ("local-insecure-secret", True, False),
        },
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
            verb = "Created" if created else "Exists"
            self.stdout.write(f"{verb}: {slug}")
            if created:
                for t in spec["targets"]:
                    Target.objects.create(environment=env, **t)
            for key, (value, is_secret, is_managed) in spec["vars"].items():
                var, _ = Variable.objects.get_or_create(environment=env, key=key)
                var.is_secret = is_secret
                var.is_managed = is_managed
                var.set_value(value)
                var.updated_by = "seed"
                var.save()
        self.stdout.write(self.style.SUCCESS("Demo data ready."))

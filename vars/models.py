"""Data model for the keymaker service."""
from django.db import models
from django.db.models import Q
from django.utils import timezone

from . import crypto


class AppUser(models.Model):
    """The signed-in UI principal. Today there is one shared account ("team")."""

    username = models.CharField(max_length=150, unique=True)
    display_name = models.CharField(max_length=255, blank=True)
    email = models.EmailField(blank=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    last_login_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.username


class Environment(models.Model):
    """A named set of variables (e.g. staging, production, dev-ethan)."""

    KIND_SHARED = "shared"
    KIND_LOCAL = "local"
    KIND_CHOICES = [(KIND_SHARED, "Shared server"), (KIND_LOCAL, "Local devs only")]

    slug = models.SlugField(max_length=80, unique=True)
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    kind = models.CharField(max_length=16, choices=KIND_CHOICES, default=KIND_SHARED)
    # Bumped on every variable change — cheap change-detection for the sync client.
    revision = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def bump_revision(self):
        Environment.objects.filter(pk=self.pk).update(
            revision=models.F("revision") + 1, updated_at=timezone.now()
        )
        self.refresh_from_db(fields=["revision"])

    def active_vars(self):
        """Live (non-archived) variables — what the UI, exports, and API serve."""
        return self.variables.filter(archived=False)


class Target(models.Model):
    """Where an environment runs — descriptive, and tells the sync client the Dokku app."""

    environment = models.ForeignKey(Environment, related_name="targets", on_delete=models.CASCADE)
    label = models.CharField(max_length=120)
    host = models.CharField(max_length=255, blank=True, help_text="IP or hostname; blank for local-only")
    dokku_app = models.CharField(max_length=120, blank=True, help_text="Dokku app name to sync to")
    domain = models.CharField(max_length=255, blank=True)
    local_only = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.label} ({self.environment.slug})"


class Variable(models.Model):
    """A single key/value within an environment. Value is encrypted at rest."""

    environment = models.ForeignKey(Environment, related_name="variables", on_delete=models.CASCADE)
    key = models.CharField(max_length=255)
    value_encrypted = models.BinaryField()
    is_secret = models.BooleanField(default=True, help_text="Masked in UI and audit log")
    is_managed = models.BooleanField(
        default=False, help_text="Managed externally (e.g. by Dokku); read-only, excluded from sync"
    )
    updated_by = models.CharField(max_length=150, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    # --- usage reconciliation (set by the keymaker scan client) ---
    last_seen_at = models.DateTimeField(
        null=True, blank=True, help_text="Last time a scan found this key referenced in code"
    )
    last_audit_at = models.DateTimeField(
        null=True, blank=True, help_text="Last time a scan checked this key"
    )
    suspected_unused = models.BooleanField(default=False)
    audit_note = models.CharField(max_length=400, blank=True)

    # --- soft delete (archive) — we never hard-delete; a human can restore ---
    archived = models.BooleanField(default=False)
    archived_at = models.DateTimeField(null=True, blank=True)
    archived_by = models.CharField(max_length=150, blank=True)
    archived_reason = models.CharField(max_length=400, blank=True)

    class Meta:
        ordering = ["key"]
        # Only one ACTIVE variable per key; archived rows with the same key are allowed.
        constraints = [
            models.UniqueConstraint(
                fields=["environment", "key"],
                condition=Q(archived=False),
                name="uniq_active_env_key",
            )
        ]

    def __str__(self):
        return f"{self.environment.slug}:{self.key}"

    @property
    def value(self) -> str:
        return crypto.decrypt(self.value_encrypted)

    def set_value(self, plaintext: str):
        self.value_encrypted = crypto.encrypt(plaintext)

    def archive(self, *, by, reason=""):
        self.archived = True
        self.archived_at = timezone.now()
        self.archived_by = by
        self.archived_reason = reason
        self.suspected_unused = False  # it's handled now
        self.save(update_fields=["archived", "archived_at", "archived_by",
                                 "archived_reason", "suspected_unused"])

    def restore(self):
        self.archived = False
        self.archived_at = None
        self.archived_by = ""
        self.archived_reason = ""
        self.save(update_fields=["archived", "archived_at", "archived_by", "archived_reason"])


class AuditLog(models.Model):
    """Append-only record of who changed what, when."""

    actor = models.CharField(max_length=200)
    action = models.CharField(max_length=80)
    environment = models.CharField(max_length=80, blank=True)
    key = models.CharField(max_length=255, blank=True)
    detail = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.actor} {self.action}"

    @classmethod
    def record(cls, *, actor, action, environment="", key="", detail=""):
        return cls.objects.create(
            actor=str(actor), action=action, environment=environment, key=key, detail=detail
        )

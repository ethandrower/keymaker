"""Credentials that expire: track them, warn before they lapse, rotate in one place.

Like vars/ops.py this is the single implementation behind the web UI, the MCP
server and the daily `credential_alerts` job. Nothing here touches a request.

A Credential is the issued token (an Atlassian API token, a Bitbucket repo
access token). Variables holding a copy of it are linked to it, so rotating the
credential can write the new value into every copy at once. Copies Keymaker
doesn't hold (pipeline repo variables, ~/.trinity/config.yaml) are listed in
`used_in` as a checklist for the human doing the rotation.
"""
import datetime as dt
import json
import logging
import urllib.request
from collections import defaultdict

from django.conf import settings
from django.utils import timezone

from . import ops
from .models import AuditLog, Credential, Environment, Variable

logger = logging.getLogger(__name__)

OK, EXPIRING, EXPIRED, NO_EXPIRY, ARCHIVED = "ok", "expiring", "expired", "no_expiry", "archived"
LABELS = {
    OK: "OK", EXPIRING: "Expiring soon", EXPIRED: "Expired",
    NO_EXPIRY: "No expiry", ARCHIVED: "Archived",
}

# Where each kind of token is regenerated, and how long one usually lives.
# `{repo}` / `{project}` are placeholders the form asks you to fill in.
PROVIDERS = {
    "atlassian_api_token": {
        "label": "Atlassian API token (Jira, Confluence, Bitbucket)",
        "rotate_url": "https://id.atlassian.com/manage-profile/security/api-tokens",
        "lifetime_days": 90,
        "scopes_hint": "Classic token: none (acts as the account). Scoped token: e.g. "
                       "read:jira-work, write:jira-work, read:confluence-content.all, "
                       "read:repository:bitbucket, write:pullrequest:bitbucket",
    },
    "bitbucket_repo_token": {
        "label": "Bitbucket repository access token",
        "rotate_url": "https://bitbucket.org/citemed/{repo}/admin/access-tokens",
        "lifetime_days": 90,
        "scopes_hint": "e.g. repository, repository:write, pullrequest, pullrequest:write, "
                       "pipeline, pipeline:write",
    },
    "bitbucket_project_token": {
        "label": "Bitbucket project access token",
        "rotate_url": "https://bitbucket.org/citemed/workspace/projects/{project}/settings/access-tokens",
        "lifetime_days": 90,
        "scopes_hint": "e.g. repository, repository:write, pullrequest, pipeline",
    },
    "bitbucket_workspace_token": {
        "label": "Bitbucket workspace access token",
        "rotate_url": "https://bitbucket.org/citemed/workspace/settings/access-tokens",
        "lifetime_days": 90,
        "scopes_hint": "e.g. repository, pullrequest, pipeline, project, account",
    },
    "github_pat": {
        "label": "GitHub fine-grained personal access token",
        "rotate_url": "https://github.com/settings/personal-access-tokens",
        "lifetime_days": 90,
        "scopes_hint": "Repository access + permissions, e.g. Contents: read/write, Pull requests: read/write",
    },
    "other": {"label": "Other", "rotate_url": "", "lifetime_days": None, "scopes_hint": ""},
}


class CredentialError(ValueError):
    """A request that can't be carried out, with a message fit to show as-is."""


# --- state ---------------------------------------------------------------

def status(cred, today=None):
    if cred.archived:
        return ARCHIVED
    days = cred.days_left(today)
    if days is None:
        return NO_EXPIRY
    if days < 0:
        return EXPIRED
    return EXPIRING if days <= cred.warn_days else OK


def due(today=None):
    """Active credentials that are expiring or expired, soonest first."""
    return [c for c in Credential.objects.filter(archived=False, expires_on__isnull=False)
            if status(c, today) in (EXPIRING, EXPIRED)]


def due_count():
    today = timezone.localdate()
    return sum(1 for c in Credential.objects.filter(archived=False, expires_on__isnull=False)
               .only("expires_on", "warn_days", "archived") if status(c, today) in (EXPIRING, EXPIRED))


def when_text(cred, today=None):
    """'expires in 6 days' / 'expires today' / 'expired 3 days ago' / 'no expiry'."""
    days = cred.days_left(today)
    if days is None:
        return "no expiry"
    if days == 0:
        return "expires today"
    if days > 0:
        return f"expires in {days} day{'s' if days != 1 else ''}"
    return f"expired {-days} day{'s' if days != -1 else ''} ago"


def linked(cred):
    return list(cred.variables.filter(archived=False)
                .select_related("environment", "target").order_by("environment__name", "key"))


def var_ref(v):
    """The `env:KEY` / `env:KEY@target` handle the MCP tools and link form use."""
    return f"{v.environment.slug}:{v.key}" + (f"@{v.target.label}" if v.target_id else "")


def resolve_ref(ref):
    """Find the active variable a `env:KEY[@target]` handle names."""
    ref = (ref or "").strip()
    if ":" not in ref:
        raise CredentialError(f"'{ref}' is not env:KEY (or env:KEY@target).")
    slug, rest = ref.split(":", 1)
    key, _, target_label = rest.partition("@")
    env = Environment.objects.filter(slug=slug.strip()).first()
    if env is None:
        raise CredentialError(f"No environment '{slug}'.")
    qs = env.active_vars().filter(key=key.strip())
    qs = qs.filter(target__label=target_label.strip()) if target_label else qs.filter(target__isnull=True)
    var = qs.first()
    if var is None:
        raise CredentialError(f"No active variable {ref}.")
    return var


def copies(cred=None, value=None):
    """Active variables holding the same value as the credential's linked copies
    (or as `value`) that aren't linked yet. This is how a token pasted into five
    environments is found from one of them. Values are compared in memory and
    never leave this function."""
    values = {value} if value else {v.value for v in linked(cred)} if cred else set()
    values.discard("")
    if not values:
        return []
    qs = (Variable.objects.filter(archived=False, is_managed=False, environment__archived=False)
          .select_related("environment", "target").order_by("environment__name", "key"))
    if cred is not None:
        qs = qs.exclude(credential=cred)
    return [v for v in qs if v.value in values]


def describe(cred, today=None):
    """Plain-data view for MCP/API. No values."""
    return {
        "id": cred.id, "name": cred.name, "provider": cred.provider, "owner": cred.owner,
        "status": status(cred, today), "when": when_text(cred, today),
        "expires_on": cred.expires_on.isoformat() if cred.expires_on else None,
        "days_left": cred.days_left(today),
        "issued_on": cred.issued_on.isoformat() if cred.issued_on else None,
        "lifetime_days": cred.lifetime_days, "warn_days": cred.warn_days,
        "rotate_url": cred.rotate_url, "scopes": cred.scopes, "used_in": cred.used_in,
        "notes": cred.notes,
        "variables": [var_ref(v) for v in linked(cred)],
    }


# --- write ---------------------------------------------------------------

FIELDS = ("name", "provider", "owner", "rotate_url", "scopes", "used_in", "notes")


def _date(value, field):
    if value in (None, ""):
        return None
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value).strip())
    except ValueError:
        raise CredentialError(f"{field} must be a date like 2026-12-31.")


def _int(value, field):
    if value in (None, ""):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise CredentialError(f"{field} must be a whole number of days.")
    if n < 0:
        raise CredentialError(f"{field} can't be negative.")
    return n


def save(actor, data, cred=None):
    """Create or update a credential from a dict of fields (form or MCP args).

    Only keys present in `data` change, so an MCP caller can patch one field.
    """
    created = cred is None
    cred = cred or Credential()
    for field in FIELDS:
        if field in data:
            setattr(cred, field, (data.get(field) or "").strip())
    if not cred.name:
        raise CredentialError("name is required.")
    if cred.provider and cred.provider not in PROVIDERS:
        raise CredentialError(f"provider must be one of: {', '.join(PROVIDERS)}.")
    if "{" in cred.rotate_url:
        raise CredentialError("Fill in the {placeholder} in the rotate link first.")
    if cred.rotate_url and not cred.rotate_url.startswith(("https://", "http://")):
        raise CredentialError("The rotate link must be a full https:// URL.")
    if "issued_on" in data:
        cred.issued_on = _date(data["issued_on"], "issued_on")
    if "expires_on" in data:
        new = _date(data["expires_on"], "expires_on")
        if new != cred.expires_on:
            cred.alerted_stage = ""   # a new date is a new countdown
        cred.expires_on = new
    if "lifetime_days" in data:
        cred.lifetime_days = _int(data["lifetime_days"], "lifetime_days")
    if data.get("warn_days") not in (None, ""):
        cred.warn_days = _int(data["warn_days"], "warn_days")
    if created and cred.lifetime_days is None and cred.provider:
        cred.lifetime_days = PROVIDERS[cred.provider]["lifetime_days"]
    cred.updated_by = actor
    cred.save()
    AuditLog.record(actor=actor, action="credential_create" if created else "credential_update",
                    key=cred.name[:255],
                    detail=f"expires {cred.expires_on or 'never'}"[:500])
    return cred


def link(cred, actor, variables):
    done = []
    for v in variables:
        if v.credential_id != cred.id:
            v.credential = cred
            v.save(update_fields=["credential"])
            done.append(var_ref(v))
    if done:
        AuditLog.record(actor=actor, action="credential_link", key=cred.name[:255],
                        detail=", ".join(done)[:500])
    return done


def unlink(cred, actor, variable):
    if variable.credential_id == cred.id:
        variable.credential = None
        variable.save(update_fields=["credential"])
        AuditLog.record(actor=actor, action="credential_unlink", key=cred.name[:255],
                        detail=var_ref(variable))


def archive(cred, actor):
    cred.archived, cred.archived_at, cred.archived_by = True, timezone.now(), actor
    cred.save(update_fields=["archived", "archived_at", "archived_by"])
    AuditLog.record(actor=actor, action="credential_archive", key=cred.name[:255])


def restore(cred, actor):
    cred.archived, cred.archived_at, cred.archived_by = False, None, ""
    cred.save(update_fields=["archived", "archived_at", "archived_by"])
    AuditLog.record(actor=actor, action="credential_restore", key=cred.name[:255])


def rotate(cred, actor, value=None, expires_on=None, push=False, today=None):
    """Record that the token was re-issued, and optionally write the new value.

    The new expiry is `expires_on` if given, else today + lifetime_days. With a
    value, every linked variable gets it (one revision bump per environment);
    with push as well, each is sent to the boxes it applies to with
    --no-restart. Copies listed in `used_in` are the caller's to update.
    """
    today = today or timezone.localdate()
    new_expiry = _date(expires_on, "expires_on")
    if new_expiry is None and cred.lifetime_days:
        new_expiry = today + dt.timedelta(days=cred.lifetime_days)
    if new_expiry is None:
        raise CredentialError("Give the new token's expiry date (or set a lifetime on the credential).")
    if new_expiry < today:
        raise CredentialError("The new expiry date is already in the past.")

    result = {"credential": cred.name, "expires_on": new_expiry.isoformat(),
              "updated": [], "pushed": {}, "push_errors": [],
              "also_update": cred.used_in}
    if value:
        by_env = defaultdict(list)
        for v in linked(cred):
            if v.is_managed:
                continue
            v.set_value(value)
            v.updated_by = actor
            v.save()
            by_env[v.environment_id].append(v)
            result["updated"].append(var_ref(v))
            AuditLog.record(actor=actor, action="update", environment=v.environment.slug, key=v.key,
                            detail=f"(secret) [{v.scope_label}] rotated: {cred.name}"[:500])
        for env_vars in by_env.values():
            env = env_vars[0].environment
            env.bump_revision()
            if push and env.kind != Environment.KIND_LOCAL:   # local envs have no servers
                result["pushed"].update(_push(env, actor, env_vars, result["push_errors"]))

    cred.issued_on, cred.expires_on = today, new_expiry
    cred.alerted_stage, cred.alerted_at = "", None
    cred.updated_by = actor
    cred.save()
    AuditLog.record(actor=actor, action="credential_rotate", key=cred.name[:255],
                    detail=f"new expiry {new_expiry}; {len(result['updated'])} variable(s) updated"
                           + (" and pushed" if push and value else ""))
    return result


def _push(env, actor, env_vars, errors):
    """Push rotated keys, scoping overrides to their own box so a base value
    holding a different token is never sent along with them."""
    pushed = {}
    by_target = defaultdict(set)
    for v in env_vars:
        by_target[v.target_id].add(v.key)
    targets = {t.id: t for t in env.targets.all()}
    for target_id, keys in by_target.items():
        try:
            r = ops.push(env, actor, keys=sorted(keys), only_target=targets.get(target_id), force=True)
        except ops.OpError as exc:
            errors.append(f"{env.slug}: {exc}")
            continue
        errors.extend(f"{env.slug}/{e}" for e in r["errors"])
        for box, box_keys in r["pushed"].items():
            pushed[f"{env.slug}/{box}"] = box_keys
    return pushed


# --- alerts --------------------------------------------------------------

# Escalating stages; the daily job posts when a credential moves into a new one.
_STAGES = [("expired", lambda d, w: d < 0), ("1d", lambda d, w: d <= 1),
           ("7d", lambda d, w: d <= 7), ("warn", lambda d, w: d <= w)]
REMIND_EXPIRED_EVERY = dt.timedelta(days=7)


def alert_stage(cred, today=None):
    days = cred.days_left(today)
    if cred.archived or days is None:
        return ""
    return next((name for name, hit in _STAGES if hit(days, cred.warn_days)), "")


def pending_alerts(today=None, now=None):
    """Credentials whose stage changed since the last post, plus expired ones
    not mentioned for a week."""
    now = now or timezone.now()
    out = []
    for c in Credential.objects.filter(archived=False, expires_on__isnull=False):
        stage = alert_stage(c, today)
        if not stage:
            continue
        if stage != c.alerted_stage or (
                stage == "expired" and (c.alerted_at is None or now - c.alerted_at >= REMIND_EXPIRED_EVERY)):
            out.append((c, stage))
    return out


def digest_text(items, today=None):
    """Slack mrkdwn: one line per credential, with the rotate link up front."""
    base = (getattr(settings, "KEYMAKER_BASE_URL", "") or "").rstrip("/")
    lines = [":key: *Keymaker: credentials to rotate*"]
    for c, _ in sorted(items, key=lambda i: i[0].expires_on):
        icon = ":red_circle:" if status(c, today) == EXPIRED else ":large_orange_circle:"
        parts = [f"{icon} *{c.name}* {when_text(c, today)} ({c.expires_on:%-d %b %Y})"]
        if c.owner:
            parts.append(f"owner {c.owner}")
        n = c.variables.filter(archived=False).count()
        if n:
            parts.append(f"{n} variable{'s' if n != 1 else ''}")
        links = []
        if c.rotate_url:
            links.append(f"<{c.rotate_url}|Rotate>")
        if base:
            links.append(f"<{base}/credentials/{c.id}/|Keymaker>")
        if links:
            parts.append(" · ".join(links))
        lines.append(" · ".join(parts))
    return "\n".join(lines)


def post_to_slack(text):
    """Webhook if configured, else chat.postMessage with a bot token. Returns
    False (and logs) when Slack isn't configured or the post fails."""
    webhook = getattr(settings, "KEYMAKER_SLACK_WEBHOOK_URL", "")
    token = getattr(settings, "KEYMAKER_SLACK_BOT_TOKEN", "")
    channel = getattr(settings, "KEYMAKER_SLACK_CHANNEL", "")
    if webhook:
        req = urllib.request.Request(webhook, data=json.dumps({"text": text}).encode(),
                                     headers={"Content-Type": "application/json"})
    elif token and channel:
        req = urllib.request.Request(
            "https://slack.com/api/chat.postMessage",
            data=json.dumps({"channel": channel, "text": text, "unfurl_links": False}).encode(),
            headers={"Content-Type": "application/json; charset=utf-8",
                     "Authorization": f"Bearer {token}"})
    else:
        logger.info("Slack not configured; credential alert not posted")
        return False
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode() or "{}"
    except OSError as exc:
        logger.warning("Slack post failed: %s", exc)
        return False
    if not webhook and not json.loads(body).get("ok"):
        logger.warning("Slack post rejected: %s", body[:300])
        return False
    return True


def send_alerts(dry_run=False, today=None, now=None):
    """The daily job: post one digest of everything newly due, then remember
    which stage each credential was announced at. If the post fails nothing is
    marked, so tomorrow's run tries again."""
    items = pending_alerts(today, now)
    if not items:
        return {"posted": False, "credentials": []}
    text = digest_text(items, today)
    names = [c.name for c, _ in items]
    if dry_run:
        return {"posted": False, "dry_run": True, "credentials": names, "text": text}
    posted = post_to_slack(text)
    if posted:
        stamp = now or timezone.now()
        for c, stage in items:
            Credential.objects.filter(pk=c.pk).update(alerted_stage=stage, alerted_at=stamp)
        AuditLog.record(actor="credential-alerts", action="credential_alert",
                        detail=", ".join(names)[:500])
    return {"posted": posted, "credentials": names, "text": text}

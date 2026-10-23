"""Model Context Protocol (MCP) endpoint, served *inside* the Django app.

An MCP server over the "streamable HTTP" transport is just a JSON-RPC 2.0 endpoint:
a single POST route that answers `initialize`, `tools/list`, and `tools/call`. There
is no separate process or daemon — this view runs in the same gunicorn workers as
the rest of Keymaker and reuses the same `Authorization: Bearer <KEYMAKER_KEY>` auth.

A Claude Code (or any MCP client) connects with:

    claude mcp add --transport http keymaker \\
      https://keymaker.citemed.com/mcp -H "Authorization: Bearer $KEYMAKER_KEY"

…then discovers the tools below via `tools/list` and invokes them via `tools/call`.
The tools wrap the same logic the REST API uses, so the two never diverge.
"""
import json
import logging

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.text import slugify
from django.views.decorators.csrf import csrf_exempt

from .auth import check_key
from .api.views import TargetNotFound, _resolve_target, build_inventory
from . import credentials, ops
from .models import AuditLog, Credential, Environment, Target, Variable

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "keymaker", "title": "Keymaker", "version": "2"}
MCP_ACTOR = "mcp"
logger = logging.getLogger(__name__)


# --- tool definitions -----------------------------------------------------
# Each entry: JSON Schema the client sees in tools/list, plus a handler(args)->dict.
# Handlers raise ValueError for client-facing errors (returned as isError content).
#
# Anything that reads from or writes to a box goes through vars/ops.py — the same
# functions the web UI calls — so an agent and an admin get identical behaviour.

def _tool_inventory(args):
    return build_inventory(include_archived=bool(args.get("include_archived")))


def _tool_list_environments(args):
    qs = Environment.objects.all()
    if not args.get("include_archived"):
        qs = qs.filter(archived=False)
    return {"environments": [
        {"slug": e.slug, "name": e.name, "kind": e.kind,
         "revision": e.revision, "archived": e.archived}
        for e in qs
    ]}


def _get_env(slug):
    env = Environment.objects.filter(slug=slug).first()
    if env is None:
        known = ", ".join(Environment.objects.filter(archived=False).values_list("slug", flat=True))
        raise ValueError(f"No environment '{slug}'. Environments: {known}.")
    return env


def _resolve(env, ident):
    try:
        return _resolve_target(env, ident)
    except TargetNotFound as exc:
        known = ", ".join(t.label for t in env.targets.all()) or "none"
        raise ValueError(f"No target '{exc}' in {env.slug}. Targets: {known}.")


def _keys(args):
    keys = args.get("keys")
    if isinstance(keys, str):
        keys = [keys]
    return [k.strip() for k in (keys or []) if k and k.strip()]


def _tool_get_variables(args):
    env = _get_env(args.get("environment"))
    target = _resolve(env, args.get("target"))
    include_managed = bool(args.get("include_managed"))
    only = set(_keys(args))
    resolved = env.resolved_for(target)
    variables = sorted(resolved.values(), key=lambda v: v.key)
    if not include_managed:
        variables = [v for v in variables if not v.is_managed]
    if only:
        variables = [v for v in variables if v.key in only]
    AuditLog.record(
        actor=MCP_ACTOR, action="api_read", environment=env.slug,
        detail=f"{len(variables)} vars (mcp)" + (f" for {target.label}" if target else ""),
    )
    out = {
        "environment": env.slug,
        "revision": env.revision,
        "target": target.label if target else None,
        "variables": {v.key: v.value for v in variables},
    }
    if only:
        out["not_found"] = sorted(only - {v.key for v in variables})
    return out


def _tool_check_revision(args):
    env = _get_env(args.get("environment"))
    return {"environment": env.slug, "revision": env.revision}


def _tool_find_key(args):
    """Where a key lives across the whole fleet — names and scopes, no values."""
    q = (args.get("key") or "").strip()
    if not q:
        raise ValueError("key is required.")
    qs = Variable.objects.filter(archived=False, environment__archived=False,
                                 key__icontains=q).select_related("environment", "target")
    hits = [{"environment": v.environment.slug, "key": v.key, "scope": v.scope_label,
             "is_secret": v.is_secret, "is_managed": v.is_managed,
             "updated_at": v.updated_at.isoformat()} for v in qs.order_by("key", "environment__slug")]
    return {"query": q, "matches": hits, "count": len(hits)}


def _tool_sync_status(args):
    env = _get_env(args.get("environment"))
    return ops.report(env, _resolve(env, args.get("target")))


def _tool_check_drift(args):
    env = _get_env(args.get("environment"))
    target = _resolve(env, args.get("target"))
    result = ops.check(env, f"drift-{MCP_ACTOR}", target=target)
    result["status"] = ops.report(env, target)
    return result


def _tool_set_variable(args):
    env = _get_env(args.get("environment"))
    key = (args.get("key") or "").strip()
    if not key:
        raise ValueError("key is required.")
    if "value" not in args:
        raise ValueError("value is required.")
    if key in settings.KEYMAKER_MANAGED_KEYS:
        raise ValueError(f"{key} is a managed key (owned by Dokku) and cannot be set here.")
    target = _resolve(env, args.get("target"))
    var = env.active_vars().filter(key=key, target=target).first()
    created = var is None
    if created:
        var = Variable(environment=env, key=key, target=target)
    if var.is_managed:
        raise ValueError("Managed variable is read-only.")
    if "is_secret" in args or created:
        var.is_secret = bool(args.get("is_secret", True))
    if "label" in args:
        var.label = (args.get("label") or "")[:80]
    var.set_value(args.get("value", ""))
    var.updated_by = MCP_ACTOR
    var.save()
    env.bump_revision()
    AuditLog.record(
        actor=MCP_ACTOR, action="api_create" if created else "api_update",
        environment=env.slug, key=key,
        detail=("(secret)" if var.is_secret else (args.get("value", "")[:120])) + f" [{var.scope_label}] (mcp)",
    )
    out = {"key": key, "target": target.label if target else None,
           "created": created, "revision": env.revision}
    if args.get("push"):
        out["push"] = ops.push(env, MCP_ACTOR, keys=[key], only_target=target, force=True)
    else:
        out["on_boxes"] = ("Stored in Keymaker only. The servers do not have it yet — call "
                           "keymaker_push_variables (or pass push: true) to send it.")
    return out


def _tool_archive_variable(args):
    env = _get_env(args.get("environment"))
    key = (args.get("key") or "").strip()
    target = _resolve(env, args.get("target"))
    var = env.active_vars().filter(key=key, target=target).first()
    if not var:
        raise ValueError(f"No active variable '{key}' at that scope in {env.slug}.")
    if var.is_managed:
        raise ValueError("Managed variable is read-only.")
    reason = args.get("reason") or "archived via MCP"
    var.archive(by=MCP_ACTOR, reason=reason)
    env.bump_revision()
    AuditLog.record(
        actor=MCP_ACTOR, action="api_archive", environment=env.slug,
        key=key, detail=f"{reason} [{var.scope_label}] (mcp)",
    )
    return {"key": key, "archived": True, "revision": env.revision,
            "on_boxes": "Archived in Keymaker only; the key is not removed from any server."}


def _tool_push_variables(args):
    env = _get_env(args.get("environment"))
    keys, everything = _keys(args), bool(args.get("all"))
    if not keys and not everything:
        raise ValueError("Pass keys, or all: true to send everything the checks flagged.")
    return ops.push(env, MCP_ACTOR, keys=keys, only_target=_resolve(env, args.get("target")),
                    all_flagged=everything and not keys)


def _tool_adopt_variables(args):
    env = _get_env(args.get("environment"))
    keys, everything = _keys(args), bool(args.get("all"))
    if not keys and not everything:
        raise ValueError("Pass keys, or all: true to adopt every key reported on a box.")
    return ops.adopt(env, MCP_ACTOR, keys=keys, view_target=_resolve(env, args.get("target")),
                     all_keys=everything and not keys)


def _tool_ignore_keys(args):
    env = _get_env(args.get("environment"))
    keys = _keys(args)
    if not keys:
        raise ValueError("keys is required.")
    return ops.ignore(env, MCP_ACTOR, keys, reason=(args.get("reason") or "").strip(),
                      view_target=_resolve(env, args.get("target")))


def _tool_create_environment(args):
    name = (args.get("name") or "").strip()
    slug = slugify(args.get("slug") or name)
    if not slug:
        raise ValueError("name (or slug) is required.")
    kind = args.get("kind") or Environment.KIND_SHARED
    if kind not in dict(Environment.KIND_CHOICES):
        raise ValueError("kind must be 'shared' or 'local'.")
    env, created = Environment.objects.get_or_create(
        slug=slug, defaults={"name": name or slug, "kind": kind,
                             "description": args.get("description", "")})
    if created:
        AuditLog.record(actor=MCP_ACTOR, action="env_create", environment=slug)
    return {"slug": env.slug, "name": env.name, "created": created,
            "next": "Add its servers with keymaker_save_target."}


def _tool_save_target(args):
    env = _get_env(args.get("environment"))
    label = (args.get("label") or "").strip()
    if not label:
        raise ValueError("label is required.")
    target = env.targets.filter(label=label).first()
    created = target is None
    if created:
        target = Target(environment=env, label=label)
    for field in ("host", "dokku_app", "domain"):
        if field in args:
            setattr(target, field, (args.get(field) or "").strip())
    if "local_only" in args:
        target.local_only = bool(args.get("local_only"))
    target.save()
    AuditLog.record(actor=MCP_ACTOR, action="target_add" if created else "target_update",
                    environment=env.slug, detail=f"{label} (mcp)")
    return {"id": target.id, "label": target.label, "host": target.host,
            "dokku_app": target.dokku_app, "domain": target.domain,
            "local_only": target.local_only, "created": created,
            "checkable": ops.checkable(target),
            "next": ("Run keymaker_check_drift to compare it to Keymaker." if ops.checkable(target)
                     else "Not comparable until it has both a host and a dokku_app.")}


def _get_credential(args):
    ident = args.get("credential")
    if ident in (None, ""):
        raise ValueError("credential (id or exact name) is required.")
    qs = Credential.objects.all()
    cred = qs.filter(id=ident).first() if str(ident).isdigit() else qs.filter(name=str(ident).strip()).first()
    if cred is None:
        names = ", ".join(qs.filter(archived=False).values_list("name", flat=True)) or "none"
        raise ValueError(f"No credential '{ident}'. Credentials: {names}.")
    return cred


def _tool_list_credentials(args):
    today = timezone.localdate()
    creds = credentials.due(today) if args.get("due_only") else Credential.objects.filter(archived=False)
    return {"credentials": [credentials.describe(c, today) for c in creds],
            "status_meanings": credentials.LABELS}


def _tool_save_credential(args):
    cred = _get_credential(args) if args.get("credential") not in (None, "") else None
    data = {k: args[k] for k in (*credentials.FIELDS, "issued_on", "expires_on",
                                 "lifetime_days", "warn_days") if k in args}
    try:
        variables = [credentials.resolve_ref(r) for r in (args.get("link") or [])]
        cred = credentials.save(MCP_ACTOR, data, cred=cred)
    except credentials.CredentialError as exc:
        raise ValueError(str(exc))
    linked = credentials.link(cred, MCP_ACTOR, variables)
    out = credentials.describe(cred)
    out["newly_linked"] = linked
    out["same_value_elsewhere"] = [credentials.var_ref(v) for v in credentials.copies(cred)]
    return out


def _tool_rotate_credential(args):
    cred = _get_credential(args)
    if cred.archived:
        raise ValueError(f"{cred.name} is archived.")
    try:
        return credentials.rotate(cred, MCP_ACTOR, value=args.get("value") or None,
                                  expires_on=args.get("expires_on"), push=bool(args.get("push")))
    except credentials.CredentialError as exc:
        raise ValueError(str(exc))


_TARGET_DESC = ("Server to scope to: its label, dokku_app, or id (see keymaker_inventory). "
                "Omit for the environment as a whole / the all-targets base value.")
_ENV = {"type": "string", "description": "Environment slug, e.g. 'staging'."}
_KEYS = {"type": "array", "items": {"type": "string"}, "description": "Key names."}

# MCP tool annotations: tell the client which tools only read, which change
# Keymaker's own records, and which reach out to a live server.
_READ = {"readOnlyHint": True, "openWorldHint": False}
_WRITE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
_BOX_READ = {"readOnlyHint": True, "openWorldHint": True}
_BOX_WRITE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}

TOOLS = [
    {
        "name": "keymaker_inventory",
        "description": "Every environment and its servers (targets): hosts, Dokku apps, domains, "
                       "revision, variable counts, and each server's latest drift check. Names "
                       "and counts only, no values. Start here to discover what exists.",
        "inputSchema": {"type": "object",
                        "properties": {"include_archived": {"type": "boolean", "default": False}}},
        "annotations": _READ, "handler": _tool_inventory,
    },
    {
        "name": "keymaker_list_environments",
        "description": "List environments (slug, name, kind, revision). Lighter than the inventory.",
        "inputSchema": {"type": "object",
                        "properties": {"include_archived": {"type": "boolean", "default": False}}},
        "annotations": _READ, "handler": _tool_list_environments,
    },
    {
        "name": "keymaker_find_key",
        "description": "Find which environments and scopes hold a key, by full or partial name "
                       "(case-insensitive). No values. Use this instead of reading every "
                       "environment when you know the key but not where it lives.",
        "inputSchema": {"type": "object",
                        "properties": {"key": {"type": "string", "description": "Key name or fragment, e.g. 'MAILGUN'."}},
                        "required": ["key"]},
        "annotations": _READ, "handler": _tool_find_key,
    },
    {
        "name": "keymaker_get_variables",
        "description": "Read the resolved key/values Keymaker holds for an environment, optionally "
                       "for one server (its overrides win over the all-targets base). Pass keys to "
                       "read just those. Managed keys (DATABASE_URL, REDIS_URL) are excluded unless "
                       "include_managed is true. This is what Keymaker holds, which may differ from "
                       "what a server has — see keymaker_sync_status.",
        "inputSchema": {"type": "object", "properties": {
            "environment": _ENV,
            "target": {"type": "string", "description": _TARGET_DESC},
            "keys": dict(_KEYS, description="Only return these keys."),
            "include_managed": {"type": "boolean", "default": False}},
            "required": ["environment"]},
        "annotations": _READ, "handler": _tool_get_variables,
    },
    {
        "name": "keymaker_check_revision",
        "description": "Current revision number of an environment. It bumps on every variable "
                       "change, so it is a cheap did-anything-change check.",
        "inputSchema": {"type": "object", "properties": {"environment": _ENV},
                        "required": ["environment"]},
        "annotations": _READ, "handler": _tool_check_revision,
    },
    {
        "name": "keymaker_sync_status",
        "description": "How an environment compares to its servers, from the latest drift checks: "
                       "which keys differ, which are missing on a server, which exist on a server "
                       "but not in Keymaker, and which servers have no recent check. Names only. "
                       "Does not contact any server — call keymaker_check_drift for a fresh reading.",
        "inputSchema": {"type": "object", "properties": {
            "environment": _ENV, "target": {"type": "string", "description": _TARGET_DESC}},
            "required": ["environment"]},
        "annotations": _READ, "handler": _tool_sync_status,
    },
    {
        "name": "keymaker_check_drift",
        "description": "Run a drift check now: read each server's live Dokku config over SSH and "
                       "compare it to Keymaker. Read-only on the server. Returns the fresh sync "
                       "status. Use before pushing or adopting, and after changing a server by hand.",
        "inputSchema": {"type": "object", "properties": {
            "environment": _ENV, "target": {"type": "string", "description": _TARGET_DESC}},
            "required": ["environment"]},
        "annotations": _BOX_READ, "handler": _tool_check_drift,
    },
    {
        "name": "keymaker_set_variable",
        "description": "Create or update a key in Keymaker (optionally as an override for one "
                       "server). This changes Keymaker's record only: no server changes until the "
                       "value is pushed. Pass push: true to also send it to the server(s) it "
                       "applies to in the same call. Safe and reversible — the previous value is in "
                       "the audit trail and nothing restarts. Managed keys are rejected.",
        "inputSchema": {"type": "object", "properties": {
            "environment": _ENV,
            "key": {"type": "string"},
            "value": {"type": "string"},
            "is_secret": {"type": "boolean", "default": True,
                          "description": "Masked in the UI and audit log."},
            "target": {"type": "string", "description": _TARGET_DESC},
            "label": {"type": "string", "description": "Optional section label, e.g. 'Mail'."},
            "push": {"type": "boolean", "default": False,
                     "description": "Also write it to the server(s) with dokku config:set --no-restart."}},
            "required": ["environment", "key", "value"]},
        "annotations": _WRITE, "handler": _tool_set_variable,
    },
    {
        "name": "keymaker_archive_variable",
        "description": "Soft-delete a key in Keymaker: restorable in the UI, never destroyed. Does "
                       "not remove the key from any server.",
        "inputSchema": {"type": "object", "properties": {
            "environment": _ENV, "key": {"type": "string"},
            "target": {"type": "string", "description": _TARGET_DESC},
            "reason": {"type": "string"}},
            "required": ["environment", "key"]},
        "annotations": _WRITE, "handler": _tool_archive_variable,
    },
    {
        "name": "keymaker_push_variables",
        "description": "Send Keymaker's values to the server(s) that are missing them or hold a "
                       "different value (dokku config:set --no-restart). Only keys the latest check "
                       "flagged are sent, each server gets its own resolved value, and managed keys "
                       "are never touched. Nothing restarts: the app picks the values up on its next "
                       "restart or deploy. Re-checks the server afterwards and reports the result.",
        "inputSchema": {"type": "object", "properties": {
            "environment": _ENV,
            "keys": dict(_KEYS, description="Keys to send. Omit and pass all: true for everything flagged."),
            "all": {"type": "boolean", "default": False},
            "target": {"type": "string", "description": _TARGET_DESC}},
            "required": ["environment"]},
        "annotations": _BOX_WRITE, "handler": _tool_push_variables,
    },
    {
        "name": "keymaker_adopt_variables",
        "description": "Take keys that exist on a server but not in Keymaker into Keymaker, reading "
                       "their live values off the server. Read-only on the server. A key that every "
                       "server holds with the same value becomes one shared value; otherwise each "
                       "server gets its own override, so differing values are never merged.",
        "inputSchema": {"type": "object", "properties": {
            "environment": _ENV,
            "keys": dict(_KEYS, description="Keys to adopt. Omit and pass all: true for every reported key."),
            "all": {"type": "boolean", "default": False},
            "target": {"type": "string", "description": _TARGET_DESC}},
            "required": ["environment"]},
        "annotations": _BOX_READ | {"readOnlyHint": False}, "handler": _tool_adopt_variables,
    },
    {
        "name": "keymaker_ignore_keys",
        "description": "Record that Keymaker should not manage certain keys found on a server "
                       "(e.g. deploy-injected APP_VERSION), so drift checks stop reporting them. "
                       "The keys stay on the server. Reversible in the UI.",
        "inputSchema": {"type": "object", "properties": {
            "environment": _ENV, "keys": _KEYS,
            "reason": {"type": "string"},
            "target": {"type": "string", "description": "Ignore only on this server. Omit for all servers."}},
            "required": ["environment", "keys"]},
        "annotations": _WRITE, "handler": _tool_ignore_keys,
    },
    {
        "name": "keymaker_create_environment",
        "description": "Create an environment (idempotent by slug). Follow with "
                       "keymaker_save_target to register its servers.",
        "inputSchema": {"type": "object", "properties": {
            "name": {"type": "string"},
            "slug": {"type": "string", "description": "Defaults to a slug of the name."},
            "kind": {"type": "string", "enum": ["shared", "local"], "default": "shared"},
            "description": {"type": "string"}},
            "required": ["name"]},
        "annotations": _WRITE, "handler": _tool_create_environment,
    },
    {
        "name": "keymaker_save_target",
        "description": "Register or update a server (target) in an environment, matched by label. "
                       "A target needs both host and dokku_app before Keymaker can check or push to "
                       "it. This records where the app runs; it does not create the Dokku app.",
        "inputSchema": {"type": "object", "properties": {
            "environment": _ENV,
            "label": {"type": "string", "description": "Name for the server, e.g. 'dev-ethan'."},
            "host": {"type": "string", "description": "IP or hostname of the Dokku host."},
            "dokku_app": {"type": "string"},
            "domain": {"type": "string"},
            "local_only": {"type": "boolean", "description": "True for localhost/docker-compose."}},
            "required": ["environment", "label"]},
        "annotations": _WRITE, "handler": _tool_save_target,
    },
    {
        "name": "keymaker_list_credentials",
        "description": "Tracked credentials (API tokens, access tokens) and when they expire: "
                       "status, days left, the page to rotate each one at, the scopes it needs, "
                       "which variables hold it and where else it lives. No values. Pass "
                       "due_only to see just the expiring and expired ones.",
        "inputSchema": {"type": "object", "properties": {
            "due_only": {"type": "boolean", "default": False}}},
        "annotations": _READ, "handler": _tool_list_credentials,
    },
    {
        "name": "keymaker_save_credential",
        "description": "Start tracking a credential's expiry, or update one (pass credential = its "
                       "id or exact name; only the fields you pass change). link takes variable "
                       "handles like 'staging:ATLASSIAN_API_TOKEN' or 'staging:KEY@dev-ethan'. The "
                       "result lists other variables holding the same value so you can link them too.",
        "inputSchema": {"type": "object", "properties": {
            "credential": {"type": "string", "description": "Id or exact name, to update. Omit to create."},
            "name": {"type": "string"},
            "provider": {"type": "string", "enum": list(credentials.PROVIDERS)},
            "owner": {"type": "string", "description": "Whose account issued it."},
            "rotate_url": {"type": "string", "description": "Page where it is regenerated."},
            "scopes": {"type": "string", "description": "Scopes/permissions to tick when re-issuing."},
            "used_in": {"type": "string", "description": "Copies outside Keymaker (pipelines, laptops)."},
            "notes": {"type": "string"},
            "issued_on": {"type": "string", "description": "YYYY-MM-DD"},
            "expires_on": {"type": "string", "description": "YYYY-MM-DD; empty = does not expire."},
            "lifetime_days": {"type": "integer"},
            "warn_days": {"type": "integer", "default": 14},
            "link": {"type": "array", "items": {"type": "string"}}}},
        "annotations": _WRITE, "handler": _tool_save_credential,
    },
    {
        "name": "keymaker_rotate_credential",
        "description": "Record that a credential was re-issued. Sets the new expiry (expires_on, "
                       "or today + its lifetime) and, given value, writes the new token into every "
                       "linked variable. push: true also sends those to their servers with "
                       "--no-restart. Copies outside Keymaker (used_in) are returned for you to update.",
        "inputSchema": {"type": "object", "properties": {
            "credential": {"type": "string", "description": "Id or exact name."},
            "value": {"type": "string", "description": "The new token. Omit to record the date only."},
            "expires_on": {"type": "string", "description": "YYYY-MM-DD"},
            "push": {"type": "boolean", "default": False}},
            "required": ["credential"]},
        "annotations": _BOX_WRITE, "handler": _tool_rotate_credential,
    },
]

INSTRUCTIONS = (
    "Keymaker is the source of truth for every environment's env vars and secrets. You are "
    "expected to write here as well as read: when work needs a new or changed env var, set it "
    "with keymaker_set_variable rather than editing .env files or running dokku config:set by "
    "hand. Writes are audited, reversible, and never restart anything.\n"
    "Keymaker's record and a server's live config are two separate things. Setting a variable "
    "changes the record only; keymaker_push_variables (or push: true on set) writes it to the "
    "server with --no-restart. keymaker_sync_status shows where the two differ, "
    "keymaker_check_drift takes a fresh reading, and keymaker_adopt_variables pulls in keys that "
    "exist only on a server.\n"
    "Typical flows — discover: keymaker_inventory, keymaker_find_key. Read: "
    "keymaker_get_variables. Add a var for a feature: keymaker_set_variable with push: true, "
    "scoped with target for one developer's box. Reconcile a server: keymaker_check_drift, then "
    "adopt / push / ignore, then read the returned status.\n"
    "Tokens that expire are tracked as credentials: keymaker_list_credentials (due_only) shows "
    "what needs rotating and where; after re-issuing one, keymaker_rotate_credential with the new "
    "value updates every variable that holds it. When you store a token with an expiry, register "
    "it with keymaker_save_credential."
)

_TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}


def _public_tools():
    """tools/list payload — the schema without the server-side handler."""
    return [{k: v for k, v in t.items() if k != "handler"} for t in TOOLS]


# --- JSON-RPC dispatch -----------------------------------------------------

def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _handle(message):
    """Dispatch a single JSON-RPC request. Returns a response dict, or None for
    notifications (which get no reply)."""
    if not isinstance(message, dict):
        # A malformed item (e.g. a bare number/string in a batch). Per JSON-RPC,
        # reply with an Invalid Request error rather than crashing the request.
        return _error(None, -32600, "Invalid Request")
    method = message.get("method")
    req_id = message.get("id")
    params = message.get("params") or {}

    # Notifications (no id) — acknowledge with no response body.
    if req_id is None:
        return None

    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
            "instructions": INSTRUCTIONS,
        })

    if method == "ping":
        return _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": _public_tools()})

    if method == "tools/call":
        name = params.get("name")
        tool = _TOOLS_BY_NAME.get(name)
        if tool is None:
            return _error(req_id, -32602, f"Unknown tool: {name}")
        try:
            data = tool["handler"](params.get("arguments") or {})
        except ValueError as exc:
            return _result(req_id, {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
            })
        except Exception as exc:  # noqa: BLE001 — an agent needs a reason, not a bare 500
            logger.exception("MCP tool %s failed", name)
            return _result(req_id, {
                "content": [{"type": "text",
                             "text": f"{name} failed inside Keymaker: {type(exc).__name__}: {str(exc)[:300]}"}],
                "isError": True,
            })
        return _result(req_id, {
            "content": [{"type": "text", "text": json.dumps(data, default=str)}],
            "structuredContent": data,
        })

    return _error(req_id, -32601, f"Method not found: {method}")


@csrf_exempt
def mcp_endpoint(request):
    """Single streamable-HTTP MCP route. Auth = same bearer key as the REST API."""
    if request.method == "GET":
        # Some clients open a GET stream for server-initiated messages; we don't push any.
        return HttpResponse(status=405)
    if request.method != "POST":
        return HttpResponse(status=405)

    header = request.META.get("HTTP_AUTHORIZATION", "")
    provided = header[7:].strip() if header.startswith("Bearer ") else ""
    if not check_key(provided):
        return JsonResponse(
            _error(None, -32001, "Invalid or missing key"), status=401
        )

    try:
        payload = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return JsonResponse(_error(None, -32700, "Parse error"), status=400)

    # A batch is a JSON array of messages; a single call is one object.
    if isinstance(payload, list):
        responses = [r for r in (_handle(m) for m in payload) if r is not None]
        if not responses:
            return HttpResponse(status=202)
        return JsonResponse(responses, safe=False)

    response = _handle(payload)
    if response is None:
        return HttpResponse(status=202)
    return JsonResponse(response)

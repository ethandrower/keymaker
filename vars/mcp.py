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

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .auth import check_key
from .api.views import TargetNotFound, _resolve_target, build_inventory
from .models import AuditLog, Environment, Variable

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "keymaker", "title": "Keymaker", "version": "1"}
MCP_ACTOR = "mcp"


# --- tool definitions -----------------------------------------------------
# Each entry: JSON Schema the client sees in tools/list, plus a handler(args)->dict.
# Handlers raise ValueError for client-facing errors (returned as isError content).

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
        raise ValueError(f"No environment '{slug}'.")
    return env


def _resolve(env, ident):
    try:
        return _resolve_target(env, ident)
    except TargetNotFound as exc:
        raise ValueError(f"No target '{exc}' in {env.slug}.")


def _tool_get_variables(args):
    env = _get_env(args.get("environment"))
    target = _resolve(env, args.get("target"))
    include_managed = bool(args.get("include_managed"))
    resolved = env.resolved_for(target)
    variables = sorted(resolved.values(), key=lambda v: v.key)
    if not include_managed:
        variables = [v for v in variables if not v.is_managed]
    AuditLog.record(
        actor=MCP_ACTOR, action="api_read", environment=env.slug,
        detail=f"{len(variables)} vars (mcp)" + (f" for {target.label}" if target else ""),
    )
    return {
        "environment": env.slug,
        "revision": env.revision,
        "target": target.label if target else None,
        "variables": {v.key: v.value for v in variables},
    }


def _tool_check_revision(args):
    env = _get_env(args.get("environment"))
    return {"environment": env.slug, "revision": env.revision}


def _tool_set_variable(args):
    env = _get_env(args.get("environment"))
    key = (args.get("key") or "").strip()
    if not key:
        raise ValueError("key is required.")
    if key in settings.KEYMAKER_MANAGED_KEYS:
        raise ValueError(f"{key} is a managed key and cannot be set here.")
    target = _resolve(env, args.get("target"))
    var = env.active_vars().filter(key=key, target=target).first()
    created = var is None
    if created:
        var = Variable(environment=env, key=key, target=target)
    if var.is_managed:
        raise ValueError("Managed variable is read-only.")
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
    return {"key": key, "target": target.label if target else None,
            "created": created, "revision": env.revision}


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
    return {"key": key, "archived": True, "revision": env.revision}


_TARGET_DESC = "Target/server to scope to (label, dokku_app, or id). Omit for the all-targets base value."

TOOLS = [
    {
        "name": "keymaker_inventory",
        "description": "Full inventory of every environment and its servers (targets): "
                       "hosts, dokku apps, domains, revision, variable counts, and latest "
                       "drift/sync state per server. Names and counts only — no values. "
                       "Start here to discover what exists.",
        "inputSchema": {
            "type": "object",
            "properties": {"include_archived": {"type": "boolean", "default": False}},
        },
        "handler": _tool_inventory,
    },
    {
        "name": "keymaker_list_environments",
        "description": "List environments (slug, name, kind, revision). Lighter than the inventory.",
        "inputSchema": {
            "type": "object",
            "properties": {"include_archived": {"type": "boolean", "default": False}},
        },
        "handler": _tool_list_environments,
    },
    {
        "name": "keymaker_get_variables",
        "description": "Resolved key/values for an environment, optionally for one target "
                       "(target overrides win over the all-targets base). Managed keys "
                       "(e.g. DATABASE_URL) excluded unless include_managed is true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "environment": {"type": "string", "description": "Environment slug."},
                "target": {"type": "string", "description": _TARGET_DESC},
                "include_managed": {"type": "boolean", "default": False},
            },
            "required": ["environment"],
        },
        "handler": _tool_get_variables,
    },
    {
        "name": "keymaker_check_revision",
        "description": "Current revision number for an environment. Cheap change-check before "
                       "doing expensive work; the revision bumps on every variable change.",
        "inputSchema": {
            "type": "object",
            "properties": {"environment": {"type": "string"}},
            "required": ["environment"],
        },
        "handler": _tool_check_revision,
    },
    {
        "name": "keymaker_set_variable",
        "description": "Create or update a key in an environment (optionally scoped to one "
                       "target). Bumps the revision. Managed keys are rejected.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "environment": {"type": "string"},
                "key": {"type": "string"},
                "value": {"type": "string"},
                "is_secret": {"type": "boolean", "default": True,
                              "description": "Masked in the UI and audit log."},
                "target": {"type": "string", "description": _TARGET_DESC},
                "label": {"type": "string", "description": "Optional section label, e.g. 'Mail'."},
            },
            "required": ["environment", "key", "value"],
        },
        "handler": _tool_set_variable,
    },
    {
        "name": "keymaker_archive_variable",
        "description": "Soft-delete (archive) a key — restorable in the UI, never destroyed. "
                       "Bumps the revision.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "environment": {"type": "string"},
                "key": {"type": "string"},
                "target": {"type": "string", "description": _TARGET_DESC},
                "reason": {"type": "string"},
            },
            "required": ["environment", "key"],
        },
        "handler": _tool_archive_variable,
    },
]

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
            "instructions": "Keymaker config store. Call keymaker_inventory to discover "
                            "environments and servers, then keymaker_get_variables to read config.",
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

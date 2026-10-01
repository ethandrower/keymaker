"""UI views (server-rendered + HTMX). Session-authed via AppUser."""
import functools

from django.conf import settings
from django.contrib import messages
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.text import slugify
from django.views.decorators.http import require_POST

from . import auth, exporters, ops, sync
from .models import AuditLog, Environment, IgnoredKey, Target, Variable


# --- decorators -----------------------------------------------------------

def login_required(view):
    @functools.wraps(view)
    def wrapper(request, *args, **kwargs):
        user = auth.current_user(request)
        if not user:
            return redirect("login")
        request.appuser = user
        return view(request, *args, **kwargs)

    return wrapper


def admin_required(view):
    @functools.wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.appuser.is_admin:
            return HttpResponseForbidden("Admin access required")
        return view(request, *args, **kwargs)

    return wrapper


def _nav_environments():
    """Active (non-archived) environments — what the sidebar shows."""
    return Environment.objects.filter(archived=False)


# --- auth views -----------------------------------------------------------

def login_view(request):
    if auth.current_user(request):
        return redirect("home")

    if request.method == "POST":
        if auth.check_key(request.POST.get("key", "")):
            user = auth.get_shared_user()
            auth.login_appuser(request, user)
            AuditLog.record(actor=user.username, action="login")
            return redirect("home")
        messages.error(request, "Incorrect key.")
        return redirect("login")

    return render(
        request,
        "vars/login.html",
        {"key_required": bool(settings.KEYMAKER_KEY)},
    )


def logout_view(request):
    auth.logout_appuser(request)
    return redirect("login")


# --- main UI --------------------------------------------------------------

@login_required
def home(request):
    envs = _nav_environments()
    first = envs.first()
    if first:
        return redirect("environment_detail", slug=first.slug)
    return render(request, "vars/home.html", {"environments": envs, "user": request.appuser})


def _env_target(env, ident):
    """Resolve a target id/label for UI views; None for all-targets/blank."""
    if not ident:
        return None
    return env.targets.filter(id=ident).first() if str(ident).isdigit() else \
        env.targets.filter(label=ident).first()


@login_required
def environment_detail(request, slug):
    env = get_object_or_404(Environment, slug=slug)
    # Optional: scope the variable table to one target's resolved view (?target=<id>).
    view_target = _env_target(env, request.GET.get("target"))
    # Sync status: what each key actually looks like on the boxes it belongs on.
    # With no target selected this rolls up across every checkable target; with
    # one selected it narrows to that box's exact state.
    targets, variables, checks, adoptions = ops.sync_state(env, view_target)
    return render(
        request,
        "vars/environment_detail.html",
        {
            "environments": _nav_environments(),
            "env": env,
            "variables": variables,
            "targets": targets,
            "view_target": view_target,        # None = show all; else scope table to this target
            "archived": env.variables.filter(archived=True),
            "user": request.appuser,
            "managed_keys": settings.KEYMAKER_MANAGED_KEYS,
            "target_rows": ops.target_rows(env, checks),   # per-box check status
            "pushable_n": sum(len(v.pushable) for v in variables),
            "adoptions": adoptions,            # on the box, not in Keymaker — triage
            "ignored": sync.ignored_rows(env, view_target=view_target),
            "summary": sync.summarize(variables, adoptions, checks, targets),
            "stale_after_hours": int(sync.STALE_AFTER.total_seconds() // 3600),
        },
    )


# --- sync actions (check / adopt / ignore / push) --------------------------
# Thin wrappers: the work is in vars/ops.py, shared with the MCP server. These
# only translate a result into flash messages and send the user back to the page
# they were on.

def _back_to_env(env, view_target):
    url = f"/environments/{env.slug}/"
    return redirect(f"{url}?target={view_target.id}" if view_target else url)


def _actor(request):
    return getattr(request.appuser, "username", "") or "user"


def _names(items, limit=8):
    items = sorted(items)
    return ", ".join(items[:limit]) + ("…" if len(items) > limit else "")


@login_required
@require_POST
def environment_check(request, slug):
    """Compare this environment's boxes to Keymaker now (one target, or all)."""
    env = get_object_or_404(Environment, slug=slug)
    view_target = _env_target(env, request.POST.get("view_target"))
    target = _env_target(env, request.POST.get("target"))
    try:
        r = ops.check(env, f"drift-ui:{_actor(request)}", target=target)
    except ops.OpError as exc:
        messages.info(request, str(exc))
        return _back_to_env(env, view_target)
    if r["checked"]:
        messages.success(request, f"Checked {_names(r['checked'])}.")
    for e in r["errors"]:
        messages.error(request, f"Couldn't check {e}")
    if r["not_reached"]:
        messages.info(request, f"{r['not_reached']} target(s) not reached in time — check again to finish.")
    return _back_to_env(env, view_target)


@admin_required
@require_POST
def variables_adopt(request, slug):
    env = get_object_or_404(Environment, slug=slug)
    view_target = _env_target(env, request.POST.get("view_target"))
    r = ops.adopt(env, _actor(request), keys=request.POST.getlist("key"),
                  view_target=view_target, all_keys=request.POST.get("all") == "1")
    if r["adopted"]:
        messages.success(request, f"Stored {len(r['adopted'])} key(s) in Keymaker: "
                                  + _names(a["key"] for a in r["adopted"]))
    elif not r["errors"]:
        messages.error(request, "Nothing to adopt — those keys are no longer reported on a box.")
    for e in r["errors"]:
        messages.error(request, f"Couldn't read {e}")
    if r["gone_from_box"]:
        messages.warning(request, "No longer set on the box (skipped): " + _names(r["gone_from_box"]))
    for e in r["recheck_errors"]:
        messages.warning(request, f"Re-check failed — {e} (status below may be stale)")
    return _back_to_env(env, view_target)


@admin_required
@require_POST
def variables_ignore(request, slug):
    env = get_object_or_404(Environment, slug=slug)
    view_target = _env_target(env, request.POST.get("view_target"))
    r = ops.ignore(env, _actor(request), request.POST.getlist("key"),
                   reason=(request.POST.get("reason") or "").strip(), view_target=view_target)
    if r["ignored"]:
        messages.success(request, f"Ignoring {len(r['ignored'])} key(s) on {r['scope']} — "
                                  "they stay on the box and stop being reported.")
    return _back_to_env(env, view_target)


@admin_required
@require_POST
def variables_unignore(request, slug, ignored_id):
    env = get_object_or_404(Environment, slug=slug)
    row = get_object_or_404(IgnoredKey, id=ignored_id, environment=env)
    r = ops.unignore(env, _actor(request), row)
    messages.success(request, f"{r['key']} will be reported again on {r['scope']}.")
    return _back_to_env(env, _env_target(env, request.POST.get("view_target")))


@admin_required
@require_POST
def variables_push(request, slug):
    env = get_object_or_404(Environment, slug=slug)
    view_target = _env_target(env, request.POST.get("view_target"))
    r = ops.push(env, _actor(request), keys=request.POST.getlist("key"),
                 view_target=view_target,
                 only_target=_env_target(env, request.POST.get("target")),
                 all_flagged=request.POST.get("all") == "1")
    sent = sum(len(k) for k in r["pushed"].values())
    if sent:
        messages.success(request, f"Sent {sent} value(s) to {_names(r['pushed'])}. "
                                  "Set with --no-restart — the app picks them up on its next restart or deploy.")
    elif not r["errors"]:
        messages.info(request, "Nothing to send — those keys already match the box.")
    for e in r["errors"]:
        messages.error(request, f"Push failed — {e}")
    for e in r["recheck_errors"]:
        messages.warning(request, f"Re-check failed — {e} (status below may be stale)")
    return _back_to_env(env, view_target)


@login_required
def environment_download(request, slug):
    """Download the environment's resolved variables as a .env file (logged)."""
    env = get_object_or_404(Environment, slug=slug)
    include_managed = request.GET.get("include_managed") == "1"
    target = _env_target(env, request.GET.get("target"))
    body = exporters.render_dotenv(env, target=target, include_managed=include_managed)
    count = body.count("\n") if body.strip() else 0
    suffix = f"-{target.label}" if target else ""
    AuditLog.record(
        actor=request.appuser.username, action="download", environment=env.slug,
        detail=f"{count} vars{' incl. managed' if include_managed else ''}"
               + (f" for {target.label}" if target else ""),
    )
    resp = HttpResponse(body, content_type="text/plain; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{env.slug}{suffix}.env"'
    return resp


@login_required
def variable_reveal(request, slug, var_id):
    """Return the decrypted value for a single secret (logged)."""
    env = get_object_or_404(Environment, slug=slug)
    var = get_object_or_404(Variable, id=var_id, environment=env)
    AuditLog.record(
        actor=request.appuser.username, action="reveal", environment=env.slug, key=var.key
    )
    return HttpResponse(var.value)


@admin_required
@require_POST
def variable_save(request, slug):
    env = get_object_or_404(Environment, slug=slug)
    var_id = request.POST.get("id")
    key = (request.POST.get("key") or "").strip()
    value = request.POST.get("value", "")
    is_secret = request.POST.get("is_secret") == "on"
    if not key:
        return HttpResponse("Key is required", status=400)

    if var_id:
        var = get_object_or_404(Variable, id=var_id, environment=env)
        action = "update"
    else:
        var = Variable(environment=env, key=key)
        action = "create"

    if var.is_managed:
        return HttpResponse("Managed variables are read-only", status=400)

    var.key = key
    var.is_secret = is_secret
    var.target = _env_target(env, request.POST.get("target"))  # blank = all targets
    var.label = (request.POST.get("label") or "").strip()[:80]
    var.set_value(value)
    var.updated_by = request.appuser.username
    var.save()
    env.bump_revision()
    AuditLog.record(
        actor=request.appuser.username,
        action=action,
        environment=env.slug,
        key=key,
        detail=("(secret)" if is_secret else value[:120]) + f" [{var.scope_label}]",
    )
    return _render_var_rows(request, env)


@admin_required
@require_POST
def variable_archive(request, slug, var_id):
    """Soft-delete: archive a variable with a reason (never hard-delete)."""
    env = get_object_or_404(Environment, slug=slug)
    var = get_object_or_404(Variable, id=var_id, environment=env, archived=False)
    if var.is_managed:
        return HttpResponse("Managed variables are read-only", status=400)
    reason = (request.POST.get("reason") or "").strip()
    var.archive(by=request.appuser.username, reason=reason)
    env.bump_revision()
    AuditLog.record(
        actor=request.appuser.username, action="archive", environment=env.slug,
        key=var.key, detail=reason or "(no reason given)",
    )
    return redirect("environment_detail", slug=env.slug)


@admin_required
@require_POST
def variable_restore(request, slug, var_id):
    """Un-archive a variable, unless an active one now holds that key."""
    env = get_object_or_404(Environment, slug=slug)
    var = get_object_or_404(Variable, id=var_id, environment=env, archived=True)
    if env.active_vars().filter(key=var.key, target=var.target).exists():
        messages.error(
            request,
            f"Can't restore {var.key} [{var.scope_label}]: an active variable already uses that key/scope.",
        )
        return redirect("environment_detail", slug=env.slug)
    var.restore()
    env.bump_revision()
    AuditLog.record(
        actor=request.appuser.username, action="restore", environment=env.slug, key=var.key
    )
    return redirect("environment_detail", slug=env.slug)


def _render_var_rows(request, env):
    """Re-render the table body for an HTMX swap, with sync status intact — the
    rows carry a Status column, so handing them back un-annotated would blank it
    out after every save."""
    view_target = _env_target(env, request.POST.get("view_target"))
    _, variables, _, _ = ops.sync_state(env, view_target)
    return render(
        request,
        "vars/_variable_rows.html",
        {"env": env, "variables": variables, "user": request.appuser,
         "view_target": view_target},
    )


@admin_required
@require_POST
def environment_create(request):
    name = (request.POST.get("name") or "").strip()
    if not name:
        messages.error(request, "Name is required")
        return redirect("home")
    slug = slugify(request.POST.get("slug") or name)
    kind = request.POST.get("kind") or Environment.KIND_SHARED
    env, created = Environment.objects.get_or_create(
        slug=slug,
        defaults={"name": name, "kind": kind, "description": request.POST.get("description", "")},
    )
    if created:
        AuditLog.record(actor=request.appuser.username, action="env_create", environment=slug)
    return redirect("environment_detail", slug=env.slug)


@admin_required
@require_POST
def environment_archive(request, slug):
    """Soft-hide an environment (restorable)."""
    env = get_object_or_404(Environment, slug=slug)
    env.archived = True
    env.archived_at = timezone.now()
    env.archived_by = request.appuser.username
    env.save(update_fields=["archived", "archived_at", "archived_by"])
    AuditLog.record(actor=request.appuser.username, action="env_archive", environment=slug)
    messages.success(request, f"Archived environment {env.name} (restorable).")
    first = _nav_environments().first()
    return redirect("environment_detail", slug=first.slug) if first else redirect("home")


@admin_required
@require_POST
def environment_restore(request, slug):
    env = get_object_or_404(Environment, slug=slug)
    env.archived = False
    env.archived_at = None
    env.archived_by = ""
    env.save(update_fields=["archived", "archived_at", "archived_by"])
    AuditLog.record(actor=request.appuser.username, action="env_restore", environment=slug)
    return redirect("environment_detail", slug=env.slug)


@admin_required
@require_POST
def environment_delete(request, slug):
    """Hard delete — removes the environment and all its targets/variables."""
    env = get_object_or_404(Environment, slug=slug)
    name, nv, nt = env.name, env.variables.count(), env.targets.count()
    env.delete()
    AuditLog.record(actor=request.appuser.username, action="env_delete", environment=slug,
                    detail=f"{name} (+{nv} vars, {nt} targets)")
    messages.success(request, f"Permanently deleted {name} ({nv} variables, {nt} targets).")
    first = _nav_environments().first()
    return redirect("environment_detail", slug=first.slug) if first else redirect("home")


@admin_required
@require_POST
def target_save(request, slug):
    """Create a target, or update it when an id is supplied."""
    env = get_object_or_404(Environment, slug=slug)
    fields = {
        "label": request.POST.get("label", "").strip() or "target",
        "host": request.POST.get("host", "").strip(),
        "dokku_app": request.POST.get("dokku_app", "").strip(),
        "domain": request.POST.get("domain", "").strip(),
        "local_only": request.POST.get("local_only") == "on",
    }
    target_id = request.POST.get("id")
    if target_id:
        target = get_object_or_404(Target, id=target_id, environment=env)
        for k, v in fields.items():
            setattr(target, k, v)
        target.save()
        action = "target_update"
    else:
        target = Target.objects.create(environment=env, **fields)
        action = "target_add"
    AuditLog.record(actor=request.appuser.username, action=action, environment=slug,
                    detail=target.label)
    return redirect("environment_detail", slug=env.slug)


@admin_required
@require_POST
def target_delete(request, slug, target_id):
    """Delete a target. Its target-specific variable overrides go with it
    (CASCADE); all-targets base values are unaffected."""
    env = get_object_or_404(Environment, slug=slug)
    target = get_object_or_404(Target, id=target_id, environment=env)
    label = target.label
    n_overrides = target.variables.count()
    target.delete()
    env.bump_revision()
    AuditLog.record(
        actor=request.appuser.username, action="target_delete", environment=slug,
        detail=f"{label} (+{n_overrides} override(s))",
    )
    messages.success(request, f"Deleted target {label} and {n_overrides} override(s).")
    return redirect("environment_detail", slug=env.slug)


# --- compare matrix -------------------------------------------------------

@login_required
def compare(request):
    all_envs = list(_nav_environments())
    selected_slugs = request.GET.getlist("env")
    selected = [e for e in all_envs if e.slug in selected_slugs]
    if not selected:
        selected = all_envs[:2]

    # Build matrix: union of keys (rows) x selected envs (columns).
    var_map = {}  # key -> {env_slug: Variable}
    for env in selected:
        for var in env.active_vars():
            var_map.setdefault(var.key, {})[env.slug] = var

    rows = []
    for key in sorted(var_map):
        cells = []
        present_values = []
        for env in selected:
            var = var_map[key].get(env.slug)
            if var is not None:
                present_values.append(var.value if not var.is_secret else f"\x00secret:{var.id}")
            cells.append({"env": env, "var": var})
        # A row "differs" if any selected env is missing the key, or values aren't all equal.
        differs = len(present_values) != len(selected) or len(set(present_values)) > 1
        rows.append({"key": key, "cells": cells, "differs": differs})

    return render(
        request,
        "vars/compare.html",
        {
            "environments": all_envs,
            "selected": selected,
            "selected_slugs": [e.slug for e in selected],
            "rows": rows,
            "user": request.appuser,
        },
    )


# --- cleanup (suspected-unused) -------------------------------------------

@login_required
def cleanup(request):
    """List all suspected-unused variables across environments for review."""
    flagged = (
        Variable.objects.filter(suspected_unused=True, archived=False)
        .select_related("environment")
        .order_by("environment__name", "key")
    )
    return render(
        request,
        "vars/cleanup.html",
        {"environments": _nav_environments(), "flagged": flagged, "user": request.appuser},
    )


@admin_required
@require_POST
def cleanup_archive(request, var_id):
    """Archive a flagged variable from the cleanup view (soft delete, restorable)."""
    var = get_object_or_404(Variable, id=var_id, archived=False)
    if var.is_managed:
        messages.error(request, f"{var.key} is managed and can't be archived here.")
        return redirect("cleanup")
    env, key = var.environment, var.key
    reason = (request.POST.get("reason") or "").strip() or "pruned via cleanup (unused)"
    var.archive(by=request.appuser.username, reason=reason)
    env.bump_revision()
    AuditLog.record(
        actor=request.appuser.username, action="archive", environment=env.slug,
        key=key, detail=reason,
    )
    messages.success(request, f"Archived {key} from {env.name} (restorable on the env page).")
    return redirect("cleanup")


# --- checks (drift) -------------------------------------------------------

@login_required
def checks(request):
    """The fleet-wide Checks page is gone: a check belongs to the environment it
    checks, so it runs from that environment's page. Old links land on home."""
    return redirect("home")


# --- audit ----------------------------------------------------------------

@login_required
def audit_log(request):
    logs = AuditLog.objects.all()[:300]
    return render(
        request,
        "vars/audit.html",
        {"environments": _nav_environments(), "logs": logs, "user": request.appuser},
    )

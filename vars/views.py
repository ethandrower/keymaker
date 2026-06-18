"""UI views (server-rendered + HTMX). Session-authed via AppUser."""
import functools

from django.conf import settings
from django.contrib import messages
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.text import slugify
from django.views.decorators.http import require_POST

from . import auth, exporters
from .models import AuditLog, Environment, Target, Variable


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
    return Environment.objects.all()


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


@login_required
def environment_detail(request, slug):
    env = get_object_or_404(Environment, slug=slug)
    return render(
        request,
        "vars/environment_detail.html",
        {
            "environments": _nav_environments(),
            "env": env,
            "variables": env.active_vars(),
            "archived": env.variables.filter(archived=True),
            "user": request.appuser,
            "managed_keys": settings.KEYMAKER_MANAGED_KEYS,
        },
    )


@login_required
def environment_download(request, slug):
    """Download the environment's variables as a .env file (logged)."""
    env = get_object_or_404(Environment, slug=slug)
    include_managed = request.GET.get("include_managed") == "1"
    body = exporters.render_dotenv(env, include_managed=include_managed)
    count = body.count("\n") if body.strip() else 0
    AuditLog.record(
        actor=request.appuser.username, action="download", environment=env.slug,
        detail=f"{count} vars{' incl. managed' if include_managed else ''}",
    )
    resp = HttpResponse(body, content_type="text/plain; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{env.slug}.env"'
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
    var.set_value(value)
    var.updated_by = request.appuser.username
    var.save()
    env.bump_revision()
    AuditLog.record(
        actor=request.appuser.username,
        action=action,
        environment=env.slug,
        key=key,
        detail="(secret)" if is_secret else value[:120],
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
    if env.active_vars().filter(key=var.key).exists():
        messages.error(request, f"Can't restore {var.key}: an active variable already uses that key.")
        return redirect("environment_detail", slug=env.slug)
    var.restore()
    env.bump_revision()
    AuditLog.record(
        actor=request.appuser.username, action="restore", environment=env.slug, key=var.key
    )
    return redirect("environment_detail", slug=env.slug)


def _render_var_rows(request, env):
    return render(
        request,
        "vars/_variable_rows.html",
        {"env": env, "variables": env.active_vars(), "user": request.appuser},
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
def target_save(request, slug):
    env = get_object_or_404(Environment, slug=slug)
    Target.objects.create(
        environment=env,
        label=request.POST.get("label", "").strip() or "target",
        host=request.POST.get("host", "").strip(),
        dokku_app=request.POST.get("dokku_app", "").strip(),
        domain=request.POST.get("domain", "").strip(),
        local_only=request.POST.get("local_only") == "on",
    )
    AuditLog.record(actor=request.appuser.username, action="target_add", environment=slug)
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


# --- audit ----------------------------------------------------------------

@login_required
def audit_log(request):
    logs = AuditLog.objects.all()[:300]
    return render(
        request,
        "vars/audit.html",
        {"environments": _nav_environments(), "logs": logs, "user": request.appuser},
    )

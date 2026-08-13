"""UI views (server-rendered + HTMX). Session-authed via AppUser."""
import functools
import os
import subprocess

from django.conf import settings
from django.contrib import messages
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.text import slugify
from django.views.decorators.http import require_POST

from . import auth, drift, exporters, sync
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


def _resolved_variables(env, view_target):
    """The variable rows the env page shows, honouring the target filter.

    active_vars() is ordered by (label, key) so the template can {% regroup %}.
    With a target selected this is that target's *resolved* set: base
    (all-targets) values, with the target's own overrides shadowing matching
    base keys, and other targets' overrides hidden.
    """
    variables = list(env.active_vars())
    if not view_target:
        return variables
    override_keys = {v.key for v in variables if v.target_id == view_target.id}
    return [v for v in variables
            if v.target_id == view_target.id
            or (v.target_id is None and v.key not in override_keys)]


def _sync_state(env, view_target):
    """Everything the env page (and every sync action) needs about drift.

    Actions recompute this rather than trusting the form for scope: which box a
    key came from and whether it should be adopted for one target or all of them
    is derived from the checks, not from whatever the browser posted back.
    """
    targets = list(env.targets.all())
    variables = _resolved_variables(env, view_target)
    checks = sync.latest_checks(env, targets)
    sync.annotate(variables, targets, checks, view_target=view_target)
    ignored = sync.ignored_index(env)
    adoptions = sync.adoption_rows(
        targets, checks, {v.key for v in variables}, ignored, view_target=view_target
    )
    return targets, variables, checks, adoptions


@login_required
def environment_detail(request, slug):
    env = get_object_or_404(Environment, slug=slug)
    # Optional: scope the variable table to one target's resolved view (?target=<id>).
    view_target = _env_target(env, request.GET.get("target"))
    # Sync status: what each key actually looks like on the boxes it belongs on.
    # With no target selected this rolls up across every checkable target; with
    # one selected it narrows to that box's exact state.
    targets, variables, checks, adoptions = _sync_state(env, view_target)
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
            "adoptions": adoptions,            # on the box, not in Keymaker — triage
            "ignored": sync.ignored_rows(env, view_target=view_target),
            "summary": sync.summarize(variables, adoptions, checks, targets),
            "stale_after_hours": int(sync.STALE_AFTER.total_seconds() // 3600),
        },
    )


# --- sync actions (adopt / ignore / push) ---------------------------------

def _back_to_env(env, view_target):
    url = f"/environments/{env.slug}/"
    return redirect(f"{url}?target={view_target.id}" if view_target else url)


def _recheck(env, targets, request, actor_prefix="sync"):
    """Re-run the drift check on the boxes an action just touched, so the status
    the user lands back on is measured rather than assumed."""
    actor = f"{actor_prefix}:{getattr(request.appuser, 'username', '') or 'user'}"
    _, errors, _ = drift.run_checks(env, targets, actor, budget_s=15.0)
    for e in errors:
        messages.warning(request, f"Re-check failed — {e} (status below may be stale)")


@admin_required
@require_POST
def variables_adopt(request, slug):
    """Take on-box keys into Keymaker, reading their live values off the box.

    Drift checks carry key names only, so this is the one path that fetches a
    value from a server. Scope is decided from the checks: a key present on
    every box becomes one all-targets value, otherwise a per-target override.
    """
    env = get_object_or_404(Environment, slug=slug)
    view_target = _env_target(env, request.POST.get("view_target"))
    keys = [k for k in request.POST.getlist("key") if k]
    _, _, _, adoptions = _sync_state(env, view_target)
    rows = {r["key"]: r for r in adoptions if r["key"] in keys}
    if not rows:
        messages.error(request, "Nothing to adopt — those keys are no longer reported on a box.")
        return _back_to_env(env, view_target)

    # One SSH read per source box, not per key.
    by_source = {}
    for r in rows.values():
        by_source.setdefault(r["source_target_id"], []).append(r)
    targets = {t.id: t for t in env.targets.all()}

    ssh_base, tmp = drift.build_ssh_base(connect_timeout=8)
    adopted, missing, touched = [], [], set()
    try:
        for target_id, group in by_source.items():
            box = targets[target_id]
            try:
                live = drift.read_values(ssh_base, box.host, box.dokku_app,
                                         [r["key"] for r in group])
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                messages.error(request, f"Couldn't read {box.label}: {str(exc)[:200]}")
                continue
            for r in group:
                if r["key"] not in live:
                    missing.append(r["key"])  # gone since the check — don't invent a value
                    continue
                var = Variable(
                    environment=env, key=r["key"], is_secret=True,
                    target=targets.get(r["adopt_target_id"]) if r["adopt_target_id"] else None,
                    updated_by=request.appuser.username,
                )
                var.set_value(live[r["key"]])
                var.save()
                adopted.append(r["key"])
                touched.add(box)
                AuditLog.record(
                    actor=request.appuser.username, action="adopt", environment=env.slug,
                    key=r["key"], detail=f"read from {box.label} [{r['adopt_scope']}]",
                )
    finally:
        if tmp:
            os.unlink(tmp)

    if adopted:
        env.bump_revision()
        messages.success(request, f"Adopted {len(adopted)} key(s) into Keymaker: "
                                  + ", ".join(sorted(adopted)[:8])
                                  + ("…" if len(adopted) > 8 else ""))
        _recheck(env, sorted(touched, key=lambda t: t.label), request, "adopt")
    if missing:
        messages.warning(request, "No longer set on the box (skipped): " + ", ".join(missing))
    return _back_to_env(env, view_target)


@admin_required
@require_POST
def variables_ignore(request, slug):
    """Record a decision that Keymaker should not own these on-box keys."""
    env = get_object_or_404(Environment, slug=slug)
    view_target = _env_target(env, request.POST.get("view_target"))
    keys = [k for k in request.POST.getlist("key") if k]
    reason = (request.POST.get("reason") or "").strip()[:400]
    # Ignoring while filtered to one target ignores it only there; ignoring from
    # the all-targets view means "anywhere in this environment".
    scope = view_target.label if view_target else ""
    for key in keys:
        IgnoredKey.objects.get_or_create(
            environment=env, key=key, target_label=scope,
            defaults={"reason": reason, "created_by": request.appuser.username},
        )
        AuditLog.record(actor=request.appuser.username, action="ignore_key",
                        environment=env.slug, key=key,
                        detail=f"[{scope or 'all targets'}] {reason}")
    if keys:
        messages.success(request, f"Ignoring {len(keys)} key(s) on {scope or 'all targets'} — "
                                  "they stay on the box and stop being reported.")
    return _back_to_env(env, view_target)


@admin_required
@require_POST
def variables_unignore(request, slug, ignored_id):
    env = get_object_or_404(Environment, slug=slug)
    row = get_object_or_404(IgnoredKey, id=ignored_id, environment=env)
    key, scope = row.key, row.scope_label
    row.delete()
    AuditLog.record(actor=request.appuser.username, action="unignore_key",
                    environment=env.slug, key=key, detail=f"[{scope}]")
    messages.success(request, f"{key} will be reported again on {scope}.")
    return _back_to_env(env, _env_target(env, request.POST.get("view_target")))


@admin_required
@require_POST
def variables_push(request, slug):
    """Send Keymaker's value for a key to the box(es) that lack it or disagree.

    Uses `dokku config:set --no-restart`: the value lands now, the app picks it
    up on its next restart or deploy. Only keys the latest check actually flagged
    as drifted/missing are pushed — this can't be used to blanket-overwrite a box.
    """
    env = get_object_or_404(Environment, slug=slug)
    view_target = _env_target(env, request.POST.get("view_target"))
    keys = [k for k in request.POST.getlist("key") if k]
    only_target = _env_target(env, request.POST.get("target"))
    _, variables, _, _ = _sync_state(env, view_target)

    # Group the work by box: {target: {KEY: value}}, from the *resolved* value
    # for that box so a target override wins over the base value.
    plan = {}
    for v in variables:
        if v.key not in keys or v.is_managed:
            continue
        for box in v.pushable:
            if only_target and box.target_id != only_target.id:
                continue
            plan.setdefault(box.target_id, set()).add(v.key)

    targets = {t.id: t for t in env.targets.all()}
    ssh_base, tmp = drift.build_ssh_base(connect_timeout=8)
    pushed, touched = 0, set()
    try:
        for target_id, keyset in plan.items():
            box = targets[target_id]
            resolved = env.resolved_for(box)
            values = {k: resolved[k].value for k in keyset
                      if k in resolved and not resolved[k].is_managed}
            try:
                drift.push_values(ssh_base, box.host, box.dokku_app, values)
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                messages.error(request, f"Push to {box.label} failed: {str(exc)[:200]}")
                continue
            pushed += len(values)
            touched.add(box)
            AuditLog.record(
                actor=request.appuser.username, action="push", environment=env.slug,
                key=", ".join(sorted(values))[:255],
                detail=f"config:set --no-restart {box.dokku_app} ({len(values)} key(s))",
            )
    finally:
        if tmp:
            os.unlink(tmp)

    if pushed:
        messages.success(
            request,
            f"Sent {pushed} value(s) to {', '.join(sorted(t.label for t in touched))} "
            "with --no-restart — the app picks them up on its next restart or deploy.",
        )
        _recheck(env, sorted(touched, key=lambda t: t.label), request, "push")
    elif not plan:
        messages.info(request, "Nothing to send — those keys already match the box.")
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
    _, variables, _, _ = _sync_state(env, view_target)
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
    """Per-target drift status: latest check, in-sync/drift, and staleness."""
    from .models import DriftCheck
    latest, previous = {}, {}
    for c in DriftCheck.objects.select_related("environment"):  # ordered -checked_at
        key = (c.environment_id, c.target_label)
        if key not in latest:
            latest[key] = c
        elif key not in previous:
            previous[key] = c  # the run before the latest, for managed-key change diff
    now = timezone.now()
    stale_after = timezone.timedelta(days=2)
    rows = []
    for env in _nav_environments():
        for t in env.targets.all():
            c = latest.get((env.id, t.label))
            p = previous.get((env.id, t.label))
            managed_added, managed_gone = [], []
            if c and p:
                managed_added = sorted(set(c.dokku_managed) - set(p.dokku_managed))
                managed_gone = sorted(set(p.dokku_managed) - set(c.dokku_managed))
            rows.append({
                "env": env, "target": t, "check": c,
                "stale": c is None or (now - c.checked_at) > stale_after,
                "never": c is None,
                "managed_added": managed_added, "managed_gone": managed_gone,
            })
    return render(
        request,
        "vars/checks.html",
        {"environments": _nav_environments(), "rows": rows, "user": request.appuser},
    )


@require_POST
@login_required
def checks_run(request):
    """On-demand drift check for one environment (optionally one target). Runs the
    same comparison as the scheduled cron, synchronously, and records DriftCheck
    rows so the Checks page reflects reality right now.

    Bounded by a wall-clock budget because it SSHes to each box in-request and the
    web worker has a finite timeout; any targets not reached are reported so the
    user can re-run. SSH failures (e.g. the drift key isn't registered on a host)
    surface as visible errors instead of a silent 'never'.

    `next` sends the user back to the environment page they launched it from,
    so checking is something you do in place rather than a trip to another view."""
    slug = request.POST.get("env")
    target_label = (request.POST.get("target") or "").strip() or None
    env = get_object_or_404(Environment, slug=slug)
    back = request.POST.get("next") or ""

    targets = [t for t in env.targets.all() if t.host and t.dokku_app]
    if target_label:
        targets = [t for t in targets if t.label == target_label]

    if not targets:
        messages.info(request, f"{env.name}: no checkable targets (need a host + Dokku app).")
        return redirect(back) if back.startswith("/") else redirect("checks")

    actor = f"drift-ui:{getattr(request.appuser, 'username', '') or 'user'}"
    checked, errors, not_reached = drift.run_checks(env, targets, actor)
    if checked:
        messages.success(request, f"{env.name}: checked {len(checked)} target(s).")
    for e in errors:
        messages.error(request, f"{env.name} — {e}")
    if not_reached:
        messages.info(request, f"{env.name}: {not_reached} target(s) not reached (time budget) — run again to finish.")
    return redirect(back) if back.startswith("/") else redirect("checks")


# --- audit ----------------------------------------------------------------

@login_required
def audit_log(request):
    logs = AuditLog.objects.all()[:300]
    return render(
        request,
        "vars/audit.html",
        {"environments": _nav_environments(), "logs": logs, "user": request.appuser},
    )

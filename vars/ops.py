"""Operations on an environment: check its boxes, adopt, ignore, push.

One implementation, two front doors. The web UI (vars/views.py) and the MCP
server (vars/mcp.py) both call these functions and only differ in how they
present the result — flash messages on one side, JSON on the other. Anything an
admin can do from the environment page an agent can do through MCP, and the two
cannot drift apart because neither holds any logic of its own.

Every function returns plain data and never touches a request. Scope (which box
a key was seen on, whether it becomes a shared value or an override, which keys
are actually out of step) is always derived from the latest drift checks, never
taken on trust from the caller.
"""
import os
import subprocess

from . import drift, sync
from .models import AuditLog, IgnoredKey, Variable

_BOX_ERRORS = (RuntimeError, OSError, subprocess.SubprocessError)


class OpError(ValueError):
    """A request that can't be carried out, with a message fit to show as-is."""


# --- state ---------------------------------------------------------------

def resolved_variables(env, view_target=None):
    """The variable rows for an environment, honouring an optional target filter.

    active_vars() is ordered by (label, key) so templates can {% regroup %}. With
    a target this is that target's *resolved* set: base (all-targets) values,
    the target's own overrides shadowing matching base keys, and other targets'
    overrides hidden.
    """
    variables = list(env.active_vars())
    if not view_target:
        return variables
    override_keys = {v.key for v in variables if v.target_id == view_target.id}
    return [v for v in variables
            if v.target_id == view_target.id
            or (v.target_id is None and v.key not in override_keys)]


def sync_state(env, view_target=None):
    """(targets, annotated variables, latest checks, adoption rows)."""
    targets = list(env.targets.all())
    variables = resolved_variables(env, view_target)
    checks = sync.latest_checks(env, targets)
    sync.annotate(variables, targets, checks, view_target=view_target)
    adoptions = sync.adoption_rows(
        targets, checks, {v.key for v in variables}, sync.ignored_index(env),
        view_target=view_target,
    )
    return targets, variables, checks, adoptions


def checkable(target):
    """A box Keymaker can actually reach: a Dokku app on a named host."""
    return bool(sync.checkable_targets([target]))


def target_rows(env, checks=None):
    """Per-target check status for the Targets table and the MCP report."""
    targets = list(env.targets.all())
    checks = checks if checks is not None else sync.latest_checks(env, targets)
    rows = []
    for t in targets:
        dc, fresh = checks.get(t.label, (None, False))
        rows.append({
            "target": t,
            "checkable": checkable(t),
            "check": dc,
            "fresh": fresh,
            "state": ("uncheckable" if not checkable(t) else "never" if dc is None
                      else "stale" if not fresh else "in_sync" if dc.in_sync else "drift"),
        })
    return rows


def report(env, view_target=None):
    """Names-only picture of how an environment compares to its boxes.

    This is what an agent reads before deciding to adopt, ignore or push, and
    what it reads afterwards to confirm the result. No values, ever.
    """
    targets, variables, checks, adoptions = sync_state(env, view_target)
    out_of_step = []
    for v in variables:
        boxes = [b for b in v.sync if b.status != sync.SYNCED]
        if boxes:
            out_of_step.append({
                "key": v.key,
                "scope": v.scope_label,
                "boxes": {b.label: b.status for b in boxes},
                "pushable_to": [b.label for b in v.pushable],
            })
    summary = sync.summarize(variables, adoptions, checks, targets)
    summary["last_checked_at"] = (
        summary["last_checked_at"].isoformat() if summary["last_checked_at"] else None)
    return {
        "environment": env.slug,
        "target": view_target.label if view_target else None,
        "summary": summary,
        "targets": [{
            "label": r["target"].label, "host": r["target"].host,
            "dokku_app": r["target"].dokku_app, "state": r["state"],
            "checked_at": r["check"].checked_at.isoformat() if r["check"] else None,
        } for r in target_rows(env, checks)
            if view_target is None or r["target"].id == view_target.id],
        "out_of_step": out_of_step,
        "on_box_not_in_keymaker": [
            {"key": a["key"], "boxes": a["box_labels"], "would_adopt_as": a["adopt_scope"]}
            for a in adoptions],
        "ignored": [{"key": i.key, "scope": i.scope_label, "reason": i.reason}
                    for i in sync.ignored_rows(env, view_target=view_target)],
        "status_meanings": sync.LABELS,
    }


# --- check ---------------------------------------------------------------

def check(env, actor, target=None):
    """Compare the environment's boxes to Keymaker right now."""
    targets = [t for t in env.targets.all() if checkable(t)]
    if target is not None:
        if not checkable(target):
            raise OpError(f"{target.label} has no host + Dokku app, so there is nothing to check.")
        targets = [target]
    if not targets:
        raise OpError(f"{env.slug} has no checkable targets (each needs a host and a Dokku app).")
    checked, errors, not_reached = drift.run_checks(env, targets, actor)
    return {"checked": checked, "errors": errors, "not_reached": not_reached}


def _recheck(env, touched, actor):
    """Re-measure the boxes an action just changed. Returns error strings."""
    if not touched:
        return []
    _, errors, _ = drift.run_checks(
        env, sorted(touched, key=lambda t: t.label), actor, budget_s=15.0)
    return errors


# --- adopt ---------------------------------------------------------------

def adopt(env, actor, keys=None, view_target=None, all_keys=False):
    """Take keys that exist on a box into Keymaker, reading their live values.

    Drift checks carry key names only, so this is the one path that fetches a
    value from a server. A key seen on every box becomes one all-targets value;
    otherwise it becomes an override for the box it was read from.
    """
    _, _, _, adoptions = sync_state(env, view_target)
    wanted = None if all_keys else set(keys or [])
    rows = [r for r in adoptions if wanted is None or r["key"] in wanted]
    unknown = sorted(wanted - {r["key"] for r in rows}) if wanted else []
    result = {"adopted": [], "gone_from_box": [], "not_reported_on_a_box": unknown,
              "errors": [], "recheck_errors": []}
    if not rows:
        return result

    by_source = {}
    for r in rows:
        by_source.setdefault(r["source_target_id"], []).append(r)
    targets = {t.id: t for t in env.targets.all()}

    ssh_base, tmp = drift.build_ssh_base(connect_timeout=8)
    touched = set()
    try:
        for target_id, group in by_source.items():   # one SSH read per box
            box = targets[target_id]
            try:
                live = drift.read_values(ssh_base, box.host, box.dokku_app,
                                         [r["key"] for r in group])
            except _BOX_ERRORS as exc:
                result["errors"].append(f"{box.label}: {str(exc)[:200]}")
                continue
            for r in group:
                if r["key"] not in live:
                    result["gone_from_box"].append(r["key"])  # never invent a value
                    continue
                scope = targets.get(r["adopt_target_id"]) if r["adopt_target_id"] else None
                var = Variable(environment=env, key=r["key"], is_secret=True,
                               target=scope, updated_by=actor)
                var.set_value(live[r["key"]])
                var.save()
                result["adopted"].append({"key": r["key"], "scope": r["adopt_scope"],
                                          "read_from": box.label})
                touched.add(box)
                AuditLog.record(actor=actor, action="adopt", environment=env.slug,
                                key=r["key"],
                                detail=f"read from {box.label} [{r['adopt_scope']}]")
    finally:
        if tmp:
            os.unlink(tmp)

    if result["adopted"]:
        env.bump_revision()
        result["recheck_errors"] = _recheck(env, touched, f"adopt:{actor}")
    result["revision"] = env.revision
    return result


# --- ignore --------------------------------------------------------------

def ignore(env, actor, keys, reason="", view_target=None):
    """Record a decision that Keymaker should not own these on-box keys."""
    scope = view_target.label if view_target else ""
    done = []
    for key in [k for k in (keys or []) if k]:
        IgnoredKey.objects.get_or_create(
            environment=env, key=key, target_label=scope,
            defaults={"reason": reason[:400], "created_by": actor})
        AuditLog.record(actor=actor, action="ignore_key", environment=env.slug, key=key,
                        detail=f"[{scope or 'all targets'}] {reason}"[:500])
        done.append(key)
    return {"ignored": done, "scope": scope or "all targets"}


def unignore(env, actor, ignored):
    key, scope = ignored.key, ignored.scope_label
    ignored.delete()
    AuditLog.record(actor=actor, action="unignore_key", environment=env.slug,
                    key=key, detail=f"[{scope}]")
    return {"key": key, "scope": scope}


# --- push ----------------------------------------------------------------

def push(env, actor, keys=None, view_target=None, only_target=None, all_flagged=False,
         force=False):
    """Send Keymaker's value to the box(es) that lack it or disagree.

    `dokku config:set --no-restart`: the value lands now and the app picks it up
    on its next restart or deploy. Only keys the latest check flagged as missing
    or different (or edited since that check) are sent, each box gets the value
    *resolved for that box*, and managed keys are never touched — so this cannot
    blanket-overwrite a server.

    `force` sends the named keys to every box they apply to without consulting
    the checks. It exists for "set this key and put it on the boxes" in one
    step, and requires explicit keys: there is no force-everything.
    """
    if force and not keys:
        raise OpError("force needs explicit keys.")
    _, variables, _, _ = sync_state(env, view_target)
    wanted = None if all_flagged else set(keys or [])
    plan = {}
    for v in variables:
        if v.is_managed or (wanted is not None and v.key not in wanted):
            continue
        for box in (v.sync if force else v.pushable):
            if only_target is None or box.target_id == only_target.id:
                plan.setdefault(box.target_id, set()).add(v.key)

    result = {"pushed": {}, "errors": [], "recheck_errors": [], "restarted": False,
              "note": "Set with --no-restart: each app picks the values up on its next "
                      "restart or deploy (dokku ps:restart <app>)."}
    if not plan:
        result["note"] = ("Nothing to send: no requested key is missing or different on a "
                          "freshly checked box. Run a check first if the boxes changed.")
        return result

    targets = {t.id: t for t in env.targets.all()}
    ssh_base, tmp = drift.build_ssh_base(connect_timeout=8)
    touched = set()
    try:
        for target_id, keyset in plan.items():
            box = targets[target_id]
            resolved = env.resolved_for(box)
            values = {k: resolved[k].value for k in keyset
                      if k in resolved and not resolved[k].is_managed}
            try:
                drift.push_values(ssh_base, box.host, box.dokku_app, values)
            except _BOX_ERRORS as exc:
                result["errors"].append(f"{box.label}: {str(exc)[:200]}")
                continue
            result["pushed"][box.label] = sorted(values)
            touched.add(box)
            AuditLog.record(
                actor=actor, action="push", environment=env.slug,
                key=", ".join(sorted(values))[:255],
                detail=f"config:set --no-restart {box.dokku_app} ({len(values)} key(s))")
    finally:
        if tmp:
            os.unlink(tmp)
    result["recheck_errors"] = _recheck(env, touched, f"push:{actor}")
    return result

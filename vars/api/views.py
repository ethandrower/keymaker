"""Agent / client API. Auth = Authorization: Bearer <KEYMAKER_KEY>
(see vars.auth.KeymakerKeyAuthentication). The key grants full read/write access.
"""
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from ..exporters import render_dotenv
from ..models import AuditLog, Environment, Target, Variable


class TargetNotFound(Exception):
    pass


def _resolve_target(env, ident):
    """Map a ?target= / body 'target' identifier to a Target in this env.

    Matches by label, dokku_app, or numeric id. Empty/None → None (all-targets).
    Raises TargetNotFound if a non-empty identifier matches nothing.
    """
    if not ident:
        return None
    for t in env.targets.all():
        if ident in (t.label, t.dokku_app, str(t.id)):
            return t
    raise TargetNotFound(ident)


class EnvironmentsView(APIView):
    """List environments, or create one (idempotent by slug)."""

    def get(self, request):
        qs = Environment.objects.all()
        if request.query_params.get("include_archived") != "1":
            qs = qs.filter(archived=False)
        return Response({"environments": [
            {"slug": e.slug, "name": e.name, "revision": e.revision, "archived": e.archived}
            for e in qs
        ]})

    def post(self, request):
        slug = (request.data.get("slug") or "").strip()
        if not slug:
            return Response({"detail": "slug is required."}, status=status.HTTP_400_BAD_REQUEST)
        env, created = Environment.objects.get_or_create(
            slug=slug,
            defaults={"name": request.data.get("name") or slug,
                      "kind": request.data.get("kind") or Environment.KIND_SHARED,
                      "description": request.data.get("description", "")},
        )
        if created:
            AuditLog.record(actor=str(request.user), action="env_create", environment=slug)
        return Response({"slug": env.slug, "created": created},
                        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class TargetsView(APIView):
    """List or create targets for an environment (idempotent by label)."""

    def get(self, request, slug):
        env = get_object_or_404(Environment, slug=slug)
        return Response({"targets": [
            {"id": t.id, "label": t.label, "host": t.host, "dokku_app": t.dokku_app,
             "domain": t.domain, "local_only": t.local_only} for t in env.targets.all()
        ]})

    def post(self, request, slug):
        env = get_object_or_404(Environment, slug=slug)
        label = (request.data.get("label") or "").strip()
        if not label:
            return Response({"detail": "label is required."}, status=status.HTTP_400_BAD_REQUEST)
        target, created = env.targets.get_or_create(
            label=label,
            defaults={"host": request.data.get("host", ""),
                      "dokku_app": request.data.get("dokku_app", ""),
                      "domain": request.data.get("domain", ""),
                      "local_only": bool(request.data.get("local_only", False))},
        )
        if created:
            AuditLog.record(actor=str(request.user), action="target_add",
                            environment=slug, detail=label)
        return Response({"id": target.id, "label": target.label, "created": created},
                        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class RevisionView(APIView):
    """Cheap change-detection poll for the sync client."""

    def get(self, request, slug):
        env = get_object_or_404(Environment, slug=slug)
        resp = Response({"slug": env.slug, "revision": env.revision})
        resp["ETag"] = f'"{env.revision}"'
        return resp


class VariablesView(APIView):
    """List values, or set/delete a single key."""

    def get(self, request, slug):
        env = get_object_or_404(Environment, slug=slug)
        try:
            target = _resolve_target(env, request.query_params.get("target"))
        except TargetNotFound as exc:
            return Response({"detail": f"No target '{exc}' in {env.slug}."},
                            status=status.HTTP_404_NOT_FOUND)

        include_managed = request.query_params.get("include_managed") == "1"
        # Resolved for the target (base all-targets values + that target's overrides).
        resolved = env.resolved_for(target)
        variables = sorted(resolved.values(), key=lambda v: v.key)
        if not include_managed:
            variables = [v for v in variables if not v.is_managed]

        AuditLog.record(
            actor=str(request.user), action="api_read", environment=env.slug,
            detail=f"{len(variables)} vars" + (f" for {target.label}" if target else " (all targets)"),
        )

        fmt = request.query_params.get("format")
        if fmt == "dotenv":
            body = render_dotenv(env, target=target, include_managed=include_managed)
            resp = HttpResponse(body, content_type="text/plain; charset=utf-8")
        else:
            resp = Response(
                {
                    "slug": env.slug,
                    "revision": env.revision,
                    "target": target.label if target else None,
                    "variables": {v.key: v.value for v in variables},
                }
            )
        resp["ETag"] = f'"{env.revision}"'
        return resp


class VariableDetailView(APIView):
    def put(self, request, slug, key):
        """Upsert a key at a scope. Body: value, is_secret, optional `target`
        (label/dokku_app/id; omit for all-targets) and `label`."""
        env = get_object_or_404(Environment, slug=slug)
        if key in settings.KEYMAKER_MANAGED_KEYS:
            return Response(
                {"detail": f"{key} is a managed key and cannot be set here."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            target = _resolve_target(env, request.data.get("target"))
        except TargetNotFound as exc:
            return Response({"detail": f"No target '{exc}' in {env.slug}."},
                            status=status.HTTP_404_NOT_FOUND)

        value = request.data.get("value", "")
        is_secret = bool(request.data.get("is_secret", True))
        # Match the active row at this exact scope; archived rows are left alone.
        var = env.active_vars().filter(key=key, target=target).first()
        created = var is None
        if created:
            var = Variable(environment=env, key=key, target=target)
        if var.is_managed:
            return Response(
                {"detail": "Managed variable is read-only."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        var.is_secret = is_secret
        if "label" in request.data:
            var.label = (request.data.get("label") or "")[:80]
        var.set_value(value)
        var.updated_by = str(request.user)
        var.save()
        env.bump_revision()
        AuditLog.record(
            actor=str(request.user), action="api_create" if created else "api_update",
            environment=env.slug, key=key,
            detail=("(secret)" if is_secret else value[:120]) + f" [{var.scope_label}]",
        )
        return Response(
            {"key": key, "target": target.label if target else None,
             "created": created, "revision": env.revision},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def delete(self, request, slug, key):
        env = get_object_or_404(Environment, slug=slug)
        try:
            target = _resolve_target(env, request.data.get("target"))
        except TargetNotFound as exc:
            return Response({"detail": f"No target '{exc}' in {env.slug}."},
                            status=status.HTTP_404_NOT_FOUND)
        var = env.active_vars().filter(key=key, target=target).first()
        if not var:
            return Response(status=status.HTTP_404_NOT_FOUND)
        if var.is_managed:
            return Response(
                {"detail": "Managed variable is read-only."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # Soft delete: archive (restorable in the UI) rather than destroying data.
        reason = request.data.get("reason", "") or "archived via API"
        var.archive(by=str(request.user), reason=reason)
        env.bump_revision()
        AuditLog.record(
            actor=str(request.user), action="api_archive", environment=env.slug,
            key=key, detail=f"{reason} [{var.scope_label}]",
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class AuditView(APIView):
    """Receive usage-scan results from the keymaker scan client and flag orphans.

    Body: {"results": {"KEY": {"used": bool, "references": int, "note": str}, ...}}
    Keys present in the store but absent from `results` are left untouched.
    Marks `suspected_unused` (never deletes — a human prunes in the UI).
    """

    def post(self, request, slug):
        env = get_object_or_404(Environment, slug=slug)

        results = request.data.get("results", {}) or {}
        now = timezone.now()
        flagged, cleared, unknown = [], [], []
        for var in env.active_vars():
            if var.key not in results:
                continue
            r = results[var.key]
            used = bool(r.get("used"))
            var.last_audit_at = now
            var.audit_note = (r.get("note") or "")[:400]
            if used:
                var.last_seen_at = now
                if var.suspected_unused:
                    cleared.append(var.key)
                var.suspected_unused = False
            else:
                if not var.suspected_unused:
                    flagged.append(var.key)
                var.suspected_unused = True
            var.save(update_fields=["last_audit_at", "last_seen_at", "suspected_unused", "audit_note"])

        # Keys used in code but not in the store (informational; agent passes these).
        missing = [k for k in (request.data.get("missing") or []) if not env.active_vars().filter(key=k).exists()]

        AuditLog.record(
            actor=str(request.user), action="scan", environment=env.slug,
            detail=f"flagged {len(flagged)}, cleared {len(cleared)}, missing {len(missing)}",
        )
        return Response({
            "environment": env.slug,
            "flagged_unused": flagged,
            "cleared": cleared,
            "missing_in_store": missing,
        })

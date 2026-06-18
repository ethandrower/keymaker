"""Agent / client API. Auth = bearer ApiToken (see vars.auth.ApiTokenAuthentication)."""
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from ..exporters import render_dotenv
from ..models import AuditLog, Environment, Variable


def _check_scope(request, env, *, write):
    """Validate the token's environment scope and write permission."""
    token = request.auth  # the ApiToken instance
    if token.environment_id and token.environment_id != env.id:
        return Response(
            {"detail": "Token is not scoped to this environment."},
            status=status.HTTP_403_FORBIDDEN,
        )
    if write and not token.can_write:
        return Response(
            {"detail": "Token is read-only."}, status=status.HTTP_403_FORBIDDEN
        )
    return None


class RevisionView(APIView):
    """Cheap change-detection poll for the sync client."""

    def get(self, request, slug):
        env = get_object_or_404(Environment, slug=slug)
        denied = _check_scope(request, env, write=False)
        if denied:
            return denied
        resp = Response({"slug": env.slug, "revision": env.revision})
        resp["ETag"] = f'"{env.revision}"'
        return resp


class VariablesView(APIView):
    """List values, or set/delete a single key."""

    def get(self, request, slug):
        env = get_object_or_404(Environment, slug=slug)
        denied = _check_scope(request, env, write=False)
        if denied:
            return denied

        include_managed = request.query_params.get("include_managed") == "1"
        qs = env.active_vars()
        if not include_managed:
            qs = qs.exclude(is_managed=True)
        pairs = [(v.key, v.value) for v in qs]

        AuditLog.record(
            actor=str(request.user), action="api_read", environment=env.slug,
            detail=f"{len(pairs)} vars",
        )

        fmt = request.query_params.get("format")
        if fmt == "dotenv":
            body = render_dotenv(env, include_managed=include_managed)
            resp = HttpResponse(body, content_type="text/plain; charset=utf-8")
        else:
            resp = Response(
                {
                    "slug": env.slug,
                    "revision": env.revision,
                    "variables": {k: val for k, val in pairs},
                }
            )
        resp["ETag"] = f'"{env.revision}"'
        return resp


class VariableDetailView(APIView):
    def put(self, request, slug, key):
        env = get_object_or_404(Environment, slug=slug)
        denied = _check_scope(request, env, write=True)
        if denied:
            return denied
        if key in settings.KEYMAKER_MANAGED_KEYS:
            return Response(
                {"detail": f"{key} is a managed key and cannot be set here."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        value = request.data.get("value", "")
        is_secret = bool(request.data.get("is_secret", True))
        # Operate on the active row; archived rows with the same key are left alone.
        var = env.active_vars().filter(key=key).first()
        created = var is None
        if created:
            var = Variable(environment=env, key=key)
        if var.is_managed:
            return Response(
                {"detail": "Managed variable is read-only."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        var.is_secret = is_secret
        var.set_value(value)
        var.updated_by = str(request.user)
        var.save()
        env.bump_revision()
        AuditLog.record(
            actor=str(request.user), action="api_create" if created else "api_update",
            environment=env.slug, key=key, detail="(secret)" if is_secret else value[:120],
        )
        return Response(
            {"key": key, "created": created, "revision": env.revision},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def delete(self, request, slug, key):
        env = get_object_or_404(Environment, slug=slug)
        denied = _check_scope(request, env, write=True)
        if denied:
            return denied
        var = env.active_vars().filter(key=key).first()
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
            key=key, detail=reason,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class AuditView(APIView):
    """Receive usage-scan results from the keymaker scan client and flag orphans.

    Body: {"results": {"KEY": {"used": bool, "references": int, "note": str}, ...}}
    Keys present in the store but absent from `results` are left untouched.
    Marks `suspected_unused` (never deletes — a human prunes in the UI).
    Requires a write-scoped token.
    """

    def post(self, request, slug):
        env = get_object_or_404(Environment, slug=slug)
        denied = _check_scope(request, env, write=True)
        if denied:
            return denied

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

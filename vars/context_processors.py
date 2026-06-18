"""Template context shared across pages (the sidebar's archived-env section)."""
from .auth import current_user
from .models import Environment


def nav(request):
    user = current_user(request)
    if not user:
        return {}
    return {"archived_environments": Environment.objects.filter(archived=True)}

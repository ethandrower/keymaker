"""Template context shared across pages (the sidebar's archived-env section and
the count of credentials due for rotation in the top nav)."""
from . import credentials
from .auth import current_user
from .models import Environment


def nav(request):
    user = current_user(request)
    if not user:
        return {}
    return {"archived_environments": Environment.objects.filter(archived=True),
            "credentials_due": credentials.due_count()}

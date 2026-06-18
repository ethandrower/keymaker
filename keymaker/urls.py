from django.urls import include, path

from vars import views
from vars.api import urls as api_urls

urlpatterns = [
    path("", views.home, name="home"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),

    path("environments/<slug:slug>/", views.environment_detail, name="environment_detail"),
    path("environments/<slug:slug>/download", views.environment_download, name="environment_download"),
    path("compare/", views.compare, name="compare"),
    path("cleanup/", views.cleanup, name="cleanup"),
    path("cleanup/<int:var_id>/archive", views.cleanup_archive, name="cleanup_archive"),

    # HTMX variable mutations (session-authed, admin only)
    path("environments/<slug:slug>/variables/save", views.variable_save, name="variable_save"),
    path("environments/<slug:slug>/variables/<int:var_id>/archive", views.variable_archive, name="variable_archive"),
    path("environments/<slug:slug>/variables/<int:var_id>/restore", views.variable_restore, name="variable_restore"),
    path("environments/<slug:slug>/variables/<int:var_id>/reveal", views.variable_reveal, name="variable_reveal"),

    # Environment + target management (admin)
    path("environments/new", views.environment_create, name="environment_create"),
    path("environments/<slug:slug>/targets/save", views.target_save, name="target_save"),
    path("environments/<slug:slug>/targets/<int:target_id>/delete", views.target_delete, name="target_delete"),

    # Audit
    path("audit/", views.audit_log, name="audit_log"),

    # Agent/client API
    path("api/v1/", include(api_urls)),
]

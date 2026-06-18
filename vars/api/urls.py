from django.urls import path

from . import views

urlpatterns = [
    path("environments/<slug:slug>/revision", views.RevisionView.as_view(), name="api_revision"),
    path("environments/<slug:slug>/audit", views.AuditView.as_view(), name="api_audit"),
    path("environments/<slug:slug>/variables", views.VariablesView.as_view(), name="api_variables"),
    path(
        "environments/<slug:slug>/variables/<str:key>",
        views.VariableDetailView.as_view(),
        name="api_variable_detail",
    ),
]

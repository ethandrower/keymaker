"""Template lookups for credential expiry, so the status rules live in one place
(vars/credentials.py) instead of being retyped in HTML."""

from django import template

from .. import credentials

register = template.Library()


@register.filter
def cred_status(cred):
    return credentials.status(cred) if cred else ""


@register.filter
def cred_when(cred):
    return credentials.when_text(cred) if cred else ""

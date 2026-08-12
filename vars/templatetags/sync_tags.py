"""Template lookups for sync-status glyphs and human labels, so the status
vocabulary lives in one place (vars/sync.py) instead of being retyped in HTML."""

from django import template

from .. import sync

register = template.Library()


@register.filter
def sync_glyph(status):
    return sync.GLYPHS.get(status, "·")


@register.filter
def sync_label(status):
    return sync.LABELS.get(status, status or "")

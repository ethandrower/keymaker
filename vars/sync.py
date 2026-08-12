"""Per-variable sync status: how each Keymaker variable compares to what is
actually set on each target box, derived from that target's latest DriftCheck.

Five states, every one of them *derived from a real check* — never assumed:

    synced         present both sides, same value
    drifted        present both sides, different value
    keymaker_only  held in Keymaker, not yet on the box
    server_only    set on the box, absent from Keymaker
    unknown        no check has ever run, or the last one is too old to trust

The `unknown` state matters as much as the others: a green dot drawn from a
three-week-old check is a lie, and "we never looked" must never render the same
as "we looked and it matched".
"""

from datetime import timedelta

from django.utils import timezone

from .models import DriftCheck

# The drift cron runs daily at 07:00, so a check older than two days means the
# cron itself is broken — the status is no longer evidence of anything.
STALE_AFTER = timedelta(hours=48)

SYNCED = "synced"
DRIFTED = "drifted"
KEYMAKER_ONLY = "keymaker_only"
SERVER_ONLY = "server_only"
UNKNOWN = "unknown"

LABELS = {
    SYNCED: "in sync with the box",
    DRIFTED: "value differs from the box",
    KEYMAKER_ONLY: "in Keymaker, not on the box",
    SERVER_ONLY: "on the box, not in Keymaker",
    UNKNOWN: "not checked",
}
GLYPHS = {SYNCED: "●", DRIFTED: "◐", KEYMAKER_ONLY: "○", SERVER_ONLY: "◆", UNKNOWN: "?"}

# Worst-first, so a row's headline status is its most alarming one.
SEVERITY = {DRIFTED: 0, SERVER_ONLY: 1, KEYMAKER_ONLY: 2, UNKNOWN: 3, SYNCED: 4}
MANAGED_SEVERITY = 9  # Dokku owns these; they are outside the sync contract.


def checkable_targets(targets):
    """Targets a drift check can actually reach. `local_only` boxes (localhost,
    docker-compose) are never polled, so counting them would permanently
    understate every environment."""
    return [t for t in targets if not t.local_only]


def latest_checks(env, targets):
    """{target_label: (DriftCheck | None, is_fresh)} for each checkable target."""
    now = timezone.now()
    checks = {}
    for t in checkable_targets(targets):
        dc = DriftCheck.objects.filter(environment=env, target_label=t.label).first()
        checks[t.label] = (dc, bool(dc) and (now - dc.checked_at) <= STALE_AFTER)
    return checks


def key_status(dc, key):
    """Which bucket of this drift check the key falls into. Anything the check
    covered but did not flag was compared and matched."""
    if key in dc.value_mismatch:
        return DRIFTED
    if key in dc.in_keymaker_only:
        return KEYMAKER_ONLY
    if key in dc.on_box_only:
        return SERVER_ONLY
    return SYNCED


def _applicable(var, targets, view_target):
    """Which boxes this variable is supposed to land on. A base (all-targets)
    value applies everywhere; an override applies only to its own target."""
    if view_target is not None:
        applies = var.target_id is None or var.target_id == view_target.id
        return [view_target] if applies and not view_target.local_only else []
    if var.target_id:
        return [t for t in targets if t.id == var.target_id]
    return list(targets)


def annotate(variables, targets, checks, view_target=None):
    """Attach sync status to each Variable, in place.

    Sets `.sync` ([(target_label, status)]), `.status` (single status when the
    row resolves to exactly one box, else None), `.synced_n`/`.total_n` for the
    rollup, `.severity` for sorting/filtering and `.status_tokens` for the
    client-side status filter.
    """
    reachable = checkable_targets(targets)
    for v in variables:
        if v.is_managed:
            v.sync, v.status = [], None
            v.status_label = "managed by Dokku — outside sync"
            v.synced_n = v.total_n = 0
            v.severity, v.status_tokens = MANAGED_SEVERITY, "managed"
            continue

        pairs = []
        for t in _applicable(v, reachable, view_target):
            dc, fresh = checks.get(t.label, (None, False))
            pairs.append((t.label, key_status(dc, v.key) if fresh else UNKNOWN))

        v.sync = pairs
        v.total_n = len(pairs)
        v.synced_n = sum(1 for _, s in pairs if s == SYNCED)
        v.severity = min((SEVERITY[s] for _, s in pairs), default=MANAGED_SEVERITY)
        v.status = pairs[0][1] if len(pairs) == 1 else None
        v.status_label = (
            LABELS[v.status] if v.status
            else f"{v.synced_n}/{v.total_n} boxes in sync" if pairs
            else "no box to check"
        )
        v.status_tokens = " ".join(sorted({s for _, s in pairs}))
    return variables


class ServerOnlyRow:
    """A key that exists on a box but not in Keymaker.

    Rendered as a real row in the variables table rather than a footnote, so an
    unadopted key is as visible — and as actionable — as a managed one. Drift
    checks carry key *names* only, so there is no value to show; adopting one
    opens the add-variable form with the key and target pre-filled.
    """

    is_server_only = True
    is_managed = False
    is_secret = False
    suspected_unused = False
    archived = False
    id = None
    target_id = None
    value = ""
    label = "⚠ On the box, not in Keymaker"
    status = SERVER_ONLY
    status_tokens = SERVER_ONLY
    severity = SEVERITY[SERVER_ONLY]

    def __init__(self, key, boxes):
        self.key = key
        self.boxes = boxes  # [(target_label, target_id)]
        self.sync = [(label, SERVER_ONLY) for label, _ in boxes]
        self.total_n = len(boxes)
        self.synced_n = 0
        self.status_label = "on %s, not in Keymaker" % ", ".join(b for b, _ in boxes)
        self.adopt_target_id = boxes[0][1] if len(boxes) == 1 else ""


def server_only_rows(targets, checks, known_keys, view_target=None):
    """Build the pseudo-rows for on-box-only keys, newest check wins.

    Only fresh checks contribute: a stale check's `on_box_only` list is no more
    trustworthy than its green dots.
    """
    ids = {t.label: t.id for t in targets}
    found = {}
    for label, (dc, fresh) in checks.items():
        if not fresh or (view_target is not None and label != view_target.label):
            continue
        for key in dc.on_box_only:
            if key not in known_keys:
                found.setdefault(key, []).append((label, ids.get(label, "")))
    return [ServerOnlyRow(k, found[k]) for k in sorted(found)]


def summarize(env_variables, extra_rows, checks, targets):
    """Environment-level headline: how much of this env we can actually vouch for."""
    reachable = checkable_targets(targets)
    checked = [lbl for lbl, (_, fresh) in checks.items() if fresh]
    stamps = [dc.checked_at for dc, fresh in checks.values() if fresh and dc]
    counts = {DRIFTED: 0, KEYMAKER_ONLY: 0, UNKNOWN: 0, SYNCED: 0}
    for v in env_variables:
        for _, status in getattr(v, "sync", []):
            if status in counts:
                counts[status] += 1
    return {
        "targets_total": len(reachable),
        "targets_checked": len(checked),
        "targets_unchecked": sorted(set(t.label for t in reachable) - set(checked)),
        "last_checked_at": max(stamps) if stamps else None,
        "drifted": counts[DRIFTED],
        "keymaker_only": counts[KEYMAKER_ONLY],
        "server_only": len(extra_rows),
        "unknown": counts[UNKNOWN],
        "synced": counts[SYNCED],
        "clean": not (counts[DRIFTED] or counts[KEYMAKER_ONLY] or counts[UNKNOWN] or extra_rows),
    }

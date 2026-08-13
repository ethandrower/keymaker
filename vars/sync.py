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
as "we looked and it matched". For the same reason every status carries the
timestamp it came from, so the UI can always answer "says who, and when?".

Keys found on a box but absent from Keymaker are not variable rows — they are
triage, not configuration. They surface in their own adoption panel above the
table (`adoption_rows`), where the only two answers are adopt or ignore.
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

# States a "send to app server" push would fix: Keymaker holds a value the box
# is missing or disagrees with.
PUSHABLE = (DRIFTED, KEYMAKER_ONLY)


class BoxStatus:
    """One variable's state on one box, and the check that established it."""

    def __init__(self, target, status, checked_at):
        self.label = target.label
        self.target_id = target.id
        self.status = status
        self.checked_at = checked_at  # None when never checked or stale

    @property
    def glyph(self):
        return GLYPHS[self.status]

    @property
    def text(self):
        return LABELS[self.status]

    @property
    def pushable(self):
        return self.status in PUSHABLE

    @property
    def tooltip(self):
        when = (f"checked {self.checked_at:%Y-%m-%d %H:%M} UTC" if self.checked_at
                else f"no check in the last {int(STALE_AFTER.total_seconds() // 3600)}h")
        return f"{self.label}: {self.text} ({when})"


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

    Sets `.sync` (list of BoxStatus), `.status` (single status when the row
    resolves to exactly one box, else None), `.synced_n`/`.total_n` for the
    rollup, `.pushable` (the boxes a push would fix), `.severity` for sorting
    and `.status_tokens` for the client-side status filter.
    """
    reachable = checkable_targets(targets)
    for v in variables:
        if v.is_managed:
            v.sync, v.status, v.pushable = [], None, []
            v.status_label = "managed by Dokku — outside sync"
            v.synced_n = v.total_n = 0
            v.severity, v.status_tokens = MANAGED_SEVERITY, "managed"
            continue

        boxes = []
        for t in _applicable(v, reachable, view_target):
            dc, fresh = checks.get(t.label, (None, False))
            status = key_status(dc, v.key) if fresh else UNKNOWN
            boxes.append(BoxStatus(t, status, dc.checked_at if fresh else None))

        v.sync = boxes
        v.total_n = len(boxes)
        v.synced_n = sum(1 for b in boxes if b.status == SYNCED)
        v.pushable = [b for b in boxes if b.pushable]
        v.severity = min((SEVERITY[b.status] for b in boxes), default=MANAGED_SEVERITY)
        v.status = boxes[0].status if len(boxes) == 1 else None
        v.status_label = (
            LABELS[v.status] if v.status
            else f"{v.synced_n}/{v.total_n} boxes in sync" if boxes
            else "no box to check"
        )
        v.status_tokens = " ".join(sorted({b.status for b in boxes}))
    return variables


def ignored_index(env):
    """{(key, target_label)} of decisions to leave a key alone. A blank
    target_label means "on every box in this environment"."""
    return {(i.key, i.target_label) for i in env.ignored_keys.all()}


def is_ignored(ignored, key, target_label):
    return (key, target_label) in ignored or (key, "") in ignored


def adoption_rows(targets, checks, known_keys, ignored, view_target=None):
    """Keys found on a box that Keymaker doesn't hold — the triage list.

    Only fresh checks contribute: a stale check's `on_box_only` list is no more
    trustworthy than its green dots. Each row knows every box it was seen on, so
    a key present on all of them can be adopted once as an all-targets value
    rather than as one override per box.
    """
    reachable = {t.label: t for t in checkable_targets(targets)}
    found = {}
    for label, (dc, fresh) in checks.items():
        if not fresh or (view_target is not None and label != view_target.label):
            continue
        for key in dc.on_box_only:
            if key in known_keys or is_ignored(ignored, key, label):
                continue
            found.setdefault(key, []).append(reachable[label])

    scope_total = 1 if view_target is not None else len(reachable)
    rows = []
    for key in sorted(found):
        boxes = sorted(found[key], key=lambda t: t.label)
        everywhere = len(boxes) == scope_total and scope_total > 1
        rows.append({
            "key": key,
            "boxes": boxes,
            "box_labels": [b.label for b in boxes],
            # Adopt as a shared base value when the key is on every box we can
            # see, as an override when only some boxes have it.
            "adopt_target_id": "" if everywhere else boxes[0].id,
            "adopt_scope": "all targets" if everywhere else boxes[0].label,
            # Which box to read the value from. Values may legitimately differ
            # between boxes; we adopt one and the next check reports the rest.
            "source_target_id": boxes[0].id,
        })
    return rows


def ignored_rows(env, view_target=None):
    """Ignored keys, for the reversible list under the adoption panel."""
    rows = list(env.ignored_keys.all())
    if view_target is not None:
        rows = [i for i in rows if i.target_label in ("", view_target.label)]
    return rows


def summarize(env_variables, adoptions, checks, targets):
    """Environment-level headline: how much of this env we can actually vouch for."""
    reachable = checkable_targets(targets)
    checked = [lbl for lbl, (_, fresh) in checks.items() if fresh]
    stamps = [dc.checked_at for dc, fresh in checks.values() if fresh and dc]
    counts = {DRIFTED: 0, KEYMAKER_ONLY: 0, UNKNOWN: 0, SYNCED: 0}
    for v in env_variables:
        for box in getattr(v, "sync", []):
            if box.status in counts:
                counts[box.status] += 1
    return {
        "targets_total": len(reachable),
        "targets_checked": len(checked),
        "targets_unchecked": sorted(set(t.label for t in reachable) - set(checked)),
        "last_checked_at": max(stamps) if stamps else None,
        "drifted": counts[DRIFTED],
        "keymaker_only": counts[KEYMAKER_ONLY],
        "server_only": len(adoptions),
        "unknown": counts[UNKNOWN],
        "synced": counts[SYNCED],
        "clean": not (counts[DRIFTED] or counts[KEYMAKER_ONLY] or counts[UNKNOWN] or adoptions),
    }

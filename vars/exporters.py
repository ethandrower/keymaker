"""Shared rendering of an environment's variables to .env text.

Used by both the agent/client API (vars/api/views.py) and the UI download
(vars/views.py) so the two never drift.
"""


def dotenv_quote(value: str) -> str:
    """Quote a value for .env output when it contains whitespace or special chars."""
    if value == "" or any(c in value for c in " \t\n\"'#$"):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{escaped}"'
    return value


def render_dotenv(env, *, include_managed=False) -> str:
    """Return the environment's live variables as `.env` text (KEY=value lines)."""
    qs = env.active_vars()
    if not include_managed:
        qs = qs.exclude(is_managed=True)
    lines = [f"{v.key}={dotenv_quote(v.value)}" for v in qs]
    return "\n".join(lines) + ("\n" if lines else "")

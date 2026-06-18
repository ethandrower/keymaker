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


def render_dotenv(env, *, target=None, include_managed=False) -> str:
    """Return the environment's resolved variables as `.env` text (KEY=value lines).

    With `target`, returns the base (all-targets) values overlaid with that target's
    overrides. Without a target, returns only the all-targets base.
    """
    resolved = env.resolved_for(target)
    variables = sorted(resolved.values(), key=lambda v: v.key)
    if not include_managed:
        variables = [v for v in variables if not v.is_managed]
    lines = [f"{v.key}={dotenv_quote(v.value)}" for v in variables]
    return "\n".join(lines) + ("\n" if lines else "")

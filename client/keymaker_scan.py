#!/usr/bin/env python3
"""Keymaker codebase ↔ store reconciler.

Pulls an environment's keys from Keymaker, scans a codebase (and, optionally, its
imported packages) for references to each one, and classifies them:

  * USED      — referenced in the code or its dependencies
  * UNUSED    — referenced nowhere (bloat candidate)
  * UNCERTAIN — no direct reference but the key looks dynamically constructed or
                shares a prefix with a used key; an optional LLM tie-breaker
                resolves these to used/unused with a reason
  * MISSING   — referenced in the code but absent from the store (a gap)

By default it prints a report. With --submit it sends results back to Keymaker,
flagging UNUSED keys as "suspected unused" (it never deletes — a human prunes in
the Cleanup UI).

Config via flags or environment:
  KEYMAKER_URL        base URL, e.g. https://keymaker.citemed.com
  KEYMAKER_KEY        the Keymaker key (same one used to log into the UI)
  KEYMAKER_ENV        environment slug to reconcile, e.g. staging
  ANTHROPIC_API_KEY   enables the LLM tie-breaker (with --llm)
  KEYMAKER_LLM_MODEL  override the model (default: claude-opus-4-8)

Examples:
  python3 keymaker_scan.py --path ../citemed_web
  python3 keymaker_scan.py --path ../citemed_web --packages ../citemed_web/.venv --llm
  python3 keymaker_scan.py --path . --llm --submit
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

# Source files worth scanning for env usage.
# Note: .env / .env.* are deliberately excluded — they DECLARE values, they don't
# CONSUME them, so counting them would mark every stored key "used" trivially.
CODE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".java",
    ".kt", ".php", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".toml",
    ".ini", ".cfg", ".conf", ".tf", ".tfvars", ".properties", ".gradle",
}
CODE_FILENAMES = {"Dockerfile", "Procfile", "Makefile", "docker-compose.yml"}

# Directories never worth walking for the *source* scan (deps are scanned separately).
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build", ".next", ".idea", "site-packages",
    "coverage", "htmlcov", ".tox",
}

# How env vars get referenced — used to extract keys the code reads (for MISSING
# detection) and to detect dynamic access (which makes a zero-ref key UNCERTAIN).
ENV_KEY_PATTERNS = [
    re.compile(r"""os\.environ(?:\.get)?\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""os\.environ\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),
    re.compile(r"""os\.getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""\benv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),         # django-environ
    re.compile(r"""\bconfig\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),      # python-decouple
    re.compile(r"""process\.env\.([A-Za-z_][A-Za-z0-9_]*)"""),            # node
    re.compile(r"""process\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),
    re.compile(r"""ENV\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),     # ruby
]
# Dynamic access: env read with a non-literal key, or an f-string key.
DYNAMIC_ACCESS = [
    re.compile(r"""os\.(?:environ\.get|getenv)\(\s*[a-zA-Z_]\w*"""),       # os.getenv(var)
    re.compile(r"""os\.environ\[\s*[a-zA-Z_]\w*\s*\]"""),
    re.compile(r"""os\.(?:environ\.get|getenv)\(\s*f["']"""),              # f-string key
    re.compile(r"""process\.env\[[^"'\]]"""),
]


# --- HTTP to Keymaker -----------------------------------------------------

def km_get(base, path, token, accept="application/json"):
    req = urllib.request.Request(
        f"{base}{path}", headers={"Authorization": f"Bearer {token}", "Accept": accept}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def km_post(base, path, token, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base}{path}", data=data, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_store_keys(base, env, token):
    body = km_get(base, f"/api/v1/environments/{env}/variables?include_managed=1", token)
    data = json.loads(body)
    # Managed keys are returned but we exclude them from bloat analysis.
    managed = set()
    nonmanaged = km_get(base, f"/api/v1/environments/{env}/variables", token)
    nonmanaged_keys = set(json.loads(nonmanaged)["variables"].keys())
    all_keys = set(data["variables"].keys())
    managed = all_keys - nonmanaged_keys
    return nonmanaged_keys, managed


# --- scanning -------------------------------------------------------------

def iter_files(root, *, scanning_deps=False):
    for dirpath, dirnames, filenames in os.walk(root):
        if not scanning_deps:
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        else:
            dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__"}]
        for name in filenames:
            ext = os.path.splitext(name)[1]
            if ext in CODE_EXTS or name in CODE_FILENAMES:
                yield os.path.join(dirpath, name)


def scan_tree(root, keys, *, scanning_deps=False):
    """Single pass per file: count references to each key, extract referenced keys,
    detect dynamic access. Returns (counts, samples, referenced, dynamic_found)."""
    # One alternation regex matching any known key as a whole word.
    key_re = re.compile(r"\b(" + "|".join(re.escape(k) for k in keys) + r")\b") if keys else None
    counts = {k: 0 for k in keys}
    samples = {k: [] for k in keys}
    referenced = set()
    dynamic_found = False

    for path in iter_files(root, scanning_deps=scanning_deps):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue

        if key_re:
            for m in key_re.finditer(text):
                k = m.group(1)
                counts[k] += 1
                if len(samples[k]) < 3:
                    line_no = text.count("\n", 0, m.start()) + 1
                    samples[k].append(f"{path}:{line_no}")

        if not scanning_deps:  # only mine the app's own code for referenced/dynamic
            for pat in ENV_KEY_PATTERNS:
                referenced.update(pat.findall(text))
            if not dynamic_found:
                dynamic_found = any(p.search(text) for p in DYNAMIC_ACCESS)

    return counts, samples, referenced, dynamic_found


# --- LLM tie-breaker ------------------------------------------------------

def llm_judge(key, *, siblings, dynamic, model, api_key):
    """Ask Claude whether a zero-reference key is likely still used. Raw HTTP so the
    client stays dependency-free; defaults to claude-opus-4-8."""
    prompt = (
        "You are auditing environment variables for dead config. A variable was NOT "
        "found by a literal text search of the codebase or its installed dependencies.\n\n"
        f"Variable: {key}\n"
        f"Other variables sharing its prefix that ARE used in code: "
        f"{', '.join(siblings) if siblings else 'none'}\n"
        f"The codebase contains dynamic env access (e.g. os.getenv(variable), "
        f"f-string keys): {dynamic}\n\n"
        "Common libraries read env vars internally without the name appearing in app "
        "code (e.g. boto3 reads AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, celery reads "
        "CELERY_*, gunicorn reads WEB_CONCURRENCY). Consider whether this variable is "
        "likely read that way, constructed dynamically, or genuinely unused.\n\n"
        'Respond with JSON: {"used": <true|false>, "reason": "<one sentence>"}. '
        "Use used=true if it is plausibly still consumed at runtime; used=false only "
        "if it appears genuinely dead."
    )
    body = {
        "model": model,
        "max_tokens": 512,
        "messages": [{"role": "user", "content": prompt}],
        "output_config": {
            "format": {
                "type": "json_schema",
                "schema": {
                    "type": "object",
                    "properties": {
                        "used": {"type": "boolean"},
                        "reason": {"type": "string"},
                    },
                    "required": ["used", "reason"],
                    "additionalProperties": False,
                },
            }
        },
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if data.get("stop_reason") == "refusal":
        return {"used": True, "reason": "LLM declined to judge; kept as used (safe default)"}
    text = next((b["text"] for b in data["content"] if b["type"] == "text"), "{}")
    verdict = json.loads(text)
    return {"used": bool(verdict.get("used")), "reason": verdict.get("reason", "")}


def prefix_of(key):
    return key.split("_")[0] if "_" in key else key


# --- main -----------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Reconcile a codebase against Keymaker")
    p.add_argument("--url", default=os.environ.get("KEYMAKER_URL"), help="Keymaker base URL (env: KEYMAKER_URL)")
    p.add_argument("--key", default=os.environ.get("KEYMAKER_KEY"), help="Keymaker key (env: KEYMAKER_KEY)")
    p.add_argument("--env", default=os.environ.get("KEYMAKER_ENV"), help="environment slug to reconcile (env: KEYMAKER_ENV)")
    p.add_argument("--path", default=".", help="codebase root to scan")
    p.add_argument("--packages", action="append", default=[],
                   help="also scan this dependency dir (e.g. a .venv or node_modules); repeatable")
    p.add_argument("--llm", action="store_true", help="use Claude to judge ambiguous keys (needs ANTHROPIC_API_KEY)")
    p.add_argument("--llm-model", default=os.environ.get("KEYMAKER_LLM_MODEL", "claude-opus-4-8"),
                   help="model for the tie-breaker (env: KEYMAKER_LLM_MODEL)")
    p.add_argument("--submit", action="store_true", help="POST results back to flag unused keys")
    p.add_argument("--json", action="store_true", help="machine-readable output (for CI)")
    args = p.parse_args()

    missing_cfg = [n for n in ("url", "key", "env") if not getattr(args, n)]
    if missing_cfg:
        p.error("missing required config: " + ", ".join(missing_cfg))

    base = args.url.rstrip("/")
    keys, managed = fetch_store_keys(base, args.env, args.key)
    if not keys:
        print(f"No (non-managed) variables in environment '{args.env}'.")
        return

    # Scan app code (mines references + dynamic access), then dependencies.
    counts, samples, referenced, dynamic = scan_tree(args.path, keys)
    for pkg in args.packages:
        if not os.path.isdir(pkg):
            print(f"warning: --packages path not found: {pkg}", file=sys.stderr)
            continue
        dep_counts, _, _, _ = scan_tree(pkg, keys, scanning_deps=True)
        for k, c in dep_counts.items():
            counts[k] += c

    used_keys = {k for k, c in counts.items() if c > 0}
    used_prefixes = {prefix_of(k) for k in used_keys}

    results = {}   # key -> {used, references, note}
    classification = {"used": [], "unused": [], "uncertain": []}

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    for key in sorted(keys):
        c = counts[key]
        if c > 0:
            results[key] = {"used": True, "references": c, "note": f"{c} refs; e.g. {samples[key][0]}" if samples[key] else f"{c} refs"}
            classification["used"].append(key)
            continue

        # Zero references — is it ambiguous?
        siblings = sorted(k for k in used_keys if prefix_of(k) == prefix_of(key))
        ambiguous = bool(siblings) or dynamic
        if ambiguous and args.llm and api_key:
            try:
                verdict = llm_judge(key, siblings=siblings, dynamic=dynamic,
                                    model=args.llm_model, api_key=api_key)
            except (urllib.error.URLError, json.JSONDecodeError, KeyError) as exc:
                verdict = {"used": True, "reason": f"LLM error ({exc}); kept as used"}
            note = f"0 refs; LLM: {verdict['reason']}"
            if verdict["used"]:
                results[key] = {"used": True, "references": 0, "note": note}
                classification["used"].append(key)
            else:
                results[key] = {"used": False, "references": 0, "note": note}
                classification["unused"].append(key)
        elif ambiguous:
            note = "0 refs but dynamic access / prefix-sibling in use — uncertain"
            results[key] = {"used": True, "references": 0, "note": note}  # don't flag uncertain
            classification["uncertain"].append(key)
        else:
            results[key] = {"used": False, "references": 0, "note": "0 refs in code or dependencies"}
            classification["unused"].append(key)

    missing = sorted(referenced - keys - managed)

    if args.json:
        print(json.dumps({"environment": args.env, "results": results,
                          "missing": missing, "classification": classification}, indent=2))
    else:
        _print_report(args.env, classification, results, missing, managed)

    if args.submit:
        resp = km_post(base, f"/api/v1/environments/{args.env}/audit", args.key,
                       {"results": results, "missing": missing})
        print(f"\nSubmitted to Keymaker: flagged {len(resp.get('flagged_unused', []))} "
              f"as suspected-unused, cleared {len(resp.get('cleared', []))}.")


def _print_report(env, classification, results, missing, managed):
    print(f"\n=== Keymaker reconcile: {env} ===")
    print(f"  used:      {len(classification['used'])}")
    print(f"  UNUSED:    {len(classification['unused'])}  (bloat candidates)")
    print(f"  uncertain: {len(classification['uncertain'])}  (no LLM verdict — review manually)")
    print(f"  missing:   {len(missing)}  (in code, not in store)")
    print(f"  managed:   {len(managed)}  (skipped)")

    if classification["unused"]:
        print("\n-- suspected UNUSED --")
        for k in classification["unused"]:
            print(f"  {k:32} {results[k]['note']}")
    if classification["uncertain"]:
        print("\n-- UNCERTAIN (run with --llm to resolve) --")
        for k in classification["uncertain"]:
            print(f"  {k:32} {results[k]['note']}")
    if missing:
        print("\n-- MISSING from store (used in code) --")
        for k in missing:
            print(f"  {k}")


if __name__ == "__main__":
    main()

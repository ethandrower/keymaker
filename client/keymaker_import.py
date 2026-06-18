#!/usr/bin/env python3
"""Bootstrap a Keymaker environment from live Dokku apps (Dokku → Keymaker).

Pulls each Dokku app's config, then builds one Keymaker environment where each
app is a **target**. Keys identical across *all* apps become the **all-targets
base**; everything else becomes a **per-target override** carrying that app's
value. Resolving for any target therefore reproduces that app's exact current
config — no app silently gains or loses a key.

Secret values are transferred over the API but never printed. Dokku-managed/auto
keys (DATABASE_URL, REDIS_URL, PORT, DOKKU_*) are skipped. Run with --dry-run
first to see the plan (key names + scope only).

Config via flags or environment:
  KEYMAKER_URL   Keymaker base URL
  KEYMAKER_KEY   the Keymaker key (UI/API)

Example:
  python3 keymaker_import.py --dokku-host dokku@178.105.80.165 \
    --env staging --name Staging --domain-suffix .staging.citemed.com \
    --apps dev-ethan,dev-kesha,dev-max --dry-run
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

SKIP = {"DATABASE_URL", "REDIS_URL", "PORT", "GIT_REV", "DATABASE_DEFAULT_URL"}
SKIP_PREFIX = ("DOKKU_",)

# Heuristic labels for visual sectioning in the UI.
LABELS = [
    (("AWS_", "DEFAULT_FILE_STORAGE"), "AWS / S3"),
    (("MAILGUN_", "EMAIL", "DEFAULT_FROM_EMAIL", "SUPPORT_EMAILS"), "Email"),
    (("PROXY_",), "Scraping / proxy"),
    (("CELERY_", "CLOUDAMQP_URL", "REMOTE_SCRAPER_QUEUE"), "Celery / queues"),
    (("LANGCHAIN_", "LANGSMITH_"), "LangChain"),
    (("SECRET_KEY", "ALLOWED_HOSTS", "SITE_URL", "CORS_", "ENV", "DJANGO_",
      "DEBUG", "APP_VERSION"), "Django"),
    (("SCRAPER_", "SPATIAL_", "VISION_", "SURYA_", "FULLTEXT_", "ARTICLE_GALAXY_",
      "GOOGLE_API_KEY", "PUBMED_", "VITE_"), "Integrations / features"),
]


def label_for(key):
    for prefixes, label in LABELS:
        if key.startswith(prefixes) or key in prefixes:
            return label
    return ""


# --- Dokku side -----------------------------------------------------------

def dokku_apps(host):
    out = subprocess.run(["ssh", "-o", "BatchMode=yes", host, "apps:list"],
                         capture_output=True, text=True, timeout=30)
    return [l.strip() for l in out.stdout.splitlines()
            if l.strip() and not l.startswith("=")]


def dokku_config(host, app):
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", host, "config:export", "--format", "json", app],
                       capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            pass
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", host, "config:export", "--format", "envfile", app],
                       capture_output=True, text=True, timeout=30)
    cfg = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[7:]
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            cfg[k.strip()] = v.strip().strip("'\"")
    return cfg


def meaningful(cfg):
    return {k: v for k, v in cfg.items() if k not in SKIP and not k.startswith(SKIP_PREFIX)}


# --- Keymaker API ---------------------------------------------------------

def api(base, key, method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        f"{base}{path}", data=data, method=method,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode()
        return json.loads(body) if body else {}


# --- main -----------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Bootstrap a Keymaker environment from Dokku apps")
    p.add_argument("--keymaker-url", default=os.environ.get("KEYMAKER_URL"), help="Keymaker base URL")
    p.add_argument("--key", default=os.environ.get("KEYMAKER_KEY"), help="Keymaker key")
    p.add_argument("--dokku-host", required=True, help="ssh target, e.g. dokku@178.105.80.165")
    p.add_argument("--env", required=True, help="Keymaker environment slug to create/populate")
    p.add_argument("--name", default=None, help="Display name (default: slug)")
    p.add_argument("--apps", default=None, help="comma-separated app list (default: all dev-* apps on the host)")
    p.add_argument("--domain-suffix", default="", help="derive each target's domain as <app><suffix>")
    p.add_argument("--dry-run", action="store_true", help="print the plan (no values) without writing")
    args = p.parse_args()
    if not args.dry_run and (not args.keymaker_url or not args.key):
        p.error("KEYMAKER_URL and KEYMAKER_KEY are required (unless --dry-run)")

    base = (args.keymaker_url or "").rstrip("/")
    host = args.dokku_host
    apps = ([a.strip() for a in args.apps.split(",") if a.strip()] if args.apps
            else [a for a in dokku_apps(host) if a.startswith("dev-")])
    if not apps:
        p.error("no apps found/selected")
    print(f"Apps → targets ({len(apps)}): {', '.join(apps)}")

    configs = {a: meaningful(dokku_config(host, a)) for a in apps}
    allkeys = sorted(set().union(*configs.values()))

    base_vars, overrides = {}, {a: {} for a in apps}  # key->value ; app->{key:value}
    for k in allkeys:
        present = [a for a in apps if k in configs[a]]
        vals = {configs[a][k] for a in present}
        if len(present) == len(apps) and len(vals) == 1:
            base_vars[k] = configs[apps[0]][k]
        else:
            for a in present:
                overrides[a][k] = configs[a][k]

    print(f"\nPlan for env '{args.env}':")
    print(f"  base (all-targets): {len(base_vars)} keys → {', '.join(sorted(base_vars))}")
    for a in apps:
        if overrides[a]:
            print(f"  {a} overrides: {len(overrides[a])} → {', '.join(sorted(overrides[a]))}")
    if args.dry_run:
        print("\n[dry-run] no changes written.")
        return

    # 1. environment
    api(base, args.key, "POST", "/api/v1/environments",
        {"slug": args.env, "name": args.name or args.env})
    # 2. targets (one per app)
    for a in apps:
        api(base, args.key, "POST", f"/api/v1/environments/{args.env}/targets",
            {"label": a, "host": host.split("@")[-1], "dokku_app": a,
             "domain": (a + args.domain_suffix) if args.domain_suffix else ""})
    # 3. base variables (all-targets)
    n = 0
    for k, v in base_vars.items():
        api(base, args.key, "PUT", f"/api/v1/environments/{args.env}/variables/{k}",
            {"value": v, "is_secret": True, "label": label_for(k)})
        n += 1
    # 4. per-target overrides
    m = 0
    for a in apps:
        for k, v in overrides[a].items():
            api(base, args.key, "PUT", f"/api/v1/environments/{args.env}/variables/{k}",
                {"value": v, "is_secret": True, "label": label_for(k), "target": a})
            m += 1
    print(f"\nDone: {len(apps)} targets, {n} base vars, {m} per-target overrides written to '{args.env}'.")


if __name__ == "__main__":
    main()

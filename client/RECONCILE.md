# Keymaker reconciler (`keymaker_scan.py`)

Finds **env bloat** and **gaps** by diffing a Keymaker environment against a real
codebase. Pure Python stdlib — nothing to `pip install` on the host or in CI.

## What it does

1. Pulls the environment's (non-managed) keys from Keymaker.
2. Scans the codebase — and, with `--packages`, its installed dependencies — for
   references to each key, in a single pass per file.
3. Classifies every key:
   - **used** — referenced in code or a dependency.
   - **unused** — referenced nowhere (bloat candidate).
   - **uncertain** — zero references, but the key is dynamically accessed
     (`os.getenv(var)`, f-string keys) or shares a prefix with a used key
     (`AWS_SECRET_ACCESS_KEY` next to `AWS_ACCESS_KEY_ID`). Resolved by the LLM
     tie-breaker when `--llm` is on; otherwise left for a human.
   - **missing** — read in code (`os.environ[...]`, `process.env.X`, `env("X")`,
     …) but absent from the store. These are gaps that will break a deploy.
4. With `--submit`, posts results to `POST /api/v1/environments/<env>/audit`,
   which flags unused keys as **suspected-unused** (shown in the Cleanup UI).
   It never deletes — a human prunes.

## Config

| Flag / env | Purpose |
| --- | --- |
| `--url` / `KEYMAKER_URL` | Keymaker base URL |
| `--key` / `KEYMAKER_KEY` | the Keymaker key (same one used to log into the UI) |
| `--env` / `KEYMAKER_ENV` | environment slug |
| `--path` | codebase root to scan (default `.`) |
| `--packages` | also scan a dependency dir (`.venv`, `node_modules`); repeatable |
| `--llm` + `ANTHROPIC_API_KEY` | use Claude to judge uncertain keys |
| `--llm-model` / `KEYMAKER_LLM_MODEL` | model for the tie-breaker (default `claude-opus-4-8`) |
| `--submit` | flag unused keys back in Keymaker |
| `--json` | machine-readable output (for CI) |

## Why an LLM tie-breaker

A literal grep can't tell that `AWS_SECRET_ACCESS_KEY` is read by boto3, `CELERY_*`
by celery, or that a prefix-constructed key is alive. Rather than guess, the
scanner sends only the **ambiguous** keys to Claude with their context (prefix
siblings in use, whether the codebase does dynamic env access) and asks for a
used/unused judgment with a one-line reason — cheap, since it's just the gray area.
The tie-breaker uses raw HTTP to the Anthropic API to keep the client
dependency-free; set `ANTHROPIC_API_KEY` and pass `--llm`.

## Examples

```bash
# Report only (safe), against an app + its virtualenv, with the LLM tie-breaker:
KEYMAKER_URL=https://keymaker.citemed.com KEYMAKER_KEY=$KEYMAKER_KEY KEYMAKER_ENV=staging \
  ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  python3 keymaker_scan.py --path ../citemed_web --packages ../citemed_web/.venv --llm

# Same, but also flag unused keys back in Keymaker:
python3 keymaker_scan.py --path ../citemed_web \
  --packages ../citemed_web/.venv --llm --submit

# CI gate: fail the build if keys are used in code but missing from the store
python3 keymaker_scan.py --path . --json | \
  python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(1 if d['missing'] else 0)"
```

## Notes

- `.env` files are **not** counted as usage — they declare values, they don't
  consume them, so counting them would mark every key "used."
- Managed keys (`DATABASE_URL`, `REDIS_URL`) are excluded from bloat analysis.
- Recommended cadence: run in CI (report + fail on `missing`), and on a schedule
  with `--submit` to keep the Cleanup view current.

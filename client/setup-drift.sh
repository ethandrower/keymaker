#!/usr/bin/env bash
# Registers the dedicated keymaker-drift public key on the Dokku hosts so the
# drift_check command can SSH in to read live config. Run this ONCE, from a
# machine with root SSH to the hosts. The matching private key already lives in
# the Keymaker app config (KEYMAKER_SSH_KEY_B64) — this only deals with the
# public key.
#
# Scheduling is NOT installed here: the daily drift run is defined in app.json's
# `cron` block and applied automatically by Dokku on deploy. This script only
# verifies that cron registered and kicks off a first run.
#
#   bash client/setup-drift.sh
#
# Safe to re-run. Dokku hosts use a restricted `dokku` user, so this key can only
# run dokku commands (read config), not a general shell.
set -euo pipefail

PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpjcOVPxT0Atc4iv/GPpdrl+3wo5R9V/K0WYK3xtzyx keymaker-drift'

# Dokku hosts that hold drift targets (staging dev boxes + pre-prod + remington, prod).
DOKKU_HOSTS=(178.105.80.165 161.35.106.225)
KEYMAKER_HOST=116.203.82.103

echo "==> Registering keymaker-drift key on Dokku hosts"
for h in "${DOKKU_HOSTS[@]}"; do
  echo "  - $h"
  echo "$PUBKEY" | ssh "root@$h" "dokku ssh-keys:add keymaker-drift" || \
    echo "    (already present or failed — check manually)"
done

echo "==> Verifying the app.json drift-check cron registered on the Keymaker host ($KEYMAKER_HOST)"
ssh "root@$KEYMAKER_HOST" '
  if dokku cron:list keymaker 2>/dev/null | grep -q "manage.py drift_check"; then
    echo "  cron present:"; dokku cron:list keymaker | grep drift_check
  else
    echo "  WARNING: no drift_check cron found. Ensure app.json deployed and your"
    echo "  Dokku version supports cron (>= 0.25). Re-deploy, or add a host crontab"
    echo "  as a fallback: 0 7 * * * dokku run keymaker python manage.py drift_check"
  fi
'

echo "==> Kicking off a first drift run now"
ssh "root@$KEYMAKER_HOST" "dokku run keymaker python manage.py drift_check" || true

echo "Done. The Checks page + per-key liveness badges will populate from this run on."

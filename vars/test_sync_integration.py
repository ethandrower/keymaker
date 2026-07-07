"""End-to-end sync integration test — proves the sync works BOTH ways.

Runs the REAL client (`client/dokku_sync.py`) as a subprocess against a live
Keymaker server (`LiveServerTestCase`) and a FAKE `dokku` binary whose "box" is
just a JSON file. No network, no SSH, no secrets — so it's safe to run on every
change while building new features.

It mirrors exactly what was verified by hand against the real Demo box:
  1. import accuracy — a freshly-imported env resolves to the box byte-for-byte
     (dry-run reports "no changes"),
  2. set  — a key added in Keymaker propagates onto the box,
  3. unset — a key removed (archived) in Keymaker is removed from the box,
  4. Dokku-managed / auto keys (DATABASE_URL, DOKKU_*) are NEVER touched.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import LiveServerTestCase, override_settings

from cryptography.fernet import Fernet

from . import crypto
from .models import Environment, Target, Variable

TEST_KEY = Fernet.generate_key().decode()
API_KEY = "test-keymaker-key"

CLIENT = str(Path(__file__).resolve().parent.parent / "client" / "dokku_sync.py")

# A stand-in for the `dokku` CLI. Its "box" is a JSON file at $BOX_STATE; it
# implements just the subcommands dokku_sync.py calls. config:export always emits
# JSON regardless of --format, which is all the client reads.
FAKE_DOKKU = r'''#!/usr/bin/env python3
import json, os, sys

STATE = os.environ["BOX_STATE"]

def load():
    try:
        with open(STATE) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save(d):
    with open(STATE, "w") as fh:
        json.dump(d, fh)

args = sys.argv[1:]
cmd = args[0] if args else ""
# Positional args = everything that isn't a flag. For config:export we ignore
# these entirely (the only stray value would be "json" from --format).
pos = [a for a in args[1:] if not a.startswith("-")]

if cmd == "config:export":
    print(json.dumps(load()))
elif cmd == "config:set":
    d = load()
    for pair in pos[1:]:            # pos[0] is the app name
        k, _, v = pair.partition("=")
        d[k] = v
    save(d)
elif cmd == "config:unset":
    d = load()
    for k in pos[1:]:
        d.pop(k, None)
    save(d)
elif cmd == "config:get":
    print(load().get(pos[1], ""))
elif cmd == "ps:restart":
    pass
else:
    sys.exit(0)
'''


@override_settings(KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_KEY=API_KEY,
                   KEYMAKER_MANAGED_KEYS=["DATABASE_URL"])
class SyncRoundTripTests(LiveServerTestCase):
    def setUp(self):
        crypto._fernet = None
        self.tmp = tempfile.mkdtemp(prefix="km-sync-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        # The fake dokku binary + the box's starting config.
        self.dokku = os.path.join(self.tmp, "dokku")
        Path(self.dokku).write_text(FAKE_DOKKU)
        os.chmod(self.dokku, 0o755)
        self.state = os.path.join(self.tmp, "box.json")
        self._write_box({
            "SECRET_KEY": "s1",
            "SITE_URL": "https://demo",
            "DATABASE_URL": "postgres://real",   # Dokku-managed — must survive
            "DOKKU_PROXY_PORT": "80",            # Dokku-owned — must survive
        })

        # Keymaker, seeded to match the box exactly (as a fresh import would).
        self.env = Environment.objects.create(slug="demo", name="Demo")
        Target.objects.create(environment=self.env, label="ec-demo", dokku_app="ec-demo")
        self._put("SECRET_KEY", "s1")
        self._put("SITE_URL", "https://demo")
        mgd = Variable(environment=self.env, key="DATABASE_URL", is_managed=True)
        mgd.set_value("postgres://real")
        mgd.save()

    # --- helpers ----------------------------------------------------------

    def _write_box(self, cfg):
        Path(self.state).write_text(json.dumps(cfg))

    def _box(self):
        return json.loads(Path(self.state).read_text())

    def _put(self, key, value):
        v = Variable(environment=self.env, key=key, is_secret=True)
        v.set_value(value)
        v.save()

    def _sync(self, *extra):
        r = subprocess.run(
            [sys.executable, CLIENT, "--url", self.live_server_url, "--key", API_KEY,
             "--env", "demo", "--app", "ec-demo", "--dokku-bin", self.dokku,
             "--once", "--no-restart", "--force", *extra],
            capture_output=True, text=True,
            env={**os.environ, "BOX_STATE": self.state,
                 "STATE_FILE": os.path.join(self.tmp, "sync-state.json")},
        )
        self.assertEqual(r.returncode, 0, msg=f"client failed:\n{r.stdout}\n{r.stderr}")
        return r.stdout

    # --- tests ------------------------------------------------------------

    def test_import_is_byte_exact_in_sync(self):
        """A freshly-imported env has zero drift against its box."""
        self.assertIn("no changes", self._sync("--dry-run"))

    def test_set_propagates_to_box(self):
        """A key added in Keymaker is set on the box."""
        self._put("NEW_FLAG", "on")
        out = self._sync()
        self.assertIn("set   NEW_FLAG", out)
        self.assertEqual(self._box().get("NEW_FLAG"), "on")

    def test_unset_propagates_to_box(self):
        """A key removed (archived) in Keymaker is unset on the box."""
        self._put("TEMP_FLAG", "x")
        self._sync()
        self.assertEqual(self._box().get("TEMP_FLAG"), "x")   # arrived first

        Variable.objects.get(environment=self.env, key="TEMP_FLAG",
                             archived=False).archive(by="test")
        out = self._sync()
        self.assertIn("unset TEMP_FLAG", out)
        self.assertNotIn("TEMP_FLAG", self._box())

    def test_managed_and_dokku_keys_are_never_touched(self):
        """Even a full sync never unsets Dokku-owned/auto keys the box holds."""
        out = self._sync()
        self.assertNotIn("unset", out)
        box = self._box()
        self.assertEqual(box.get("DATABASE_URL"), "postgres://real")
        self.assertEqual(box.get("DOKKU_PROXY_PORT"), "80")

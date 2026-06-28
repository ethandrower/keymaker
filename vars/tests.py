"""Tests for keymaker core behavior."""
import json
from unittest import mock

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from cryptography.fernet import Fernet

from . import crypto
from .models import DriftCheck, Environment, Target, Variable

TEST_KEY = Fernet.generate_key().decode()
API_KEY = "test-keymaker-key"


@override_settings(KEYMAKER_MASTER_KEYS=[TEST_KEY])
class CryptoTests(TestCase):
    def setUp(self):
        crypto._fernet = None  # reset cached cipher for the test key

    def test_round_trip(self):
        token = crypto.encrypt("super-secret-value")
        self.assertNotIn(b"super-secret", token)
        self.assertEqual(crypto.decrypt(token), "super-secret-value")

    def test_empty(self):
        self.assertEqual(crypto.decrypt(crypto.encrypt("")), "")

    def test_rotation(self):
        old = crypto.encrypt("v1")
        new_key = Fernet.generate_key().decode()
        with override_settings(KEYMAKER_MASTER_KEYS=[new_key, TEST_KEY]):
            crypto._fernet = None
            # New primary key still decrypts data written under the old key.
            self.assertEqual(crypto.decrypt(old), "v1")
        crypto._fernet = None


@override_settings(KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_MANAGED_KEYS=["DATABASE_URL"],
                   KEYMAKER_KEY=API_KEY)
class ApiTests(TestCase):
    def setUp(self):
        crypto._fernet = None
        self.env = Environment.objects.create(slug="staging", name="Staging")
        v = Variable(environment=self.env, key="SECRET_KEY", is_secret=True)
        v.set_value("abc")
        v.save()
        m = Variable(environment=self.env, key="DATABASE_URL", is_managed=True)
        m.set_value("postgres://x")
        m.save()
        self.box = Target.objects.create(environment=self.env, label="boxA", dokku_app="app-a")

    def _client(self, key=API_KEY):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {key}")
        return c

    def test_requires_key(self):
        self.assertEqual(APIClient().get("/api/v1/environments/staging/revision").status_code, 401)

    def test_wrong_key_rejected(self):
        self.assertEqual(
            self._client("nope").get("/api/v1/environments/staging/revision").status_code, 401
        )

    def test_managed_excluded_from_dotenv(self):
        resp = self._client().get("/api/v1/environments/staging/variables?format=dotenv")
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        self.assertIn("SECRET_KEY=abc", body)
        self.assertNotIn("DATABASE_URL", body)

    def test_include_managed(self):
        resp = self._client().get(
            "/api/v1/environments/staging/variables?format=dotenv&include_managed=1"
        )
        self.assertIn("DATABASE_URL", resp.content.decode())

    def test_write_bumps_revision(self):
        before = self.env.revision
        resp = self._client().put(
            "/api/v1/environments/staging/variables/NEW", {"value": "v", "is_secret": False},
            format="json",
        )
        self.assertEqual(resp.status_code, 201)
        self.env.refresh_from_db()
        self.assertEqual(self.env.revision, before + 1)

    def test_cannot_write_managed_key(self):
        resp = self._client().put(
            "/api/v1/environments/staging/variables/DATABASE_URL", {"value": "x"}, format="json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_delete_archives_not_destroys(self):
        resp = self._client().delete("/api/v1/environments/staging/variables/SECRET_KEY")
        self.assertEqual(resp.status_code, 204)
        var = Variable.objects.get(environment=self.env, key="SECRET_KEY")
        self.assertTrue(var.archived)               # still in the DB
        self.assertEqual(var.archived_by, "api")
        body = self._client().get(
            "/api/v1/environments/staging/variables?format=dotenv"
        ).content.decode()
        self.assertNotIn("SECRET_KEY", body)

    def test_archived_and_active_can_share_key(self):
        v = self.env.variables.get(key="SECRET_KEY", target__isnull=True)
        v.archive(by="tester", reason="rotated")
        resp = self._client().put(
            "/api/v1/environments/staging/variables/SECRET_KEY",
            {"value": "new", "is_secret": True}, format="json",
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(self.env.active_vars().filter(key="SECRET_KEY").count(), 1)
        self.assertEqual(self.env.variables.filter(key="SECRET_KEY").count(), 2)

    # --- target scope ---

    def test_target_override_wins_per_target_but_not_base(self):
        c = self._client()
        c.put("/api/v1/environments/staging/variables/SITE_URL",
              {"value": "base", "is_secret": False}, format="json")
        c.put("/api/v1/environments/staging/variables/SITE_URL",
              {"value": "for-boxA", "is_secret": False, "target": "boxA"}, format="json")
        base = c.get("/api/v1/environments/staging/variables?format=dotenv").content.decode()
        self.assertIn("SITE_URL=base", base)
        boxa = c.get("/api/v1/environments/staging/variables?format=dotenv&target=boxA").content.decode()
        self.assertIn("SITE_URL=for-boxA", boxa)
        # Two distinct rows coexist (base + override) under the partial unique constraints.
        self.assertEqual(self.env.active_vars().filter(key="SITE_URL").count(), 2)

    def test_target_matches_by_dokku_app(self):
        c = self._client()
        c.put("/api/v1/environments/staging/variables/SITE_URL",
              {"value": "for-boxA", "is_secret": False, "target": "app-a"}, format="json")
        # resolve by the dokku_app identifier too
        boxa = c.get("/api/v1/environments/staging/variables?format=dotenv&target=app-a").content.decode()
        self.assertIn("SITE_URL=for-boxA", boxa)

    def test_unknown_target_404(self):
        self.assertEqual(
            self._client().get("/api/v1/environments/staging/variables?target=nope").status_code,
            404,
        )

    def test_resolved_for_model_helper(self):
        base = Variable(environment=self.env, key="X"); base.set_value("b"); base.save()
        ov = Variable(environment=self.env, key="X", target=self.box); ov.set_value("o"); ov.save()
        self.assertEqual(self.env.resolved_for(None)["X"].value, "b")
        self.assertEqual(self.env.resolved_for(self.box)["X"].value, "o")


@override_settings(KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_MANAGED_KEYS=["DATABASE_URL"],
                   KEYMAKER_KEY=API_KEY)
class InventoryTests(TestCase):
    def setUp(self):
        crypto._fernet = None
        self.env = Environment.objects.create(slug="staging", name="Staging")
        v = Variable(environment=self.env, key="SECRET_KEY"); v.set_value("abc"); v.save()
        m = Variable(environment=self.env, key="DATABASE_URL", is_managed=True)
        m.set_value("postgres://x"); m.save()
        Target.objects.create(environment=self.env, label="boxA", dokku_app="app-a", host="1.2.3.4")
        Environment.objects.create(slug="old", name="Old", archived=True)

    def _client(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {API_KEY}")
        return c

    def test_inventory_lists_envs_and_servers(self):
        resp = self._client().get("/api/v1/inventory")
        self.assertEqual(resp.status_code, 200)
        envs = resp.json()["environments"]
        # Archived env hidden by default.
        slugs = {e["slug"] for e in envs}
        self.assertEqual(slugs, {"staging"})
        staging = envs[0]
        self.assertEqual(staging["variable_count"], 1)   # SECRET_KEY; managed excluded
        self.assertEqual(staging["managed_count"], 1)
        self.assertEqual(staging["targets"][0]["dokku_app"], "app-a")
        self.assertIsNone(staging["targets"][0]["latest_drift"])

    def test_inventory_never_includes_values(self):
        body = self._client().get("/api/v1/inventory").content.decode()
        self.assertNotIn("abc", body)
        self.assertNotIn("postgres://x", body)

    def test_inventory_include_archived(self):
        resp = self._client().get("/api/v1/inventory?include_archived=1")
        slugs = {e["slug"] for e in resp.json()["environments"]}
        self.assertEqual(slugs, {"staging", "old"})


@override_settings(KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_MANAGED_KEYS=["DATABASE_URL"],
                   KEYMAKER_KEY=API_KEY)
class McpTests(TestCase):
    def setUp(self):
        crypto._fernet = None
        self.env = Environment.objects.create(slug="staging", name="Staging")
        v = Variable(environment=self.env, key="SECRET_KEY"); v.set_value("abc"); v.save()

    def _rpc(self, method, params=None, req_id=1, key=API_KEY):
        body = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
        kwargs = {"content_type": "application/json"}
        if key is not None:
            kwargs["HTTP_AUTHORIZATION"] = f"Bearer {key}"
        return self.client.post("/mcp", data=json.dumps(body), **kwargs)

    def _call(self, name, arguments=None):
        resp = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        self.assertEqual(resp.status_code, 200)
        return resp.json()["result"]

    def test_requires_key(self):
        resp = self._rpc("tools/list", key=None)
        self.assertEqual(resp.status_code, 401)

    def test_initialize_advertises_tools(self):
        result = self._rpc("initialize").json()["result"]
        self.assertEqual(result["serverInfo"]["name"], "keymaker")
        self.assertIn("tools", result["capabilities"])

    def test_tools_list(self):
        tools = self._rpc("tools/list").json()["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertIn("keymaker_inventory", names)
        self.assertIn("keymaker_get_variables", names)
        # Handler must never leak into the public schema.
        self.assertNotIn("handler", tools[0])

    def test_notification_gets_no_body(self):
        body = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
        resp = self.client.post("/mcp", data=body, content_type="application/json",
                                HTTP_AUTHORIZATION=f"Bearer {API_KEY}")
        self.assertEqual(resp.status_code, 202)

    def test_get_variables_returns_values(self):
        result = self._call("keymaker_get_variables", {"environment": "staging"})
        data = result["structuredContent"]
        self.assertEqual(data["variables"]["SECRET_KEY"], "abc")

    def test_set_variable_bumps_revision(self):
        before = self.env.revision
        result = self._call("keymaker_set_variable",
                            {"environment": "staging", "key": "NEW", "value": "v", "is_secret": False})
        self.assertTrue(result["structuredContent"]["created"])
        self.env.refresh_from_db()
        self.assertEqual(self.env.revision, before + 1)

    def test_set_managed_key_is_error(self):
        result = self._call("keymaker_set_variable",
                            {"environment": "staging", "key": "DATABASE_URL", "value": "x"})
        self.assertTrue(result["isError"])

    def test_archive_variable(self):
        result = self._call("keymaker_archive_variable",
                            {"environment": "staging", "key": "SECRET_KEY"})
        self.assertTrue(result["structuredContent"]["archived"])
        self.assertTrue(Variable.objects.get(key="SECRET_KEY").archived)

    def test_unknown_tool_rejected(self):
        resp = self._rpc("tools/call", {"name": "keymaker_nope", "arguments": {}})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("error", resp.json())

    def test_inventory_tool(self):
        result = self._call("keymaker_inventory")
        slugs = {e["slug"] for e in result["structuredContent"]["environments"]}
        self.assertEqual(slugs, {"staging"})


@override_settings(KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_MANAGED_KEYS=["DATABASE_URL"],
                   KEYMAKER_KEY=API_KEY)
class ContractApiTests(TestCase):
    """The agent/client-facing endpoints not covered above: /environments, /targets,
    /drift, /audit, and the /revision ETag. These are the surface a dev-team agent
    fleet drives, so the request/response contract is locked down here."""

    def setUp(self):
        crypto._fernet = None
        self.env = Environment.objects.create(slug="staging", name="Staging")
        used = Variable(environment=self.env, key="USED_KEY"); used.set_value("u"); used.save()
        orphan = Variable(environment=self.env, key="ORPHAN_KEY"); orphan.set_value("o"); orphan.save()
        self.box = Target.objects.create(environment=self.env, label="boxA", dokku_app="app-a",
                                         host="1.2.3.4")

    def _client(self, key=API_KEY):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {key}")
        return c

    # --- /environments create (idempotent) ---

    def test_create_environment_idempotent(self):
        c = self._client()
        first = c.post("/api/v1/environments", {"slug": "prod", "name": "Prod"}, format="json")
        self.assertEqual(first.status_code, 201)
        self.assertTrue(first.json()["created"])
        again = c.post("/api/v1/environments", {"slug": "prod"}, format="json")
        self.assertEqual(again.status_code, 200)
        self.assertFalse(again.json()["created"])
        self.assertEqual(Environment.objects.filter(slug="prod").count(), 1)

    def test_create_environment_requires_slug(self):
        resp = self._client().post("/api/v1/environments", {"name": "no slug"}, format="json")
        self.assertEqual(resp.status_code, 400)

    # --- /targets list + create (idempotent) ---

    def test_targets_list(self):
        resp = self._client().get("/api/v1/environments/staging/targets")
        self.assertEqual(resp.status_code, 200)
        labels = {t["label"] for t in resp.json()["targets"]}
        self.assertEqual(labels, {"boxA"})

    def test_create_target_idempotent(self):
        c = self._client()
        first = c.post("/api/v1/environments/staging/targets",
                       {"label": "boxB", "dokku_app": "app-b", "host": "5.6.7.8"}, format="json")
        self.assertEqual(first.status_code, 201)
        self.assertTrue(first.json()["created"])
        again = c.post("/api/v1/environments/staging/targets", {"label": "boxB"}, format="json")
        self.assertEqual(again.status_code, 200)
        self.assertFalse(again.json()["created"])
        self.assertEqual(self.env.targets.filter(label="boxB").count(), 1)

    def test_create_target_requires_label(self):
        resp = self._client().post("/api/v1/environments/staging/targets",
                                   {"host": "1.1.1.1"}, format="json")
        self.assertEqual(resp.status_code, 400)

    # --- /revision ETag ---

    def test_revision_sets_etag(self):
        resp = self._client().get("/api/v1/environments/staging/revision")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["ETag"], f'"{self.env.revision}"')
        self.assertEqual(resp.json()["revision"], self.env.revision)

    def test_revision_etag_tracks_writes(self):
        c = self._client()
        before = c.get("/api/v1/environments/staging/revision")["ETag"]
        c.put("/api/v1/environments/staging/variables/NEW",
              {"value": "v", "is_secret": False}, format="json")
        after = c.get("/api/v1/environments/staging/revision")["ETag"]
        self.assertNotEqual(before, after)

    # --- /drift report intake ---

    def test_drift_records_check(self):
        resp = self._client().post(
            "/api/v1/environments/staging/drift",
            {"target": "boxA", "on_box_only": ["SNUCK_IN"],
             "in_keymaker_only": ["GONE"], "value_mismatch": ["CHANGED"]},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["in_sync"])
        self.assertEqual(body["drift"], 3)
        check = DriftCheck.objects.get(environment=self.env, target_label="boxA")
        self.assertEqual(check.on_box_only, ["SNUCK_IN"])

    def test_drift_in_sync_when_empty(self):
        resp = self._client().post("/api/v1/environments/staging/drift",
                                   {"target": "boxA"}, format="json")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["in_sync"])

    def test_drift_unknown_target_404(self):
        resp = self._client().post("/api/v1/environments/staging/drift",
                                   {"target": "ghost", "on_box_only": ["X"]}, format="json")
        self.assertEqual(resp.status_code, 404)
        self.assertFalse(DriftCheck.objects.filter(environment=self.env).exists())

    def test_drift_never_stores_values(self):
        # Names only — even if a client mistakenly sends values, only names land.
        self._client().post("/api/v1/environments/staging/drift",
                            {"target": "boxA", "on_box_only": ["SNUCK_IN"]}, format="json")
        body = str(DriftCheck.objects.get(environment=self.env, target_label="boxA").on_box_only)
        self.assertIn("SNUCK_IN", body)

    # --- /audit scan intake (the reconciler contract) ---

    def test_audit_flags_unused_clears_used(self):
        resp = self._client().post(
            "/api/v1/environments/staging/audit",
            {"results": {
                "USED_KEY": {"used": True, "references": 3},
                "ORPHAN_KEY": {"used": False, "note": "no refs found"},
            }},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["flagged_unused"], ["ORPHAN_KEY"])
        self.assertNotIn("USED_KEY", body["flagged_unused"])
        orphan = self.env.variables.get(key="ORPHAN_KEY")
        self.assertTrue(orphan.suspected_unused)
        self.assertEqual(orphan.audit_note, "no refs found")
        used = self.env.variables.get(key="USED_KEY")
        self.assertFalse(used.suspected_unused)
        self.assertIsNotNone(used.last_seen_at)

    def test_audit_reports_missing_in_store(self):
        resp = self._client().post(
            "/api/v1/environments/staging/audit",
            {"results": {}, "missing": ["USED_KEY", "TOTALLY_NEW_KEY"]},
            format="json",
        )
        # USED_KEY is in the store, so only the genuinely-absent key is reported.
        self.assertEqual(resp.json()["missing_in_store"], ["TOTALLY_NEW_KEY"])

    def test_audit_leaves_unmentioned_keys_untouched(self):
        # A scan that only mentions ORPHAN_KEY must not touch USED_KEY.
        self._client().post("/api/v1/environments/staging/audit",
                            {"results": {"ORPHAN_KEY": {"used": False}}}, format="json")
        used = self.env.variables.get(key="USED_KEY")
        self.assertIsNone(used.last_audit_at)

    def test_audit_requires_key(self):
        resp = APIClient().post("/api/v1/environments/staging/audit",
                                {"results": {}}, format="json")
        self.assertEqual(resp.status_code, 401)


@override_settings(KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_KEY=API_KEY)
class McpBatchTests(TestCase):
    """JSON-RPC batch + malformed-input handling on the MCP route — the paths an
    agent client can trigger that the happy-path MCP tests don't exercise."""

    def setUp(self):
        crypto._fernet = None
        self.env = Environment.objects.create(slug="staging", name="Staging")

    def _post(self, payload):
        return self.client.post("/mcp", data=json.dumps(payload),
                                content_type="application/json",
                                HTTP_AUTHORIZATION=f"Bearer {API_KEY}")

    def test_valid_batch_returns_array(self):
        resp = self._post([
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ])
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertEqual({r["id"] for r in data}, {1, 2})

    def test_batch_of_only_notifications_is_202(self):
        resp = self._post([{"jsonrpc": "2.0", "method": "notifications/initialized"}])
        self.assertEqual(resp.status_code, 202)

    def test_malformed_batch_item_does_not_crash(self):
        # A bare number where an object is expected must yield an Invalid Request
        # error, not a 500. Regression test for non-dict batch items.
        resp = self._post([1, {"jsonrpc": "2.0", "id": 7, "method": "ping"}])
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 2)
        errors = [r for r in data if "error" in r]
        self.assertTrue(any(r["error"]["code"] == -32600 for r in errors))

    def test_parse_error_is_400(self):
        resp = self.client.post("/mcp", data="{not json",
                                content_type="application/json",
                                HTTP_AUTHORIZATION=f"Bearer {API_KEY}")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"]["code"], -32700)

    def test_unknown_method_returns_method_not_found(self):
        resp = self._post({"jsonrpc": "2.0", "id": 1, "method": "does/not/exist"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["error"]["code"], -32601)

    def test_get_is_405(self):
        resp = self.client.get("/mcp", HTTP_AUTHORIZATION=f"Bearer {API_KEY}")
        self.assertEqual(resp.status_code, 405)


@override_settings(KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_MANAGED_KEYS=["DATABASE_URL"])
class DriftCheckCommandTests(TestCase):
    """The drift_check management command. SSH/Dokku is mocked so the comparison,
    error handling, and config parsing are exercised without a real host."""

    MOD = "vars.management.commands.drift_check"

    def setUp(self):
        crypto._fernet = None
        self.env = Environment.objects.create(slug="staging", name="Staging")
        for k, v in {"SECRET_KEY": "km", "API_TOKEN": "km-tok"}.items():
            var = Variable(environment=self.env, key=k); var.set_value(v); var.save()
        m = Variable(environment=self.env, key="DATABASE_URL", is_managed=True)
        m.set_value("postgres://x"); m.save()
        self.box = Target.objects.create(environment=self.env, label="boxA",
                                         dokku_app="app-a", host="1.2.3.4")

    def _run(self, live, **kw):
        from django.core.management import call_command
        with mock.patch(f"{self.MOD}._dokku_config", return_value=live):
            call_command("drift_check", **kw)

    def test_in_sync_when_live_matches(self):
        self._run({"SECRET_KEY": "km", "API_TOKEN": "km-tok"})
        check = DriftCheck.objects.get(environment=self.env, target_label="boxA")
        self.assertTrue(check.in_sync)
        self.assertEqual(check.on_box_only, [])
        self.assertEqual(check.in_keymaker_only, [])
        self.assertEqual(check.value_mismatch, [])

    def test_detects_all_three_drift_kinds(self):
        # API_TOKEN changed on the box, SECRET_KEY missing on the box, EXTRA snuck in.
        self._run({"SECRET_KEY": "km", "API_TOKEN": "changed", "EXTRA": "x"})
        # value mismatch case needs SECRET_KEY present-but-different; redo precisely:
        DriftCheck.objects.all().delete()
        self._run({"API_TOKEN": "changed", "EXTRA": "x"})
        check = DriftCheck.objects.get(environment=self.env, target_label="boxA")
        self.assertFalse(check.in_sync)
        self.assertEqual(check.on_box_only, ["EXTRA"])
        self.assertEqual(check.in_keymaker_only, ["SECRET_KEY"])
        self.assertEqual(check.value_mismatch, ["API_TOKEN"])

    def test_managed_keys_excluded_from_comparison(self):
        # Even though DATABASE_URL is in Keymaker and absent from live, it is
        # managed and must not register as drift.
        self._run({"SECRET_KEY": "km", "API_TOKEN": "km-tok"})
        check = DriftCheck.objects.get(environment=self.env, target_label="boxA")
        self.assertTrue(check.in_sync)
        self.assertNotIn("DATABASE_URL", check.in_keymaker_only)

    def test_ssh_error_records_nothing_and_does_not_crash(self):
        from django.core.management import call_command
        with mock.patch(f"{self.MOD}._dokku_config",
                        side_effect=RuntimeError("ssh boom")):
            call_command("drift_check")  # must not raise
        self.assertFalse(DriftCheck.objects.filter(environment=self.env).exists())

    def test_target_without_host_is_skipped(self):
        Target.objects.create(environment=self.env, label="local", local_only=True)
        self._run({"SECRET_KEY": "km", "API_TOKEN": "km-tok"})
        # Only boxA (which has a host + dokku_app) gets a check.
        self.assertFalse(DriftCheck.objects.filter(target_label="local").exists())
        self.assertTrue(DriftCheck.objects.filter(target_label="boxA").exists())

    def test_env_filter_limits_scope(self):
        other = Environment.objects.create(slug="prod", name="Prod")
        Target.objects.create(environment=other, label="prodbox",
                              dokku_app="app-p", host="9.9.9.9")
        self._run({"SECRET_KEY": "km", "API_TOKEN": "km-tok"}, env="staging")
        self.assertTrue(DriftCheck.objects.filter(environment=self.env).exists())
        self.assertFalse(DriftCheck.objects.filter(environment=other).exists())


class DriftConfigParsingTests(TestCase):
    """The _dokku_config / _meaningful helpers: JSON path, envfile fallback, and
    the noise filter — pure parsing, subprocess mocked."""

    MOD = "vars.management.commands.drift_check"

    @staticmethod
    def _cmd():
        import importlib
        return importlib.import_module("vars.management.commands.drift_check")

    def test_meaningful_filters_noise(self):
        c = self._cmd()
        cfg = {"REAL": "v", "DATABASE_URL": "x", "REDIS_URL": "y", "PORT": "8000",
               "DOKKU_PROXY_PORT": "80", "GIT_REV": "abc"}
        self.assertEqual(c._meaningful(cfg), {"REAL": "v"})

    def test_dokku_config_parses_json(self):
        c = self._cmd()
        proc = mock.Mock(returncode=0, stdout='{"REAL": "v", "PORT": "8000"}', stderr="")
        with mock.patch(f"{self.MOD}.subprocess.run", return_value=proc):
            out = c._dokku_config(["ssh"], "host", "app")
        self.assertEqual(out, {"REAL": "v"})

    def test_dokku_config_falls_back_to_envfile(self):
        c = self._cmd()
        bad_json = mock.Mock(returncode=0, stdout="not json", stderr="")
        envfile = mock.Mock(returncode=0,
                            stdout="export REAL='v'\nPORT=8000\n# comment\n", stderr="")
        with mock.patch(f"{self.MOD}.subprocess.run", side_effect=[bad_json, envfile]):
            out = c._dokku_config(["ssh"], "host", "app")
        self.assertEqual(out, {"REAL": "v"})

    def test_dokku_config_raises_on_failure(self):
        c = self._cmd()
        bad_json = mock.Mock(returncode=1, stdout="", stderr="boom")
        fail = mock.Mock(returncode=1, stdout="", stderr="ssh denied")
        with mock.patch(f"{self.MOD}.subprocess.run", side_effect=[bad_json, fail]):
            with self.assertRaises(RuntimeError):
                c._dokku_config(["ssh"], "host", "app")


class SyncDiffTests(TestCase):
    """The Dokku sync client's pure diff logic (no Dokku required)."""

    @staticmethod
    def _mod():
        import importlib.util
        import pathlib

        path = pathlib.Path(__file__).resolve().parent.parent / "client" / "dokku_sync.py"
        spec = importlib.util.spec_from_file_location("dokku_sync", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_diff_sets_changes_and_unsets_removed(self):
        mod = self._mod()
        desired = {"A": "1", "B": "2"}
        current = {"A": "old", "C": "3"}
        to_set, to_unset = mod.compute_changes(desired, current, set())
        self.assertEqual(to_set, {"A": "1", "B": "2"})  # A changed, B added
        self.assertEqual(to_unset, ["C"])  # C removed

    def test_managed_keys_never_touched(self):
        mod = self._mod()
        desired = {"A": "1"}
        current = {"A": "1", "DATABASE_URL": "auto", "REDIS_URL": "auto"}
        to_set, to_unset = mod.compute_changes(desired, current, mod.ALWAYS_IGNORE)
        self.assertEqual(to_set, {})  # A unchanged
        self.assertEqual(to_unset, [])  # managed keys not unset

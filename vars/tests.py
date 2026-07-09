"""Tests for keymaker core behavior."""
import json
from unittest import mock

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from cryptography.fernet import Fernet

from . import auth, crypto
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
    error handling, and config parsing are exercised without a real host. The
    comparison itself lives in vars.drift (shared with the on-demand UI check)."""

    MOD = "vars.drift"

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
        import io
        from django.core.management import call_command
        with mock.patch(f"{self.MOD}.dokku_config", return_value=live):
            call_command("drift_check", stdout=io.StringIO(), stderr=io.StringIO(), **kw)

    def test_in_sync_when_live_matches(self):
        self._run({"SECRET_KEY": "km", "API_TOKEN": "km-tok"})
        check = DriftCheck.objects.get(environment=self.env, target_label="boxA")
        self.assertTrue(check.in_sync)
        self.assertEqual(check.on_box_only, [])
        self.assertEqual(check.in_keymaker_only, [])
        self.assertEqual(check.value_mismatch, [])

    def test_detects_all_three_drift_kinds(self):
        # API_TOKEN value changed on the box, SECRET_KEY missing on the box (in
        # Keymaker only), EXTRA snuck in directly on the box.
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
        import io
        from django.core.management import call_command
        with mock.patch(f"{self.MOD}.dokku_config",
                        side_effect=RuntimeError("ssh boom")):
            call_command("drift_check", stdout=io.StringIO(),
                         stderr=io.StringIO())  # must not raise
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

    def test_dokku_managed_surfaced_not_counted_as_drift(self):
        # Dokku's own keys live on every box. They must be recorded under
        # dokku_managed (visible), never as on_box_only drift, and never break in_sync.
        self._run({"SECRET_KEY": "km", "API_TOKEN": "km-tok",
                   "DOKKU_APP_TYPE": "dockerfile", "GIT_REV": "abc", "DATABASE_URL": "auto"})
        check = DriftCheck.objects.get(environment=self.env, target_label="boxA")
        self.assertTrue(check.in_sync)
        self.assertEqual(check.on_box_only, [])
        self.assertEqual(check.dokku_managed, ["DATABASE_URL", "DOKKU_APP_TYPE", "GIT_REV"])

    def test_dokku_managed_change_recorded_and_audited(self):
        # A new Dokku-managed key appearing on the box between runs must surface as a
        # change (audit note) even though it is never synced.
        self._run({"SECRET_KEY": "km", "API_TOKEN": "km-tok", "DOKKU_APP_TYPE": "dockerfile"})
        self._run({"SECRET_KEY": "km", "API_TOKEN": "km-tok",
                   "DOKKU_APP_TYPE": "dockerfile", "DOKKU_PROXY_PORT": "80"})
        rows = list(DriftCheck.objects.filter(target_label="boxA").order_by("checked_at"))
        self.assertEqual(rows[0].dokku_managed, ["DOKKU_APP_TYPE"])
        self.assertEqual(rows[1].dokku_managed, ["DOKKU_APP_TYPE", "DOKKU_PROXY_PORT"])
        from vars.models import AuditLog
        self.assertTrue(AuditLog.objects.filter(action="drift_check",
                                                detail__contains="dokku-managed +1").exists())


class DriftConfigParsingTests(TestCase):
    """The dokku_config / meaningful helpers: JSON path, envfile fallback, and
    the noise filter — pure parsing, subprocess mocked."""

    MOD = "vars.drift"

    @staticmethod
    def _cmd():
        import importlib
        return importlib.import_module("vars.drift")

    def test_meaningful_filters_noise(self):
        c = self._cmd()
        cfg = {"REAL": "v", "DATABASE_URL": "x", "REDIS_URL": "y", "PORT": "8000",
               "DOKKU_PROXY_PORT": "80", "GIT_REV": "abc"}
        self.assertEqual(c.meaningful(cfg), {"REAL": "v"})

    def test_dokku_config_parses_json(self):
        # dokku_config returns the RAW config (PORT included); the caller splits it
        # into meaningful (compared) and dokku-managed (surfaced) keys.
        c = self._cmd()
        proc = mock.Mock(returncode=0, stdout='{"REAL": "v", "PORT": "8000"}', stderr="")
        with mock.patch(f"{self.MOD}.subprocess.run", return_value=proc):
            out = c.dokku_config(["ssh"], "host", "app")
        self.assertEqual(out, {"REAL": "v", "PORT": "8000"})

    def test_dokku_config_falls_back_to_envfile(self):
        c = self._cmd()
        bad_json = mock.Mock(returncode=0, stdout="not json", stderr="")
        envfile = mock.Mock(returncode=0,
                            stdout="export REAL='v'\nPORT=8000\n# comment\n", stderr="")
        with mock.patch(f"{self.MOD}.subprocess.run", side_effect=[bad_json, envfile]):
            out = c.dokku_config(["ssh"], "host", "app")
        self.assertEqual(out, {"REAL": "v", "PORT": "8000"})

    def test_dokku_managed_extracts_dokku_keys(self):
        c = self._cmd()
        cfg = {"REAL": "v", "DATABASE_URL": "x", "PORT": "8000",
               "DOKKU_PROXY_PORT": "80", "GIT_REV": "abc"}
        self.assertEqual(c.dokku_managed(cfg),
                         ["DATABASE_URL", "DOKKU_PROXY_PORT", "GIT_REV", "PORT"])

    def test_dokku_config_raises_on_failure(self):
        c = self._cmd()
        bad_json = mock.Mock(returncode=1, stdout="", stderr="boom")
        fail = mock.Mock(returncode=1, stdout="", stderr="ssh denied")
        with mock.patch(f"{self.MOD}.subprocess.run", side_effect=[bad_json, fail]):
            with self.assertRaises(RuntimeError):
                c.dokku_config(["ssh"], "host", "app")


@override_settings(
    KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_MANAGED_KEYS=["DATABASE_URL"],
    KEYMAKER_KEY=API_KEY,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class OnDemandCheckTests(TestCase):
    """The Checks-page 'Check now' / 'Check all' buttons → checks_run view. Runs the
    SAME comparison as the cron (vars.drift), synchronously; SSH is mocked."""

    MOD = "vars.drift"

    def setUp(self):
        crypto._fernet = None
        self.env = Environment.objects.create(slug="staging", name="Staging")
        v = Variable(environment=self.env, key="SECRET_KEY"); v.set_value("km"); v.save()
        self.box = Target.objects.create(environment=self.env, label="boxA",
                                         dokku_app="app-a", host="1.2.3.4")

    def _login(self):
        self.assertEqual(self.client.post("/login", {"key": API_KEY}).status_code, 302)

    def test_requires_login(self):
        resp = self.client.post("/checks/run", {"env": "staging", "target": "boxA"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp["Location"])
        self.assertFalse(DriftCheck.objects.exists())

    def test_check_now_records_a_row_and_redirects(self):
        self._login()
        with mock.patch(f"{self.MOD}.dokku_config", return_value={"SECRET_KEY": "km"}):
            resp = self.client.post("/checks/run", {"env": "staging", "target": "boxA"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/checks", resp["Location"])
        dc = DriftCheck.objects.get(environment=self.env, target_label="boxA")
        self.assertTrue(dc.in_sync)

    def test_check_now_only_hits_the_named_target(self):
        self._login()
        Target.objects.create(environment=self.env, label="boxB", dokku_app="app-b", host="5.6.7.8")
        with mock.patch(f"{self.MOD}.dokku_config", return_value={"SECRET_KEY": "km"}) as m:
            self.client.post("/checks/run", {"env": "staging", "target": "boxA"})
        self.assertEqual(m.call_count, 1)
        self.assertTrue(DriftCheck.objects.filter(target_label="boxA").exists())
        self.assertFalse(DriftCheck.objects.filter(target_label="boxB").exists())

    def test_check_all_hits_every_target_in_env(self):
        self._login()
        Target.objects.create(environment=self.env, label="boxB", dokku_app="app-b", host="5.6.7.8")
        with mock.patch(f"{self.MOD}.dokku_config", return_value={"SECRET_KEY": "km"}) as m:
            self.client.post("/checks/run", {"env": "staging"})
        self.assertEqual(m.call_count, 2)
        self.assertEqual(DriftCheck.objects.count(), 2)

    def test_ssh_error_is_surfaced_and_records_nothing(self):
        self._login()
        with mock.patch(f"{self.MOD}.dokku_config",
                        side_effect=RuntimeError("Permission denied (publickey)")):
            resp = self.client.post("/checks/run", {"env": "staging", "target": "boxA"}, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(DriftCheck.objects.exists())
        self.assertContains(resp, "Permission denied")  # visible, not a silent 'never'

    def test_target_without_host_is_not_checkable(self):
        self._login()
        env2 = Environment.objects.create(slug="localdev", name="Local")
        Target.objects.create(environment=env2, label="local", local_only=True)
        with mock.patch(f"{self.MOD}.dokku_config") as m:
            self.client.post("/checks/run", {"env": "localdev"}, follow=True)
        m.assert_not_called()
        self.assertFalse(DriftCheck.objects.exists())


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

    def test_dokku_auto_keys_never_unset(self):
        """Regression: Dokku's own keys (DOKKU_*, GIT_REV) live on every box but
        are never stored in Keymaker. The sync must leave them alone, not unset
        them (which would strip routing/proxy config and force a restart). The
        ignore rule must match the import client + drift_check."""
        mod = self._mod()
        desired = {"A": "1"}
        current = {
            "A": "1", "GIT_REV": "abc123", "DATABASE_DEFAULT_URL": "auto",
            "DOKKU_APP_TYPE": "dockerfile", "DOKKU_PROXY_PORT": "80",
            "DOKKU_PROXY_SSL_PORT": "443", "DOKKU_APP_RESTORE": "1",
        }
        to_set, to_unset = mod.compute_changes(desired, current, mod.ALWAYS_IGNORE)
        self.assertEqual(to_set, {})
        self.assertEqual(to_unset, [])  # not one Dokku/auto key proposed for unset


@override_settings(
    KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_MANAGED_KEYS=["DATABASE_URL"],
    KEYMAKER_KEY=API_KEY,
    # Tests run without a built staticfiles manifest; use the plain backend so
    # {% static %} doesn't demand a collectstatic manifest entry.
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class UiTests(TestCase):
    """Server-rendered UI: auth gating, page smoke renders, and the HTMX/form
    mutations the dev team will use day to day. Login is session-based."""

    def setUp(self):
        crypto._fernet = None
        self.env = Environment.objects.create(slug="staging", name="Staging")
        self.secret = Variable(environment=self.env, key="SECRET_KEY", is_secret=True)
        self.secret.set_value("plaintext-secret"); self.secret.save()
        self.managed = Variable(environment=self.env, key="DATABASE_URL", is_managed=True)
        self.managed.set_value("postgres://x"); self.managed.save()
        self.box = Target.objects.create(environment=self.env, label="boxA", dokku_app="app-a")

    def _login(self):
        resp = self.client.post("/login", {"key": API_KEY})
        self.assertEqual(resp.status_code, 302)

    # --- auth gating ---

    def test_anonymous_redirected_to_login(self):
        for path in ("/", f"/environments/{self.env.slug}/", "/compare/", "/cleanup/",
                     "/checks/", "/audit/"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 302, path)
            self.assertIn("/login", resp["Location"], path)

    def test_login_wrong_key_rejected(self):
        resp = self.client.post("/login", {"key": "nope"}, follow=True)
        self.assertIsNone(auth.current_user(resp.wsgi_request))

    def test_login_correct_key_then_home(self):
        self._login()
        # Now authed: home redirects to the first env.
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 302)
        self.assertIn(self.env.slug, resp["Location"])

    def test_logout_clears_session(self):
        self._login()
        self.client.get("/logout")
        self.assertEqual(self.client.get("/compare/").status_code, 302)

    def test_non_admin_blocked_from_mutations(self):
        from .models import AppUser
        plain = AppUser.objects.create(username="readonly", is_admin=False)
        session = self.client.session
        session[auth.SESSION_USER_KEY] = plain.id
        session.save()
        resp = self.client.post(f"/environments/{self.env.slug}/variables/save",
                                {"key": "X", "value": "y"})
        self.assertEqual(resp.status_code, 403)

    # --- page smoke renders ---

    def test_pages_render(self):
        self._login()
        for path in (f"/environments/{self.env.slug}/", "/compare/", "/cleanup/",
                     "/checks/", "/audit/"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, path)

    def test_login_page_renders_for_anonymous(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)

    # --- variable mutations ---

    def test_variable_save_creates_and_bumps_revision(self):
        self._login()
        before = self.env.revision
        resp = self.client.post(f"/environments/{self.env.slug}/variables/save",
                                {"key": "NEW_KEY", "value": "v", "is_secret": ""})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(self.env.active_vars().filter(key="NEW_KEY").exists())
        self.env.refresh_from_db()
        self.assertEqual(self.env.revision, before + 1)

    def test_variable_save_requires_key(self):
        self._login()
        resp = self.client.post(f"/environments/{self.env.slug}/variables/save",
                                {"key": "", "value": "v"})
        self.assertEqual(resp.status_code, 400)

    def test_variable_save_rejects_managed(self):
        self._login()
        resp = self.client.post(f"/environments/{self.env.slug}/variables/save",
                                {"id": self.managed.id, "key": "DATABASE_URL", "value": "x"})
        self.assertEqual(resp.status_code, 400)

    def test_variable_save_get_is_405(self):
        self._login()
        resp = self.client.get(f"/environments/{self.env.slug}/variables/save")
        self.assertEqual(resp.status_code, 405)

    def test_variable_archive_then_restore(self):
        self._login()
        self.client.post(
            f"/environments/{self.env.slug}/variables/{self.secret.id}/archive",
            {"reason": "rotated"})
        self.secret.refresh_from_db()
        self.assertTrue(self.secret.archived)
        self.client.post(
            f"/environments/{self.env.slug}/variables/{self.secret.id}/restore")
        self.secret.refresh_from_db()
        self.assertFalse(self.secret.archived)

    def test_variable_reveal_returns_plaintext(self):
        self._login()
        resp = self.client.get(
            f"/environments/{self.env.slug}/variables/{self.secret.id}/reveal")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content.decode(), "plaintext-secret")

    def test_download_returns_dotenv_attachment(self):
        self._login()
        resp = self.client.get(f"/environments/{self.env.slug}/download")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp["Content-Disposition"])
        self.assertIn("SECRET_KEY=plaintext-secret", resp.content.decode())
        self.assertNotIn("DATABASE_URL", resp.content.decode())  # managed excluded by default

    # --- environment + target management ---

    def test_environment_create(self):
        self._login()
        self.client.post("/environments/new",
                         {"name": "Production", "slug": "prod", "kind": "shared"})
        self.assertTrue(Environment.objects.filter(slug="prod").exists())

    def test_environment_archive_restore_delete(self):
        self._login()
        keep = Environment.objects.create(slug="keep", name="Keep")  # so a nav env survives
        self.client.post(f"/environments/{self.env.slug}/archive")
        self.env.refresh_from_db()
        self.assertTrue(self.env.archived)
        self.client.post(f"/environments/{self.env.slug}/restore")
        self.env.refresh_from_db()
        self.assertFalse(self.env.archived)
        self.client.post(f"/environments/{self.env.slug}/delete")
        self.assertFalse(Environment.objects.filter(slug=self.env.slug).exists())

    def test_target_save_and_delete(self):
        self._login()
        self.client.post(f"/environments/{self.env.slug}/targets/save",
                         {"label": "boxB", "dokku_app": "app-b", "host": "5.6.7.8"})
        t = self.env.targets.get(label="boxB")
        self.client.post(f"/environments/{self.env.slug}/targets/{t.id}/delete")
        self.assertFalse(self.env.targets.filter(label="boxB").exists())

    def test_cleanup_archive(self):
        self._login()
        flagged = Variable(environment=self.env, key="ORPHAN", suspected_unused=True)
        flagged.set_value("o"); flagged.save()
        self.client.post(f"/cleanup/{flagged.id}/archive", {"reason": "unused"})
        flagged.refresh_from_db()
        self.assertTrue(flagged.archived)


class ScanReconcileTests(TestCase):
    """The keymaker_scan reconciler's pure scanning brain (no Keymaker/LLM/network):
    reference counting, MISSING-key extraction, dynamic-access detection, and the
    directory/extension filtering that keeps .env declarations from self-confirming."""

    @staticmethod
    def _mod():
        import importlib.util
        import pathlib

        path = pathlib.Path(__file__).resolve().parent.parent / "client" / "keymaker_scan.py"
        spec = importlib.util.spec_from_file_location("keymaker_scan", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _tree(self, files):
        """Write {relpath: content} into a temp dir and return its path."""
        import tempfile
        import os
        root = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, root, True)
        for rel, content in files.items():
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write(content)
        return root

    def test_prefix_of(self):
        mod = self._mod()
        self.assertEqual(mod.prefix_of("AWS_SECRET_KEY"), "AWS")
        self.assertEqual(mod.prefix_of("PORT"), "PORT")

    def test_counts_literal_references(self):
        mod = self._mod()
        root = self._tree({"app.py": "x = os.environ['USED_KEY']\nprint(USED_KEY)\n"})
        counts, samples, _, _ = mod.scan_tree(root, {"USED_KEY", "ABSENT_KEY"})
        self.assertEqual(counts["USED_KEY"], 2)
        self.assertEqual(counts["ABSENT_KEY"], 0)
        self.assertTrue(samples["USED_KEY"])  # file:line recorded

    def test_extracts_referenced_keys_for_missing(self):
        mod = self._mod()
        root = self._tree({
            "a.py": "os.environ.get('IN_STORE')\nos.getenv('NOT_IN_STORE')\n",
            "b.js": "const u = process.env.NODE_KEY\n",
        })
        _, _, referenced, _ = mod.scan_tree(root, {"IN_STORE"})
        self.assertIn("NOT_IN_STORE", referenced)
        self.assertIn("NODE_KEY", referenced)
        self.assertIn("IN_STORE", referenced)

    def test_detects_dynamic_access(self):
        mod = self._mod()
        root = self._tree({"dyn.py": "name = 'X'\nval = os.getenv(name)\n"})
        _, _, _, dynamic = mod.scan_tree(root, {"SOME_KEY"})
        self.assertTrue(dynamic)

    def test_no_dynamic_for_literal_only(self):
        mod = self._mod()
        root = self._tree({"lit.py": "val = os.getenv('LITERAL_KEY')\n"})
        _, _, _, dynamic = mod.scan_tree(root, {"LITERAL_KEY"})
        self.assertFalse(dynamic)

    def test_dotenv_files_not_scanned(self):
        # .env DECLARES values; counting it would mark every key trivially "used".
        mod = self._mod()
        root = self._tree({".env": "SECRET_KEY=abc\n", "app.py": "pass\n"})
        counts, _, _, _ = mod.scan_tree(root, {"SECRET_KEY"})
        self.assertEqual(counts["SECRET_KEY"], 0)

    def test_skip_dirs_excluded_from_source_scan(self):
        mod = self._mod()
        root = self._tree({
            "app.py": "os.environ['REAL']\n",
            "node_modules/pkg/index.js": "process.env.REAL\n",
        })
        counts, _, _, _ = mod.scan_tree(root, {"REAL"})
        self.assertEqual(counts["REAL"], 1)  # node_modules not walked in source mode

    def test_deps_scan_counts_but_does_not_mine(self):
        mod = self._mod()
        root = self._tree({"pkg/lib.py": "os.environ['DEP_KEY']\nos.getenv('OTHER')\n"})
        counts, _, referenced, dynamic = mod.scan_tree(root, {"DEP_KEY"}, scanning_deps=True)
        self.assertEqual(counts["DEP_KEY"], 1)      # references still counted
        self.assertEqual(referenced, set())          # but referenced/dynamic not mined
        self.assertFalse(dynamic)

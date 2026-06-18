"""Tests for keymaker core behavior."""
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from cryptography.fernet import Fernet

from . import crypto
from .models import Environment, Variable

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
        v = self.env.variables.get(key="SECRET_KEY")
        v.archive(by="tester", reason="rotated")
        resp = self._client().put(
            "/api/v1/environments/staging/variables/SECRET_KEY",
            {"value": "new", "is_secret": True}, format="json",
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(self.env.active_vars().filter(key="SECRET_KEY").count(), 1)
        self.assertEqual(self.env.variables.filter(key="SECRET_KEY").count(), 2)


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

"""Credential expiry tracking: status, finding copies, rotation, alerts, and the
UI / MCP / REST front doors."""
import datetime as dt
import json
from io import StringIO
from unittest import mock

from cryptography.fernet import Fernet
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from . import credentials, crypto
from .models import AuditLog, Credential, Environment, Target, Variable

TEST_KEY = Fernet.generate_key().decode()
API_KEY = "test-keymaker-key"
TODAY = dt.date(2026, 10, 23)


def _var(env, key, value, target=None, **kw):
    v = Variable(environment=env, key=key, target=target, **kw)
    v.set_value(value)
    v.save()
    return v


@override_settings(KEYMAKER_MASTER_KEYS=[TEST_KEY], KEYMAKER_KEY=API_KEY,
                   KEYMAKER_MANAGED_KEYS=["DATABASE_URL"], KEYMAKER_BASE_URL="https://km.test",
                   KEYMAKER_SLACK_WEBHOOK_URL="", KEYMAKER_SLACK_BOT_TOKEN="", KEYMAKER_SLACK_CHANNEL="",
                   STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage")
class CredentialTestBase(TestCase):
    def setUp(self):
        crypto._fernet = None
        self.staging = Environment.objects.create(slug="staging", name="Staging")
        self.local = Environment.objects.create(slug="localdev", name="Local dev", kind="local")
        self.box = Target.objects.create(environment=self.staging, label="boxA",
                                         host="10.0.0.1", dokku_app="app-a")
        self.tok_staging = _var(self.staging, "ATLASSIAN_API_TOKEN", "atl-old")
        self.tok_local = _var(self.local, "JIRA_TOKEN", "atl-old")
        self.other = _var(self.staging, "MAILGUN_KEY", "mg")
        self.cred = Credential.objects.create(
            name="Atlassian (trinity)", provider="atlassian_api_token", owner="ethan",
            rotate_url="https://id.atlassian.com/manage-profile/security/api-tokens",
            scopes="read:jira-work, write:jira-work", used_in="~/.trinity/config.yaml",
            expires_on=TODAY + dt.timedelta(days=30), lifetime_days=90)


class StatusTests(CredentialTestBase):
    def test_boundaries(self):
        c = self.cred
        cases = [(30, "ok"), (14, "expiring"), (0, "expiring"), (-1, "expired")]
        for days, want in cases:
            c.expires_on = TODAY + dt.timedelta(days=days)
            self.assertEqual(credentials.status(c, TODAY), want, days)
        c.expires_on = None
        self.assertEqual(credentials.status(c, TODAY), "no_expiry")

    def test_when_text(self):
        c = self.cred
        for days, want in [(6, "expires in 6 days"), (1, "expires in 1 day"), (0, "expires today"),
                           (-3, "expired 3 days ago")]:
            c.expires_on = TODAY + dt.timedelta(days=days)
            self.assertEqual(credentials.when_text(c, TODAY), want)

    def test_due_excludes_archived_and_far_off(self):
        Credential.objects.create(name="soon", expires_on=TODAY + dt.timedelta(days=3))
        Credential.objects.create(name="gone", expires_on=TODAY - dt.timedelta(days=3), archived=True)
        self.assertEqual([c.name for c in credentials.due(TODAY)], ["soon"])


class CopiesAndLinkTests(CredentialTestBase):
    def test_copies_find_the_same_value_in_other_environments(self):
        found = credentials.copies(value="atl-old")
        self.assertEqual({v.id for v in found}, {self.tok_staging.id, self.tok_local.id})

    def test_copies_skip_linked_and_managed(self):
        _var(self.staging, "DATABASE_URL", "atl-old", is_managed=True)
        credentials.link(self.cred, "t", [self.tok_staging])
        self.assertEqual([v.id for v in credentials.copies(self.cred)], [self.tok_local.id])

    def test_resolve_ref(self):
        override = _var(self.staging, "ATLASSIAN_API_TOKEN", "x", target=self.box)
        self.assertEqual(credentials.resolve_ref("staging:ATLASSIAN_API_TOKEN").id, self.tok_staging.id)
        self.assertEqual(credentials.resolve_ref("staging:ATLASSIAN_API_TOKEN@boxA").id, override.id)
        with self.assertRaises(credentials.CredentialError):
            credentials.resolve_ref("staging:NOPE")

    def test_save_validates_and_defaults_lifetime(self):
        with self.assertRaises(credentials.CredentialError):
            credentials.save("t", {"name": "x", "rotate_url": "https://bitbucket.org/citemed/{repo}/admin"})
        c = credentials.save("t", {"name": "bb", "provider": "bitbucket_repo_token"})
        self.assertEqual(c.lifetime_days, 90)

    def test_new_expiry_resets_alert_stage(self):
        self.cred.alerted_stage = "7d"
        self.cred.save()
        credentials.save("t", {"expires_on": "2027-01-31"}, cred=self.cred)
        self.cred.refresh_from_db()
        self.assertEqual(self.cred.alerted_stage, "")


class RotateTests(CredentialTestBase):
    def setUp(self):
        super().setUp()
        credentials.link(self.cred, "t", [self.tok_staging, self.tok_local])

    def test_rotate_writes_every_copy_and_bumps_revisions(self):
        rev_s, rev_l = self.staging.revision, self.local.revision
        r = credentials.rotate(self.cred, "ethan", value="atl-new", today=TODAY)
        for v in (self.tok_staging, self.tok_local):
            v.refresh_from_db()
            self.assertEqual(v.value, "atl-new")
        self.other.refresh_from_db()
        self.assertEqual(self.other.value, "mg")
        self.staging.refresh_from_db(); self.local.refresh_from_db()
        self.assertEqual((self.staging.revision, self.local.revision), (rev_s + 1, rev_l + 1))
        self.cred.refresh_from_db()
        self.assertEqual(self.cred.expires_on, TODAY + dt.timedelta(days=90))
        self.assertEqual(self.cred.issued_on, TODAY)
        self.assertEqual(r["also_update"], "~/.trinity/config.yaml")
        self.assertTrue(AuditLog.objects.filter(action="credential_rotate").exists())

    def test_rotate_without_value_only_moves_the_date(self):
        credentials.rotate(self.cred, "ethan", expires_on="2027-03-01", today=TODAY)
        self.tok_staging.refresh_from_db()
        self.assertEqual(self.tok_staging.value, "atl-old")
        self.cred.refresh_from_db()
        self.assertEqual(self.cred.expires_on, dt.date(2027, 3, 1))

    def test_rotate_needs_a_future_expiry(self):
        self.cred.lifetime_days = None
        with self.assertRaises(credentials.CredentialError):
            credentials.rotate(self.cred, "ethan", today=TODAY)
        with self.assertRaises(credentials.CredentialError):
            credentials.rotate(self.cred, "ethan", expires_on="2026-01-01", today=TODAY)

    def test_push_scopes_overrides_to_their_own_box(self):
        override = _var(self.staging, "ATLASSIAN_API_TOKEN", "atl-old", target=self.box)
        credentials.link(self.cred, "t", [override])
        self.tok_staging.credential = None
        self.tok_staging.save()
        with mock.patch.object(credentials.ops, "push",
                               return_value={"pushed": {"boxA": ["ATLASSIAN_API_TOKEN"]}, "errors": []}) as p:
            r = credentials.rotate(self.cred, "ethan", value="atl-new", push=True, today=TODAY)
        p.assert_called_once()
        self.assertEqual(p.call_args.kwargs["only_target"], self.box)
        self.assertTrue(p.call_args.kwargs["force"])
        self.assertEqual(r["pushed"], {"staging/boxA": ["ATLASSIAN_API_TOKEN"]})


class AlertTests(CredentialTestBase):
    def _now(self, d):
        return timezone.make_aware(dt.datetime.combine(d, dt.time(7, 30)))

    def test_posts_on_stage_change_only(self):
        self.cred.expires_on = TODAY + dt.timedelta(days=10)
        self.cred.save()
        with mock.patch.object(credentials, "post_to_slack", return_value=True) as post:
            r = credentials.send_alerts(today=TODAY, now=self._now(TODAY))
            self.assertTrue(r["posted"])
            self.assertIn("https://id.atlassian.com/manage-profile/security/api-tokens", post.call_args.args[0])
            self.assertIn("https://km.test/credentials/", post.call_args.args[0])
            # Next day, same stage: quiet.
            day2 = TODAY + dt.timedelta(days=1)
            self.assertFalse(credentials.send_alerts(today=day2, now=self._now(day2))["credentials"])
            # Inside a week: escalates.
            day4 = TODAY + dt.timedelta(days=4)
            self.assertEqual(credentials.send_alerts(today=day4, now=self._now(day4))["credentials"],
                             ["Atlassian (trinity)"])
        self.assertEqual(post.call_count, 2)

    def test_expired_reminds_weekly(self):
        self.cred.expires_on = TODAY - dt.timedelta(days=1)
        self.cred.save()
        with mock.patch.object(credentials, "post_to_slack", return_value=True):
            credentials.send_alerts(today=TODAY, now=self._now(TODAY))
            d3 = TODAY + dt.timedelta(days=3)
            self.assertFalse(credentials.send_alerts(today=d3, now=self._now(d3))["credentials"])
            d7 = TODAY + dt.timedelta(days=7)
            self.assertTrue(credentials.send_alerts(today=d7, now=self._now(d7))["credentials"])

    def test_failed_post_retries_next_run(self):
        self.cred.expires_on = TODAY + dt.timedelta(days=2)
        self.cred.save()
        with mock.patch.object(credentials, "post_to_slack", return_value=False):
            self.assertFalse(credentials.send_alerts(today=TODAY, now=self._now(TODAY))["posted"])
        self.cred.refresh_from_db()
        self.assertEqual(self.cred.alerted_stage, "")

    def test_no_slack_config_posts_nothing(self):
        self.assertFalse(credentials.post_to_slack("hi"))

    def test_command_dry_run(self):
        self.cred.expires_on = timezone.localdate() + dt.timedelta(days=3)
        self.cred.save()
        out = StringIO()
        call_command("credential_alerts", "--dry-run", stdout=out)
        self.assertIn("Atlassian (trinity)", out.getvalue())
        self.assertIn("dry run", out.getvalue())
        self.cred.refresh_from_db()
        self.assertEqual(self.cred.alerted_stage, "")


class FrontDoorTests(CredentialTestBase):
    def _call(self, name, arguments):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}}
        resp = self.client.post("/mcp", data=json.dumps(body), content_type="application/json",
                                HTTP_AUTHORIZATION=f"Bearer {API_KEY}")
        self.assertEqual(resp.status_code, 200)
        return resp.json()["result"]

    def _login(self):
        self.assertEqual(self.client.post("/login", {"key": API_KEY}).status_code, 302)

    def test_mcp_save_list_rotate(self):
        r = self._call("keymaker_save_credential", {
            "name": "BB citemed_web", "provider": "bitbucket_repo_token",
            "rotate_url": "https://bitbucket.org/citemed/citemed_web/admin/access-tokens",
            "expires_on": "2026-11-01", "scopes": "repository:write, pullrequest:write",
            "link": ["staging:MAILGUN_KEY"]})
        self.assertFalse(r.get("isError"), r)
        data = r["structuredContent"]
        self.assertEqual(data["variables"], ["staging:MAILGUN_KEY"])
        listed = self._call("keymaker_list_credentials", {"due_only": True})["structuredContent"]
        self.assertIn("BB citemed_web", [c["name"] for c in listed["credentials"]])
        rot = self._call("keymaker_rotate_credential",
                         {"credential": "BB citemed_web", "value": "new-mg"})["structuredContent"]
        self.assertEqual(rot["updated"], ["staging:MAILGUN_KEY"])
        self.other.refresh_from_db()
        self.assertEqual(self.other.value, "new-mg")

    def test_mcp_bad_link_creates_nothing(self):
        r = self._call("keymaker_save_credential", {"name": "x", "link": ["staging:NOPE"]})
        self.assertTrue(r["isError"])
        self.assertFalse(Credential.objects.filter(name="x").exists())

    def test_api_due(self):
        Credential.objects.create(name="soon", expires_on=timezone.localdate() + dt.timedelta(days=2))
        resp = self.client.get("/api/v1/credentials?due=1", HTTP_AUTHORIZATION=f"Bearer {API_KEY}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([c["name"] for c in resp.json()["credentials"]], ["soon"])
        self.assertNotIn("atl-old", resp.content.decode())

    def test_ui_track_from_variable_then_rotate(self):
        self._login()
        resp = self.client.get(f"/credentials/new?var={self.tok_staging.id}")
        self.assertContains(resp, "localdev:JIRA_TOKEN")          # same value found elsewhere
        resp = self.client.post("/credentials/new", {
            "name": "Ethan Atlassian", "provider": "atlassian_api_token",
            "rotate_url": "https://id.atlassian.com/manage-profile/security/api-tokens",
            "expires_on": (timezone.localdate() + dt.timedelta(days=5)).isoformat(),
            "warn_days": "14", "link_var": [self.tok_staging.id, self.tok_local.id]})
        cred = Credential.objects.get(name="Ethan Atlassian")
        self.assertRedirects(resp, f"/credentials/{cred.id}/")
        self.assertEqual(cred.variables.count(), 2)

        page = self.client.get(f"/environments/{self.staging.slug}/")
        self.assertContains(page, "expires in 5 days")
        self.assertContains(self.client.get("/credentials/"), 'class="nav-count"')

        self.client.post(f"/credentials/{cred.id}/rotate", {"value": "atl-new"})
        self.tok_local.refresh_from_db()
        self.assertEqual(self.tok_local.value, "atl-new")
        cred.refresh_from_db()
        self.assertEqual(cred.expires_on, timezone.localdate() + dt.timedelta(days=90))

    def test_ui_pages_render(self):
        self._login()
        for path in ("/credentials/", "/credentials/?archived=1", "/credentials/new",
                     f"/credentials/{self.cred.id}/"):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_ui_requires_login(self):
        resp = self.client.get("/credentials/")
        self.assertEqual(resp.status_code, 302)

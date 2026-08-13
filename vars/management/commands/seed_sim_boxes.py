"""Write fake Dokku boxes for local development.

The sync UX is only meaningful against boxes that disagree with Keymaker in
interesting ways, and no developer should need SSH access to production to work
on it. This paints a deliberately messy picture — a key each of drifted,
missing, and unadopted, plus deploy-injected noise worth ignoring — into
KEYMAKER_SIM_BOX_DIR, where drift.py reads and writes instead of using SSH.

    docker compose exec web python manage.py seed_sim_boxes
    docker compose exec web python manage.py drift_check

Never run in production: it does nothing unless KEYMAKER_SIM_BOX_DIR is set,
and production must never set it.
"""
import json
import os

from django.core.management.base import BaseCommand, CommandError

from vars import drift
from vars.models import Environment


class Command(BaseCommand):
    help = "Create simulated Dokku box configs for local drift/sync development."

    def add_arguments(self, parser):
        parser.add_argument("--env", help="Only this environment slug")

    def handle(self, *args, **opts):
        sim = drift.sim_dir()
        if not sim:
            raise CommandError(
                "KEYMAKER_SIM_BOX_DIR is not set — refusing to guess. "
                "Set it in docker-compose.yml for local dev."
            )
        os.makedirs(sim, exist_ok=True)

        envs = Environment.objects.filter(archived=False)
        if opts.get("env"):
            envs = envs.filter(slug=opts["env"])

        for env in envs:
            for i, target in enumerate(env.targets.filter(local_only=False)):
                if not (target.host and target.dokku_app):
                    continue
                cfg = self._box_for(env, target, i)
                path = os.path.join(sim, f"{target.host}__{target.dokku_app}.json")
                with open(path, "w") as fh:
                    json.dump(cfg, fh, indent=2, sort_keys=True)
                self.stdout.write(f"  {env.slug}/{target.label} → {len(cfg)} keys  {path}")

    def _box_for(self, env, target, i):
        """A box that mostly matches Keymaker, with planted, explainable drift."""
        resolved = env.resolved_for(target)
        cfg = {k: v.value for k, v in resolved.items() if not v.is_managed}
        keys = sorted(cfg)

        # 1. One value changed on the box behind our back → drifted.
        if keys:
            cfg[keys[0]] = cfg[keys[0]] + "-CHANGED-ON-BOX"
        # 2. One value never made it to the box → keymaker_only.
        if len(keys) > 1:
            cfg.pop(keys[1])
        # 3. Only the second box drops a third key, so a rollup row shows a
        #    genuine split (one box fine, one box not) rather than uniform state.
        if i > 0 and len(keys) > 2:
            cfg.pop(keys[2])
        # 4. Real secrets somebody set by hand and never wrote down → server_only.
        cfg["ARTICLE_GALAXY_SOAP_PASSWORD"] = "hunter2-set-by-hand"
        cfg[f"{target.label.upper().replace('-', '_')}_LEGACY_TOKEN"] = "tok-legacy"
        # 5. Deploy-injected noise — the stuff worth *ignoring*, not adopting.
        cfg["APP_VERSION"] = "2026.08.13"
        cfg["RELEASE_NOTES_LINK"] = "https://example.invalid/releases"
        # 6. Dokku's own keys: surfaced elsewhere, never compared.
        cfg["DATABASE_URL"] = "postgres://user:pw@db:5432/app"
        cfg["DOKKU_APP_TYPE"] = "herokuish"
        cfg["GIT_REV"] = "deadbeef"
        return cfg

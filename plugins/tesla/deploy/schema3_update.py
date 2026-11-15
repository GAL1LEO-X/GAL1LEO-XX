#!/usr/bin/env python3
"""Reviewed 0.4.1/schema-2 to 1.0.1/schema-3 maintenance adapter.

Run only from a private, reviewed delivery bundle. The original OPS updater is
not modified or called for activation. Its file/installation primitives remain
pinned. Both SQLite writers are stopped before migration or downgrade; recovery
never overwrites the database with an older copy. External scheduled jobs must
be inspected separately before maintenance.
"""
import argparse
from contextlib import closing, contextmanager
import fcntl
from functools import wraps
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import sqlite3
import subprocess
import sys
import time
import zipfile


OPS_HASHES = {
    "tesla_personal_update.py": "65e34a475bedb655e61019c52a0817daa2d6da0cc3053fa92f60ca513ef02070",
    "tesla_pilot.py": "0d35bec83214dec377a048dfcf1ddd5d59f94b0e5d0db8e4f13480af60f78131",
    "tesla_proxy_update.py": "d7ed68b6a5991ad28b022f1c2db4ead5f55f6417c37d01ee92c3d5306e1ae84c",
}
PREVIOUS_STORE = "97c7ff29ac26b12c62ff2af84049fd9f68ac3b659cb60ebfb1c0a9884b6b61d1"
CANDIDATE_FILES = {
    "src/tesla_plugin/store.py": "89b06e4fd7ee5efb4d132878c22e4c9e9aa6542e4ee96d9469a889b88d643119",
    "src/tesla_plugin/schema_migrations.py": "bb9139ee1eb308b6b17d0f0f8aec047015f1a486772c840a6006cfccbc865162",
    "requirements.lock": "6cbae69d16074ead0fbb8897af9e5bdbbdfcc76f6be33fb050847a1325a15cd1",
}
WRITERS = ("tesla-personal.service", "tesla-consumer.service")
TRANSPORT = ("tesla-command", "tesla-telemetry", "tesla-kafka")
TERMINAL = ("restored_verified", "superseded", "cancelled", "start_rejected")
PROTECTED = {
    "rules": "SELECT id,vehicle,kind,config,enabled FROM rules ORDER BY vehicle,id",
    "triggers": "SELECT * FROM trigger_settings ORDER BY vehicle",
    "preferences": "SELECT * FROM trigger_preferences ORDER BY vehicle,id",
    "collection": "SELECT vehicle,section,data FROM snapshots WHERE section IN "
                  "('telemetry_saved','telemetry_target','telemetry_preview','event_delivery_access') ORDER BY vehicle,section",
    "authorization": "SELECT id,scopes,region,generation,status FROM connection ORDER BY id",
    "subscriptions": "SELECT id,name,filters,generation,active FROM subscriptions ORDER BY id",
    "generation": "SELECT value FROM meta WHERE key='connection_generation'",
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class RecoveryIncomplete(RuntimeError):
    """Recovery refused or failed; inspect the receipt before any further action."""


class IntegrityFailure(ValueError):
    """Known data loss requires inspection, never an automatic software rollback."""


def exclusive(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._exclusive():
            return method(self, *args, **kwargs)
    return locked


def load_ops(directory):
    directory = Path(directory).resolve()
    for name, expected in OPS_HASHES.items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
            raise ValueError("Reviewed OPS primitive changed")
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location("tesla_personal_update", directory / "tesla_personal_update.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Adapter:
    def __init__(self, profile, ops, *, unit_root=Path("/etc/systemd/system")):
        self.p, self.ops = profile, ops
        self.previous, self.release, self.recovery = ops.paths(profile)
        self.settings = Path(profile["config_root"]) / "settings.json"
        self.database = Path(profile["state_root"]) / "state.sqlite3"
        self.unit_root = Path(unit_root)
        self.hold = self.recovery / "maintenance.hold"
        self.baseline = None
        if profile.get("proxy_update") or profile.get("storage_compatibility"):
            raise ValueError("This adapter has no proxy or general storage exceptions")
        if set(profile.get("transport_units", {})) != {*TRANSPORT, "tesla-consumer"}:
            raise ValueError("All transport unit fingerprints are required")
        self.old_units = {WRITERS[0]: profile["previous_unit_sha256"],
                          WRITERS[1]: profile["transport_units"]["tesla-consumer"]}

    @contextmanager
    def _exclusive(self):
        path = self.recovery.parent / "schema3-maintenance.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        acquired = False
        try:
            if os.fstat(fd).st_mode & 0o077:
                raise ValueError("Maintenance lock must be private")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("Another maintenance process is still running") from None
            self._lock_fd = fd
            acquired = True
            yield
        finally:
            if acquired:
                self.__dict__.pop("_lock_fd", None)
            os.close(fd)

    def _system(self, action, *names):
        return self.ops.run(["systemctl", action, *names])

    def _state(self, name, property_name):
        return self._system("show", name, "--property=" + property_name, "--value").strip()

    def _restart_condition_loaded(self, name):
        # systemctl show renders this structured property as [unprintable] on
        # systemd 257. Read its typed D-Bus value, resolving the actual unit
        # object through the manager instead of guessing its encoded path.
        command = ["busctl", "--system", "--json=short", "--timeout=10"]
        unit = json.loads(self.ops.run(command + ["call", "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnit", "s", name]))
        if (not isinstance(unit, dict) or unit.get("type") != "o"
                or not isinstance(unit.get("data"), list) or len(unit["data"]) != 1
                or not isinstance(unit["data"][0], str)
                or not re.fullmatch(r"/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+", unit["data"][0])):
            raise ValueError("Unexpected systemd unit object")
        value = json.loads(self.ops.run(command + ["get-property", "org.freedesktop.systemd1",
            unit["data"][0], "org.freedesktop.systemd1.Unit", "Conditions"]))
        if (not isinstance(value, dict) or value.get("type") != "a(sbbsi)"
                or not isinstance(value.get("data"), list)):
            raise ValueError("Unexpected systemd conditions value")
        matches = 0
        for condition in value["data"]:
            if (not isinstance(condition, list) or len(condition) != 5
                    or not isinstance(condition[0], str) or type(condition[1]) is not bool
                    or type(condition[2]) is not bool or not isinstance(condition[3], str)
                    or type(condition[4]) is not int):
                raise ValueError("Unexpected systemd condition tuple")
            # Non-trigger means this negated path condition is mandatory even
            # when the unit also contains an OR group of trigger conditions.
            matches += condition[:4] == ["ConditionPathExists", False, True, str(self.hold)]
        return matches == 1

    def _check_files(self, units):
        if self.ops.sha(self.settings) != self.p["settings_sha256"]:
            raise ValueError("Settings changed; inspect without overwriting")
        for name, expected in units.items():
            if self.ops.sha(self.unit_root / name) != expected:
                raise ValueError("Writer unit changed; inspect without overwriting")
        for name in TRANSPORT:
            if (self.ops.sha(self.unit_root / (name + ".service")) != self.p["transport_units"][name]
                    or self._state(name + ".service", "ActiveState") != "active"
                    or self._state(name + ".service", "UnitFileState") != "enabled"):
                raise ValueError("Transport changed during maintenance")

    def _check_writers(self, active):
        for name in WRITERS:
            if (self._state(name, "ActiveState") != ("active" if active else "inactive")
                    or self._state(name, "UnitFileState") != "enabled"):
                raise ValueError("Unexpected writer service state")

    def inspect(self):
        if self.database.is_symlink() or self.database.stat().st_mode & 0o077:
            raise ValueError("Database must be private and not a symlink")
        owner = json.loads(self.settings.read_text())["owner_subject"]
        with closing(sqlite3.connect(self.database.absolute().as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("BEGIN")
            if db.execute("SELECT value FROM meta WHERE key='owner'").fetchone() != (owner,):
                raise ValueError("Database owner mismatch")
            schema = db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            if schema not in (("2",), ("3",)):
                raise ValueError("Unsupported database schema")
            protected = {name: db.execute(sql).fetchall() for name, sql in PROTECTED.items()}
            intents = {}
            for row in db.execute("SELECT * FROM intents ORDER BY id"):
                normalized = list(row)
                if normalized[10] in ("prepared", "expired"):
                    normalized[10] = "prepared_or_expired"
                intents[row[0]] = {"digest": digest(normalized), "created": row[8],
                                   "expires": row[9], "status": row[10]}
            pending = 0
            if schema == ("3",):
                pending = sum(row[0] not in TERMINAL for row in db.execute("SELECT status FROM temporary_collections"))
            sending = db.execute("SELECT count(*) FROM intents WHERE status='sending'").fetchone()[0]
            uncertain = db.execute("SELECT count(*) FROM (SELECT status,expires,row_number() OVER "
                "(PARTITION BY vehicle ORDER BY created DESC,rowid DESC) AS position FROM intents WHERE operation IN "
                "('vehicle_fleet_telemetry_config_create','vehicle_fleet_telemetry_config_delete')) "
                "WHERE position=1 AND status='prepared' AND expires>?",
                (time.time(),)).fetchone()[0]
            # A later rejected or even acknowledged intent cannot establish the
            # current configuration after an uncertain dispatch. Only a later
            # synchronized observation matching the current target can do so.
            for vehicle, expires in db.execute("SELECT vehicle,expires FROM intents WHERE status='unknown' "
                    "AND operation IN ('vehicle_fleet_telemetry_config_create','vehicle_fleet_telemetry_config_delete')"):
                remote = db.execute("SELECT data,received,source FROM snapshots WHERE vehicle=? AND section='telemetry_remote'", (vehicle,)).fetchone()
                target = db.execute("SELECT data,received FROM snapshots WHERE vehicle=? AND section='telemetry_target'", (vehicle,)).fetchone()
                try:
                    observed = json.loads(remote[0]) if remote else {}
                    resolved = (remote and target and remote[2] == "tesla_api" and isinstance(observed, dict)
                                and "config" in observed and observed.get("synced") is True
                                and remote[1] > expires and remote[1] >= target[1]
                                and remote[1] <= time.time() and observed.get("config") == json.loads(target[0]))
                except (TypeError, ValueError):
                    resolved = False
                uncertain += not resolved
            return {"schema": int(schema[0]), "owner_digest": digest(protected),
                    "intents": intents, "intent_digest": digest({key: value["digest"] for key, value in intents.items()}),
                    "samples_count": db.execute("SELECT count(*) FROM samples").fetchone()[0],
                    "sending_count": sending, "pending_collection_count": uncertain,
                    "pending_temporaries": pending}

    def _guard(self, expected_schema, owner_digest, units):
        self._check_files(units)
        state = self.inspect()
        if (state["schema"] != expected_schema or state["owner_digest"] != owner_digest
                or state["sending_count"] or state["pending_collection_count"] or state["pending_temporaries"]):
            raise ValueError("Schema, owner activity or collection obligation changed")
        if self.baseline is not None:
            cutoff = time.time() - json.loads(self.settings.read_text()).get("history_days", 30) * 86400
            before, current = self.baseline["intents"], state["intents"]
            if set(current) - set(before):
                raise ValueError("New owner operation during maintenance")
            for identifier, prior in before.items():
                if identifier in current:
                    if current[identifier]["digest"] != prior["digest"]:
                        raise ValueError("Owner operation changed during maintenance")
                elif not (prior["created"] < cutoff and prior["status"] != "sending"
                          and (prior["status"] != "prepared" or prior["expires"] <= time.time())):
                    raise ValueError("Unexpected intent loss during maintenance")
        return state

    def _verify_release(self):
        if self.ops.sha(self.previous / "src/tesla_plugin/store.py") != PREVIOUS_STORE:
            raise ValueError("Previous Store differs from reviewed 0.4.1")
        for name, expected in CANDIDATE_FILES.items():
            if self.ops.sha(self.release / name) != expected:
                raise ValueError("Candidate storage or dependency fingerprint changed")
        if (self.previous.joinpath("requirements.lock").read_bytes() != self.release.joinpath("requirements.lock").read_bytes()
                or self.previous.joinpath("VERSION").read_text().strip() != "0.4.1"
                or self.release.joinpath("VERSION").read_text().strip() != "1.0.1"):
            raise ValueError("This transition requires 0.4.1 to 1.0.1 with unchanged dependencies")
        # Verify the complete unpacked source against the reviewed archive manifest.
        if self.ops.sha(self.p["archive_path"]) != self.p["source_archive_sha256"]:
            raise ValueError("Reviewed archive changed")
        with zipfile.ZipFile(self.p["archive_path"]) as archive:
            manifest_bytes = archive.read("SHA256SUMS.json")
        if self.release.joinpath("SHA256SUMS.json").read_bytes() != manifest_bytes:
            raise ValueError("Staged manifest differs from reviewed archive")
        manifest = json.loads(manifest_bytes)
        for name, expected in manifest.items():
            path = self.release / name
            if path.is_symlink() or self.ops.sha(path) != expected:
                raise ValueError("Staged source changed")

    @exclusive
    def stage(self):
        self._check_writers(True)
        baseline = self._guard(2, self.p["expected_owner_digest"], self.old_units)
        if baseline["intent_digest"] != self.p["expected_intent_digest"]:
            raise ValueError("Owner operations changed since review")
        self.baseline = baseline
        self.ops.check_personal_settings(json.loads(self.settings.read_text()), transport=True)
        if self.release.exists() or self.recovery.exists():
            raise ValueError("Already staged or attempted; inspect the original receipt")
        self.recovery.mkdir(mode=0o700)
        self.ops.write_new(self.recovery / "profile.json", json.dumps(self.p, sort_keys=True))
        for name in WRITERS:
            self.ops.write_new(self.recovery / (name + ".before"), (self.unit_root / name).read_bytes())
        self.ops.extract_verified(self.p["archive_path"], self.release, self.p["source_archive_sha256"])
        self._verify_release()
        self.ops.run(["python3", "-m", "venv", str(self.release / "venv")], log=self.recovery / "venv.log")
        python = str(self.release / "venv/bin/python")
        self.ops.run([python, "-m", "pip", "install", "--disable-pip-version-check", "-r",
                      str(self.release / "requirements.lock"), "setuptools==84.0.0"], log=self.recovery / "dependencies.log")
        self.ops.run([python, "-m", "pip", "install", "--disable-pip-version-check", "--no-deps",
                      "--no-build-isolation", str(self.release)], log=self.recovery / "package.log")
        self.ops.run([python, "-m", "pip", "check"], log=self.recovery / "pip-check.log")
        self.ops.release_access(self.p["release_root"], self.release, pwd.getpwnam(self.p["service_user"]).pw_gid)
        self.ops.run(["runuser", "-u", self.p["service_user"], "--", str(self.release / "venv/bin/tesla-plugin"),
                      "check-config", "--config", str(self.settings)], log=self.recovery / "check-config.log")
        units = {}
        for name in WRITERS:
            candidate = self.ops.candidate_unit((self.recovery / (name + ".before")).read_text(),
                self.previous, self.release, consumer=name == WRITERS[1])
            path = self.recovery / (name + ".candidate")
            self.ops.write_new(path, candidate)
            units[name] = self.ops.sha(path)
        self._guard(2, baseline["owner_digest"], self.old_units)
        record = {"state": "staged", "baseline": baseline, "candidate_units": units}
        self.ops.write_new(self.recovery / "stage.json", json.dumps(record))
        return record

    def _staged(self):
        if json.loads((self.recovery / "profile.json").read_text()) != self.p:
            raise ValueError("Reviewed profile changed")
        self._verify_release()
        record = json.loads((self.recovery / "stage.json").read_text())
        self.baseline = record["baseline"]
        for name in WRITERS:
            if (self.ops.sha(self.recovery / (name + ".candidate")) != record["candidate_units"][name]
                    or self.ops.sha(self.recovery / (name + ".before")) != self.old_units[name]):
                raise ValueError("Staged units changed")
        return record

    def _schema(self, action):
        # Execute the reviewed candidate module without constructing Store or any
        # network client. Migration runs as the database's service identity.
        script = ("import json,hashlib,importlib.util,pathlib,sys;"
                  "expected=json.loads(sys.argv[3]);"
                  "[(None if hashlib.sha256(pathlib.Path(importlib.util.find_spec('tesla_plugin.'+name).origin).read_bytes()).hexdigest()==value "
                  "else sys.exit('Runtime storage fingerprint mismatch')) for name,value in expected.items()];"
                  "from tesla_plugin.config import Settings;"
                  "from tesla_plugin.schema_migrations import initialize_database,rollback_schema;"
                  "from tesla_plugin.store import SCHEMA;import sys;"
                  "s=Settings.load(sys.argv[1]);"
                  "p=initialize_database(s.database,s.owner_subject,SCHEMA) if sys.argv[2]=='migrate' "
                  "else rollback_schema(s.database,s.owner_subject);print(json.dumps({'backup':str(p)}))")
        pins = {"store": CANDIDATE_FILES["src/tesla_plugin/store.py"],
                "schema_migrations": CANDIDATE_FILES["src/tesla_plugin/schema_migrations.py"]}
        result = self._schema_process([str(self.release / "venv/bin/python"), "-c", script,
                                       str(self.settings), action, json.dumps(pins)])
        backup = Path(json.loads(result)["backup"])
        if not backup.is_file() or backup.is_symlink() or backup.stat().st_mode & 0o077:
            raise ValueError("Migration did not deliver a private backup")
        return str(backup)

    def _schema_process(self, arguments):
        # The same open flock description survives in the child. Killing this
        # adapter cannot let another operator race a still-running migration.
        # Direct uid/gid switching avoids assuming runuser preserves inherited
        # descriptors. No identity, group membership or configuration is edited.
        account = pwd.getpwnam(self.p["service_user"])
        identity = {} if (os.geteuid(), os.getegid()) == (account.pw_uid, account.pw_gid) else {
            "user": account.pw_uid, "group": account.pw_gid, "extra_groups": []}
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            pass_fds=(self._lock_fd,), **identity)
        if result.returncode:
            log = self.recovery / ("schema-failure-" + secrets.token_hex(8) + ".log")
            self.ops.write_new(log, result.stdout[-65536:])
            self._sync_directory(self.recovery)
            self._schema_failure_log = str(log)
            raise RuntimeError("Candidate schema operation failed; inspect private maintenance receipt")
        return result.stdout.decode()

    def _health(self, version):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                health = self.ops.get_json("http://127.0.0.1:8018/tesla/healthz")
                if (health.get("version") == version and health.get("live_enabled") is True
                        and health.get("worker", {}).get("running") and not health["worker"].get("last_error")):
                    self.ops.status(self.p)
                    self._check_writers(True)
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.25)
        raise ValueError("Expected runtime health did not become ready")

    def _stop(self):
        self._inhibit()
        self._system("stop", *WRITERS)
        self._check_writers(False)

    def _guard_path(self, name):
        return self.unit_root / (name + ".d") / "90-tesla-schema3-maintenance.conf"

    def _guard_content(self):
        return "[Unit]\nConditionPathExists=!" + str(self.hold) + "\n"

    @staticmethod
    def _sync_directory(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _inhibit(self):
        # A persistent condition also prevents old binaries from starting after
        # a reboot during the schema/unit switch. Existing foreign drop-ins are
        # refused, never overwritten. Unit contents and enablement stay intact.
        for name in WRITERS:
            path = self._guard_path(name)
            if path.parent.is_symlink() or path.is_symlink() or (path.exists() and path.read_text() != self._guard_content()):
                raise ValueError("Unexpected maintenance drop-in")
        if self.hold.is_symlink() or (self.hold.exists() and self.hold.read_text() != self.p["source_commit"]):
            raise ValueError("Unexpected maintenance marker")
        if not self.hold.exists():
            self.ops.write_new(self.hold, self.p["source_commit"])
            self._sync_directory(self.recovery)
        for name in WRITERS:
            path = self._guard_path(name)
            path.parent.mkdir(mode=0o755, exist_ok=True)
            if not path.exists():
                self.ops.write_new(path, self._guard_content())
                self._sync_directory(path.parent)
                self._sync_directory(self.unit_root)
        self._system("daemon-reload")
        for name in WRITERS:
            if not self._restart_condition_loaded(name):
                raise ValueError("Systemd did not load the persistent maintenance condition")

    def _release_hold(self):
        for name in WRITERS:
            if self._guard_path(name).read_text() != self._guard_content():
                raise ValueError("Maintenance condition changed")
        if self.hold.read_text() != self.p["source_commit"]:
            raise ValueError("Maintenance marker changed")
        self.hold.unlink()
        self._sync_directory(self.recovery)

    def _finish(self, receipt, record):
        # Commit runtime/schema outcome before optional guard cleanup, so a
        # cleanup failure cannot be mistaken for a failed schema transition.
        if getattr(self, "_schema_failure_log", None):
            record["schema_failure_log"] = self._schema_failure_log
        self.ops.atomic(receipt, json.dumps(record))
        self._sync_directory(self.recovery)
        try:
            for name in WRITERS:
                path = self._guard_path(name)
                if (path.parent.is_symlink() or path.is_symlink()
                        or path.read_text() != self._guard_content()):
                    raise ValueError("Maintenance condition changed before cleanup")
            if self.hold.exists():
                raise ValueError("Cannot clean an active maintenance hold")
            for name in WRITERS:
                path = self._guard_path(name)
                path.unlink()
                self._sync_directory(path.parent)
            self._system("daemon-reload")
            record["maintenance_cleanup_complete"] = True
        except Exception:
            record["maintenance_cleanup_complete"] = False
        self.ops.atomic(receipt, json.dumps(record))
        self._sync_directory(self.recovery)
        return record

    def _incomplete(self, receipt, record):
        stopped = True
        if getattr(self, "_schema_failure_log", None):
            record["schema_failure_log"] = self._schema_failure_log
        inhibited = True
        try:
            self._inhibit()
        except Exception:
            inhibited = False
        for name in WRITERS:
            try:
                self._system("stop", name)
                stopped = stopped and self._state(name, "ActiveState") == "inactive"
            except Exception:
                stopped = False
        self.ops.atomic(receipt, json.dumps(record | {"state": "recovery_incomplete", "writers_stopped": stopped,
                                                      "restart_inhibited": inhibited}))
        self._sync_directory(self.recovery)

    def _recover(self, staged, current_units, record):
        self._stop()
        schema = self.inspect()["schema"]
        before = self._guard(schema, staged["baseline"]["owner_digest"], current_units)
        if schema == 3:
            record["rollback_backup"] = self._schema("rollback")
        after = self._guard(2, staged["baseline"]["owner_digest"], current_units)
        if after["samples_count"] != before["samples_count"]:
            record["data_integrity_failed"] = True
            raise IntegrityFailure("Sample count changed during stopped schema rollback")
        for name in WRITERS:
            self._check_files(current_units)
            self.ops.atomic(self.unit_root / name, (self.recovery / (name + ".before")).read_bytes())
            current_units[name] = self.old_units[name]
        self._system("daemon-reload")
        self._sync_directory(self.unit_root)
        self._guard(2, staged["baseline"]["owner_digest"], self.old_units)
        self._release_hold()
        self._system("start", *WRITERS)
        self._health("0.4.1")
        self._guard(2, staged["baseline"]["owner_digest"], self.old_units)
        record.update(state="rolled_back", schema=2)

    @exclusive
    def activate(self):
        staged = self._staged()
        self._check_writers(True)
        self._guard(2, staged["baseline"]["owner_digest"], self.old_units)
        receipt = self.recovery / "activation.json"
        record = {"state": "started", "source_commit": self.p["source_commit"]}
        self.ops.write_new(receipt, json.dumps(record))
        self._sync_directory(self.recovery)
        current_units = dict(self.old_units)
        try:
            self._stop()
            before = self._guard(2, staged["baseline"]["owner_digest"], current_units)
            record["migration_backup"] = self._schema("migrate")
            self.ops.atomic(receipt, json.dumps(record | {"state": "migrated"}))
            self._sync_directory(self.recovery)
            migrated = self._guard(3, staged["baseline"]["owner_digest"], current_units)
            if migrated["samples_count"] != before["samples_count"]:
                raise IntegrityFailure("Sample count changed during stopped schema migration")
            for name in WRITERS:
                self._check_files(current_units)
                self.ops.atomic(self.unit_root / name, (self.recovery / (name + ".candidate")).read_bytes())
                current_units[name] = staged["candidate_units"][name]
            self._system("daemon-reload")
            self._sync_directory(self.unit_root)
            self._guard(3, staged["baseline"]["owner_digest"], current_units)
            self._release_hold()
            self._system("start", *WRITERS)
            self._health("1.0.1")
            self._guard(3, staged["baseline"]["owner_digest"], current_units)
            record.update(state="active", schema=3)
        except Exception as error:
            if isinstance(error, IntegrityFailure):
                record["data_integrity_failed"] = True
                self._incomplete(receipt, record)
                raise RecoveryIncomplete("Data integrity failed; inspect without automatic rollback") from error
            try:
                self._recover(staged, current_units, record)
            except Exception:
                self._incomplete(receipt, record)
                raise RecoveryIncomplete("Recovery incomplete; inspect the private receipt") from error
            self._finish(receipt, record)
            raise
        return self._finish(receipt, record)

    @exclusive
    def recover(self):
        """Explicit recovery after process death; never automatically replay activation."""
        staged = self._staged()
        activation = json.loads((self.recovery / "activation.json").read_text())
        interrupted = activation
        for filename in ("rollback.json", "recovery.json"):
            path = self.recovery / filename
            if path.exists():
                observed = json.loads(path.read_text())
                interrupted = observed
        if interrupted.get("state") not in ("started", "migrated", "recovery_incomplete"):
            raise ValueError("No interrupted activation to recover")
        if interrupted.get("data_integrity_failed") or activation.get("data_integrity_failed"):
            raise ValueError("Data integrity requires separate operator review")
        current = {name: self.ops.sha(self.unit_root / name) for name in WRITERS}
        if any(current[name] not in (self.old_units[name], staged["candidate_units"][name]) for name in WRITERS):
            raise ValueError("Unknown unit state; inspect without overwriting")
        receipt = self.recovery / "recovery.json"
        record = {"state": "started", "source_commit": self.p["source_commit"],
                  "previous_state": interrupted["state"]}
        if receipt.exists():
            # A repeated explicit recovery resumes the same recorded operation;
            # no caller can replay the original activation or provider request.
            self.ops.atomic(receipt, json.dumps(record))
        else:
            self.ops.write_new(receipt, json.dumps(record))
        self._sync_directory(self.recovery)
        try:
            self._recover(staged, current, record)
        except Exception as error:
            self._incomplete(receipt, record)
            raise RecoveryIncomplete("Explicit recovery incomplete; inspect its receipt") from error
        self._finish(receipt, record)
        self.ops.atomic(self.recovery / "activation.json", json.dumps(activation | record))
        self._sync_directory(self.recovery)
        return record

    @exclusive
    def rollback(self):
        staged = self._staged()
        activation = json.loads((self.recovery / "activation.json").read_text())
        if activation.get("state") != "active":
            raise ValueError("Activation is not committed; inspect its original receipt")
        # A known owner change or obligation is a preflight refusal, preserving
        # the healthy candidate. Repeat all checks after stopping for races.
        self._check_writers(True)
        self._guard(3, staged["baseline"]["owner_digest"], staged["candidate_units"])
        receipt = self.recovery / "rollback.json"
        record = {"state": "started", "source_commit": self.p["source_commit"]}
        self.ops.write_new(receipt, json.dumps(record))
        self._sync_directory(self.recovery)
        try:
            self._recover(staged, staged["candidate_units"], record)
        except Exception as error:
            self._incomplete(receipt, record)
            raise RecoveryIncomplete("Rollback incomplete; inspect the private receipt") from error
        self._finish(receipt, record)
        self.ops.atomic(self.recovery / "activation.json", json.dumps(activation | record))
        self._sync_directory(self.recovery)
        return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "stage", "activate", "rollback", "recover"))
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--ops-directory", type=Path, required=True)
    arguments = parser.parse_args()
    adapter = Adapter(json.loads(arguments.profile.read_text()), load_ops(arguments.ops_directory))
    print(json.dumps(getattr(adapter, arguments.action)()))

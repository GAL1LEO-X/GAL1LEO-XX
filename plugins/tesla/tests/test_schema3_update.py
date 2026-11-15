"""Synthetic orchestration qualification; no real services, provider or network calls."""
from contextlib import closing, redirect_stdout
import fcntl
import hashlib
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import pwd
import select
import shutil
import signal
import sqlite3
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import zipfile

import pytest

from tesla_plugin import schema_migrations
from tesla_plugin.store import SCHEMA


ADAPTER_PATH = Path(__file__).parents[1] / "deploy" / "schema3_update.py"
OWNER = "schema-adapter-synthetic-owner"
PREVIOUS = "1" * 40
CANDIDATE = "2" * 40
OWNERS = ("tesla-personal", "tesla-consumer")
TRANSPORT = ("tesla-command", "tesla-telemetry", "tesla-kafka")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sql(path, statement, parameters=()):
    with closing(sqlite3.connect(path)) as db:
        rows = db.execute(statement, parameters).fetchall()
        db.commit()
        return rows


def add_sample(path, identifier):
    sql(path, "INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)",
        (identifier, "synthetic-vehicle", "BatteryLevel", "85", 100, 110,
         "valid", "payload_created_at"))


def add_intent(path, identifier, status, *, created=100, expires=200,
               operation="vehicle_fleet_telemetry_config_create"):
    sql(path, "INSERT INTO intents VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (identifier, identifier, "synthetic-fingerprint", "synthetic-vehicle", operation,
         "{}", "[]", 7, created, expires, status, None))


def legacy_database(path):
    path.touch(mode=0o600)
    with closing(sqlite3.connect(path)) as db:
        db.executescript(SCHEMA)
        for table in ("sample_provenance", "latest_provenance", "temporary_collections"):
            db.execute("DROP TABLE " + table)
        db.executemany("INSERT INTO meta VALUES(?,?)",
                       (("schema", "2"), ("owner", OWNER), ("connection_generation", "7")))
        db.execute("INSERT INTO trigger_settings VALUES(?,?,?)", ("synthetic-vehicle", 11, 30))
        db.execute("INSERT INTO trigger_preferences VALUES(?,?,?)", ("synthetic-vehicle", "charging", 1))
        db.execute("INSERT INTO rules VALUES(?,?,?,?,?,?)",
                   ("synthetic-rule", "synthetic-vehicle", "battery", '{"limit":85}', "{}", 1))
        fields = {"SyntheticField" + str(index): {"interval_seconds": 60} for index in range(9)}
        fields["Location"] = {"interval_seconds": 300, "resend_interval_seconds": 300, "minimum_delta": 25}
        for section in ("telemetry_saved", "telemetry_target"):
            db.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?)",
                       ("synthetic-vehicle", section, json.dumps({"fields": fields}), "owner", 100, 110))
        db.commit()
    add_sample(path, "sample-before-upgrade")


class FakeOps:
    """Model the verified OPS primitive seam without launching any commands."""

    def __init__(self, root):
        self.root = root
        self.calls = []
        self.states = {name: {"ActiveState": "active", "UnitFileState": "enabled"}
                       for name in (*OWNERS, *TRANSPORT)}
        self.before_system = None
        self.before_atomic = None
        self.CONSUMER_UNIT = root / "units" / "tesla-consumer.service"
        self.unit_objects = {name + ".service": "/org/freedesktop/systemd1/unit/qa_loaded_" + str(index)
                             for index, name in enumerate(self.states)}

    def conditions(self, name):
        # This models only unit-file/startup semantics. The original mock also
        # exposed this file text through `systemctl show Conditions`, masking
        # systemd 257's real "[unprintable]" response. Keep that CLI rendering
        # separate from the independently qualified typed busctl transport.
        path = self.root / "units" / (name.removesuffix(".service") + ".service.d") / "90-tesla-schema3-maintenance.conf"
        if not path.exists():
            return ""
        return "\n".join(line for line in path.read_text().splitlines() if line.startswith("Condition"))

    def startup_inhibited(self, name):
        prefix = "ConditionPathExists=!"
        return any(Path(line[len(prefix):]).exists() for line in self.conditions(name).splitlines()
                   if line.startswith(prefix))

    def reboot(self):
        for name in self.states:
            self.states[name]["ActiveState"] = "inactive" if self.startup_inhibited(name) else "active"

    def paths(self, profile):
        releases = Path(profile["release_root"]) / "releases"
        return releases / profile["previous_commit"], releases / profile["source_commit"], self.root / "recovery"

    sha = staticmethod(sha)

    @staticmethod
    def candidate_unit(before, previous, release, *, consumer=False):
        assert before.count(str(previous)) == 2
        return before.replace(str(previous), str(release))

    @staticmethod
    def write_new(path, value):
        path = Path(path)
        with path.open("xb") as output:
            output.write(value.encode() if isinstance(value, str) else value)
        path.chmod(0o600)

    def atomic(self, path, value):
        path = Path(path)
        if self.before_atomic:
            self.before_atomic(path, value)
        path.write_bytes(value.encode() if isinstance(value, str) else value)
        path.chmod(0o600)

    @staticmethod
    def extract_verified(archive, release, expected_digest):
        assert sha(archive) == expected_digest
        release.mkdir(parents=True, exist_ok=False)
        with zipfile.ZipFile(archive) as source:
            for name in source.namelist():
                assert not Path(name).is_absolute() and ".." not in Path(name).parts
                target = release / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read(name))

    @staticmethod
    def release_access(*args):
        pass

    @staticmethod
    def check_personal_settings(*args, **kwargs):
        pass

    def run(self, arguments, **kwargs):
        arguments = list(map(str, arguments))
        self.calls.append(arguments)
        if arguments[0] == "busctl":
            assert arguments[:4] == ["busctl", "--system", "--json=short", "--timeout=10"]
            if arguments[4] == "call":
                assert arguments[5:10] == ["org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                          "org.freedesktop.systemd1.Manager", "GetUnit", "s"]
                return json.dumps({"type": "o", "data": [self.unit_objects[arguments[10]]]})
            assert arguments[4] == "get-property" and arguments[5] == "org.freedesktop.systemd1"
            assert arguments[7:] == ["org.freedesktop.systemd1.Unit", "Conditions"]
            name = next(name for name, object_path in self.unit_objects.items() if object_path == arguments[6])
            conditions = []
            for line in self.conditions(name).splitlines():
                kind, parameter = line.split("=", 1)
                trigger = parameter.startswith("|")
                parameter = parameter.removeprefix("|")
                negate = parameter.startswith("!")
                conditions.append([kind, trigger, negate, parameter.removeprefix("!"), 0])
            # Real busctl 257 JSON from an isolated Gio service: get-property
            # carries the array directly; method replies carry an outer body list.
            return json.dumps({"type": "a(sbbsi)", "data": conditions})
        if arguments[0] != "systemctl":
            # Staging command effects stay entirely inside the synthetic release.
            if arguments[:3] == ["python3", "-m", "venv"]:
                directory = Path(arguments[3]) / "bin"
                directory.mkdir(parents=True)
                for name in ("python", "tesla-plugin"):
                    (directory / name).write_text("synthetic executable placeholder")
                return ""
            if "pip" in arguments or "check-config" in arguments:
                return ""
            raise AssertionError("Unexpected executable requested by adapter: " + arguments[0])
        action = arguments[1]
        if self.before_system:
            self.before_system(action, arguments[2:])
        names = [name.removesuffix(".service") for name in arguments[2:] if not name.startswith("--")]
        if action == "daemon-reload":
            return ""
        if action == "show":
            state = self.states[names[0]] | {"Conditions": "[unprintable]"}
            properties = next((item.split("=", 1)[1] for item in arguments if item.startswith("--property=")),
                              "ActiveState,UnitFileState").split(",")
            if "--value" in arguments:
                return "\n".join(state[prop] for prop in properties)
            return "\n".join(prop + "=" + state[prop] for prop in properties)
        if action == "is-active":
            return self.states[names[0]]["ActiveState"]
        if action not in ("stop", "start", "disable", "enable"):
            raise AssertionError("Unexpected systemctl action: " + action)
        for name in names:
            state = self.states[name]
            if action in ("stop", "start") or "--now" in arguments:
                state["ActiveState"] = "active" if action in ("start", "enable") else "inactive"
                if state["ActiveState"] == "active" and self.startup_inhibited(name):
                    state["ActiveState"] = "inactive"
            if action in ("disable", "enable"):
                state["UnitFileState"] = "enabled" if action == "enable" else "disabled"
        return ""


@pytest.fixture
def adapter_module():
    spec = importlib.util.spec_from_file_location("synthetic_schema3_adapter", ADAPTER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def rig(tmp_path, monkeypatch, adapter_module):
    config = tmp_path / "config"
    state = tmp_path / "state"
    units = tmp_path / "units"
    for directory in (config, state, units):
        directory.mkdir(mode=0o700)
    database = state / "state.sqlite3"
    legacy_database(database)
    settings = config / "settings.json"
    settings.write_text(json.dumps({"owner_subject": OWNER, "database": str(database), "charging_amps": 5}))
    settings.chmod(0o600)
    previous = tmp_path / "application" / "releases" / PREVIOUS
    previous.mkdir(parents=True)
    (previous / "VERSION").write_text("0.4.1\n")
    (previous / "requirements.lock").write_text("synthetic dependencies\n")
    for name in (*OWNERS, *TRANSPORT):
        command = "consume" if name == "tesla-consumer" else "serve"
        (units / (name + ".service")).write_text(
            "[Service]\nWorkingDirectory=" + str(previous) + "\nExecStart=" + str(previous)
            + "/venv/bin/tesla-plugin " + command + " --config " + str(settings) + "\n")
    archive = tmp_path / "candidate.zip"
    source = {"VERSION": b"1.0.1\n", "requirements.lock": b"synthetic dependencies\n"}
    with zipfile.ZipFile(archive, "w") as output:
        for name, value in source.items():
            output.writestr(name, value)
        output.writestr("SHA256SUMS.json", json.dumps({name: hashlib.sha256(value).hexdigest() for name, value in source.items()}))
    ops = FakeOps(tmp_path)
    profile = {"source_commit": CANDIDATE, "previous_commit": PREVIOUS,
               "release_root": str(tmp_path / "application"), "config_root": str(config), "state_root": str(state),
               "service_user": "synthetic-user", "service_name": "tesla-personal.service",
               "archive_path": str(archive), "source_archive_sha256": sha(archive),
               "settings_sha256": sha(settings), "previous_unit_sha256": sha(units / "tesla-personal.service"),
               "transport_units": {name: sha(units / (name + ".service")) for name in ("tesla-consumer", *TRANSPORT)},
               "expected_owner_digest": "0" * 64, "expected_intent_digest": "0" * 64}
    monkeypatch.setattr(adapter_module.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    adapter = adapter_module.Adapter(profile, ops, unit_root=units)
    inspected = adapter.inspect()
    profile["expected_owner_digest"] = inspected["owner_digest"]
    profile["expected_intent_digest"] = inspected["intent_digest"]
    result = SimpleNamespace(adapter=adapter, module=adapter_module, ops=ops, database=database, settings=settings,
                             units=units, profile=profile, schema_calls=[], health_calls=[], previous=previous,
                             archive=archive, initial_units={name: (units / (name + ".service")).read_bytes()
                                                            for name in (*OWNERS, *TRANSPORT)})
    monkeypatch.setattr(adapter, "_verify_release", lambda: None)

    def migrate(action):
        assert all(ops.states[name]["ActiveState"] == "inactive" for name in OWNERS), "A writer was running during schema change"
        assert all(ops.startup_inhibited(name) for name in OWNERS), "A writer could restart during schema change"
        result.schema_calls.append(action)
        if action == "migrate":
            return str(schema_migrations.initialize_database(database, OWNER, SCHEMA))
        assert action == "rollback"
        return str(schema_migrations.rollback_schema(database, OWNER))

    def healthy(version):
        result.health_calls.append(version)
        assert all(ops.states[name]["ActiveState"] == "active" for name in OWNERS)
        assert not adapter.hold.exists()
        expected_schema = "3" if version == "1.0.1" else "2"
        assert sql(database, "SELECT value FROM meta WHERE key='schema'") == [(expected_schema,)]
        expected_release = CANDIDATE if version == "1.0.1" else PREVIOUS
        for name in OWNERS:
            assert expected_release in (units / (name + ".service")).read_text()

    monkeypatch.setattr(adapter, "_schema", migrate)
    monkeypatch.setattr(adapter, "_health", healthy)
    result.real_schema = migrate
    result.real_health = healthy
    return result


def receipt(rig, name="activation.json"):
    return json.loads((rig.adapter.recovery / name).read_text())


def refresh_review(rig):
    state = rig.adapter.inspect()
    rig.profile["expected_owner_digest"] = state["owner_digest"]
    rig.profile["expected_intent_digest"] = state["intent_digest"]


def assert_maintenance_lock_released(rig):
    path = rig.adapter.recovery.parent / "schema3-maintenance.lock"
    with path.open("r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def assert_stopped(rig):
    assert all(rig.ops.states[name] == {"ActiveState": "inactive", "UnitFileState": "enabled"} for name in OWNERS)


def assert_old_runtime(rig):
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [("2",)]
    for name in OWNERS:
        assert (rig.units / (name + ".service")).read_bytes() == rig.initial_units[name]
        assert rig.ops.states[name] == {"ActiveState": "active", "UnitFileState": "enabled"}


def test_stage_is_readonly_for_database_and_running_services(rig):
    before = rig.database.read_bytes()
    staged = rig.adapter.stage()
    assert staged["state"] == "staged"
    assert rig.database.read_bytes() == before
    assert rig.schema_calls == []
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
    assert not any(call[:2] == ["systemctl", "stop"] for call in rig.ops.calls)
    assert not list(rig.database.parent.glob("*.pre-*.sqlite3"))


def test_upgrade_and_rollback_preserve_new_samples_and_owner_state(rig):
    original_settings = rig.settings.read_bytes()
    baseline = rig.adapter.inspect()
    rig.adapter.stage()
    active = rig.adapter.activate()
    assert active["state"] == "active" and active["schema"] == 3
    backup = Path(active["migration_backup"])
    assert backup.stat().st_mode & 0o777 == 0o600
    assert sql(backup, "PRAGMA integrity_check") == [("ok",)]
    assert sql(backup, "SELECT value FROM meta WHERE key='schema'") == [("2",)]
    assert rig.adapter.inspect()["owner_digest"] == baseline["owner_digest"]
    add_sample(rig.database, "sample-received-on-schema3")
    rolled_back = rig.adapter.rollback()
    assert rolled_back["state"] == "rolled_back"
    assert_old_runtime(rig)
    assert sql(rig.database, "SELECT id FROM samples ORDER BY id") == [("sample-before-upgrade",), ("sample-received-on-schema3",)]
    assert rig.settings.read_bytes() == original_settings
    assert rig.adapter.inspect()["owner_digest"] == baseline["owner_digest"]
    assert rig.schema_calls == ["migrate", "rollback"]
    assert rig.health_calls == ["1.0.1", "0.4.1"]
    for name in TRANSPORT:
        assert (rig.units / (name + ".service")).read_bytes() == rig.initial_units[name]
        assert rig.ops.states[name] == {"ActiveState": "active", "UnitFileState": "enabled"}
    assert sql(rolled_back["rollback_backup"], "SELECT id FROM samples ORDER BY id") == [("sample-before-upgrade",), ("sample-received-on-schema3",)]


def test_health_failure_rolls_back_schema_before_starting_old_workers(rig, monkeypatch):
    rig.adapter.stage()

    def health(version):
        rig.real_health(version)
        if version == "1.0.1":
            add_sample(rig.database, "sample-before-unhealthy-recovery")
            raise ValueError("synthetic candidate health failure")

    monkeypatch.setattr(rig.adapter, "_health", health)
    with pytest.raises(ValueError, match="candidate health failure"):
        rig.adapter.activate()
    assert receipt(rig)["state"] == "rolled_back"
    assert_old_runtime(rig)
    assert rig.schema_calls == ["migrate", "rollback"]
    assert sql(rig.database, "SELECT count(*) FROM samples") == [(2,)]


@pytest.mark.parametrize("phase", ("before_commit", "after_commit"))
def test_failed_or_uncertain_migration_reconciles_actual_schema(rig, monkeypatch, phase):
    rig.adapter.stage()

    def migrate(action):
        if action == "migrate":
            if phase == "after_commit":
                rig.real_schema(action)
            raise OSError("synthetic lost migration result")
        return rig.real_schema(action)

    monkeypatch.setattr(rig.adapter, "_schema", migrate)
    with pytest.raises(OSError, match="lost migration result"):
        rig.adapter.activate()
    assert_old_runtime(rig)
    assert receipt(rig)["state"] == "rolled_back"
    assert rig.schema_calls == (["migrate", "rollback"] if phase == "after_commit" else [])


def test_partial_unit_switch_failure_recovers_both_units(rig):
    rig.adapter.stage()
    failed = False

    def fail_consumer_switch(path, value):
        nonlocal failed
        if path == rig.units / "tesla-consumer.service" and not failed:
            failed = True
            raise OSError("synthetic second unit write failure")

    rig.ops.before_atomic = fail_consumer_switch
    with pytest.raises(OSError, match="second unit write"):
        rig.adapter.activate()
    assert failed
    assert_old_runtime(rig)
    assert receipt(rig)["state"] == "rolled_back"


def test_owner_change_after_migration_prevents_overwriting_and_leaves_writers_stopped(rig, monkeypatch):
    rig.adapter.stage()

    def migrate(action):
        result = rig.real_schema(action)
        if action == "migrate":
            sql(rig.database, "UPDATE trigger_settings SET revision=12")
        return result

    monkeypatch.setattr(rig.adapter, "_schema", migrate)
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.activate()
    assert_stopped(rig)
    assert rig.schema_calls == ["migrate"]
    assert sql(rig.database, "SELECT revision FROM trigger_settings") == [(12,)]
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [("3",)]
    assert receipt(rig)["state"] == "recovery_incomplete"
    assert receipt(rig)["writers_stopped"] is True


@pytest.mark.parametrize("status", ("prepared", "active", "accepted", "unknown", "blocked", "restore_pending", "restore_accepted", "restore_unknown", "restore_rejected", "future_state"))
def test_every_unresolved_temporary_state_blocks_downgrade(rig, status):
    rig.adapter.stage()
    rig.adapter.activate()
    sql(rig.database, "INSERT INTO temporary_collections(intent_id,vehicle,plan,generation,status,updated) VALUES(?,?,?,?,?,?)",
        ("synthetic-obligation", "synthetic-vehicle", "{}", 7, status, 100))
    with pytest.raises(ValueError, match="obligation changed"):
        rig.adapter.rollback()
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
    assert rig.schema_calls == ["migrate"]
    assert sql(rig.database, "SELECT status FROM temporary_collections") == [(status,)]
    assert not (rig.adapter.recovery / "rollback.json").exists()


@pytest.mark.parametrize("status", ("restored_verified", "superseded", "cancelled", "start_rejected"))
def test_terminal_temporary_states_allow_explicit_downgrade(rig, status):
    rig.adapter.stage()
    rig.adapter.activate()
    sql(rig.database, "INSERT INTO temporary_collections(intent_id,vehicle,plan,generation,status,updated) VALUES(?,?,?,?,?,?)",
        ("synthetic-completed-window", "synthetic-vehicle", "{}", 7, status, 100))
    assert rig.adapter.rollback()["state"] == "rolled_back"
    assert_old_runtime(rig)


def test_unit_drift_is_preserved_and_blocks_downgrade(rig):
    rig.adapter.stage()
    rig.adapter.activate()
    unit = rig.units / "tesla-consumer.service"
    changed = unit.read_bytes() + b"# independently changed unit\n"
    unit.write_bytes(changed)
    with pytest.raises(ValueError, match="unit changed"):
        rig.adapter.rollback()
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
    assert unit.read_bytes() == changed
    assert rig.schema_calls == ["migrate"]
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [("3",)]


@pytest.mark.parametrize("failure", ("schema", "old_health"))
def test_failed_recovery_keeps_both_writers_stopped(rig, monkeypatch, failure):
    rig.adapter.stage()
    rig.adapter.activate()
    if failure == "schema":
        def unavailable(action):
            raise OSError("synthetic rollback backup unavailable")
        monkeypatch.setattr(rig.adapter, "_schema", unavailable)
    else:
        def unavailable(version):
            raise ValueError("synthetic old runtime unhealthy")
        monkeypatch.setattr(rig.adapter, "_health", unavailable)
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.rollback()
    assert_stopped(rig)
    failed = receipt(rig, "rollback.json")
    assert failed["state"] == "recovery_incomplete" and failed["writers_stopped"]
    assert sql(rig.database, "SELECT count(*) FROM samples") == [(1,)]


def test_guard_rechecks_owner_activity_after_stopping_writers(rig):
    rig.adapter.stage()
    raced = False

    def owner_race(action, arguments):
        nonlocal raced
        if action == "stop" and not raced:
            raced = True
            sql(rig.database, "UPDATE trigger_settings SET revision=12")

    rig.ops.before_system = owner_race
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.activate()
    assert_stopped(rig)
    assert rig.schema_calls == []
    assert sql(rig.database, "SELECT revision FROM trigger_settings") == [(12,)]


def test_staging_owner_race_refuses_activation_without_stopping_services(rig, monkeypatch):
    original_run = rig.ops.run

    def racing_install(arguments, **kwargs):
        result = original_run(arguments, **kwargs)
        if "check-config" in arguments:
            sql(rig.database, "UPDATE trigger_settings SET revision=12")
        return result

    monkeypatch.setattr(rig.ops, "run", racing_install)
    with pytest.raises(ValueError, match="owner activity"):
        rig.adapter.stage()
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
    assert not (rig.adapter.recovery / "stage.json").exists()
    assert rig.schema_calls == []
    assert sql(rig.database, "SELECT revision FROM trigger_settings") == [(12,)]


def test_failed_stop_never_migrates_or_claims_all_writers_stopped(rig):
    rig.adapter.stage()

    def unavailable_stop(action, arguments):
        if action == "stop" and "tesla-consumer.service" in arguments:
            raise OSError("synthetic consumer stop unavailable")

    rig.ops.before_system = unavailable_stop
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.activate()
    assert rig.schema_calls == []
    assert rig.ops.states["tesla-personal"]["ActiveState"] == "inactive"
    assert rig.ops.states["tesla-consumer"]["ActiveState"] == "active"
    assert receipt(rig)["state"] == "recovery_incomplete"
    assert receipt(rig)["writers_stopped"] is False
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [("2",)]


def test_owner_mismatch_refused_without_receipts_or_stopping_services(rig):
    sql(rig.database, "UPDATE meta SET value='another-synthetic-owner' WHERE key='owner'")
    with pytest.raises(ValueError, match="owner mismatch"):
        rig.adapter.stage()
    assert not rig.adapter.recovery.exists()
    assert rig.schema_calls == []
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)


def test_stage_and_activation_cannot_be_blindly_repeated(rig):
    rig.adapter.stage()
    with pytest.raises(ValueError, match="Already staged"):
        rig.adapter.stage()
    rig.adapter.activate()
    with pytest.raises((ValueError, FileExistsError)):
        rig.adapter.activate()
    assert rig.schema_calls == ["migrate"]
    assert receipt(rig)["state"] == "active"


def test_new_obligation_racing_with_rollback_stop_is_retained_and_workers_stopped(rig):
    rig.adapter.stage()
    rig.adapter.activate()
    raced = False

    def obligation_race(action, arguments):
        nonlocal raced
        if action == "stop" and not raced:
            raced = True
            sql(rig.database, "INSERT INTO temporary_collections(intent_id,vehicle,plan,generation,status,updated) VALUES(?,?,?,?,?,?)",
                ("synthetic-racing-window", "synthetic-vehicle", "{}", 7, "active", 100))

    rig.ops.before_system = obligation_race
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.rollback()
    assert_stopped(rig)
    assert rig.schema_calls == ["migrate"]
    assert sql(rig.database, "SELECT status FROM temporary_collections") == [("active",)]
    assert receipt(rig, "rollback.json")["writers_stopped"]


def test_old_unknown_collection_with_later_acknowledgment_requires_observed_configuration(rig):
    add_intent(rig.database, "historical-unknown", "unknown", created=100)
    add_intent(rig.database, "newer-acknowledged", "acknowledged", created=200)
    refresh_review(rig)
    assert rig.adapter.inspect()["pending_collection_count"] == 1
    with pytest.raises(ValueError, match="obligation changed"):
        rig.adapter.stage()
    assert not rig.adapter.recovery.exists()
    assert sql(rig.database, "SELECT status FROM intents WHERE id='historical-unknown'") == [("unknown",)]
    assert rig.schema_calls == []


@pytest.mark.parametrize("status,expires", (("unknown", 0), ("prepared", 1e30), ("sending", 0)))
def test_latest_unresolved_collection_blocks_before_staging(rig, status, expires):
    add_intent(rig.database, "unresolved-collection", status, expires=expires)
    refresh_review(rig)
    with pytest.raises(ValueError, match="obligation changed"):
        rig.adapter.stage()
    assert not rig.adapter.recovery.exists()
    assert rig.schema_calls == []
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)


def test_old_sending_intent_cannot_be_hidden_by_later_acknowledgment(rig):
    add_intent(rig.database, "older-sending", "sending", created=100)
    add_intent(rig.database, "newer-acknowledged", "acknowledged", created=200)
    refresh_review(rig)
    with pytest.raises(ValueError, match="obligation changed"):
        rig.adapter.stage()
    assert not rig.adapter.recovery.exists()


def test_known_owner_change_refuses_rollback_without_stopping_candidate(rig):
    rig.adapter.stage()
    rig.adapter.activate()
    sql(rig.database, "UPDATE trigger_settings SET revision=12")
    with pytest.raises(ValueError, match="owner activity"):
        rig.adapter.rollback()
    assert not (rig.adapter.recovery / "rollback.json").exists()
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
    assert rig.schema_calls == ["migrate"]
    assert sql(rig.database, "SELECT revision FROM trigger_settings") == [(12,)]


def test_schema_command_executes_real_migration_without_store_or_network(rig, monkeypatch):
    from tesla_plugin.config import Settings
    from tesla_plugin.store import Store

    rig.adapter.stage()
    rig.adapter._stop()
    monkeypatch.setattr(Settings, "load", lambda path: SimpleNamespace(database=rig.database, owner_subject=OWNER))

    def forbidden(*args, **kwargs):
        raise AssertionError("Store/network access is forbidden for schema commands")

    monkeypatch.setattr(Store, "__init__", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    called = []

    def isolated_script(arguments, **kwargs):
        assert Path(arguments[0]) == rig.adapter.release / "venv/bin/python"
        assert arguments[1] == "-c" and arguments[3] == str(rig.settings)
        assert set(json.loads(arguments[5])) == {"store", "schema_migrations"}
        assert all(rig.ops.states[name]["ActiveState"] == "inactive" for name in OWNERS)
        called.append(arguments[4])
        monkeypatch.setattr(sys, "argv", ["synthetic-migration", *arguments[3:]])
        output = io.StringIO()
        with redirect_stdout(output):
            exec(compile(arguments[2], "synthetic-schema-command", "exec"), {})
        return output.getvalue()

    monkeypatch.setattr(rig.adapter, "_schema_process", isolated_script)
    # The frozen 1.0.1 adapter must refuse the modified Store. Separately bind
    # this script-level fixture to the current modules to exercise actual
    # migration/backup behavior without claiming a historical release match.
    with pytest.raises(SystemExit, match='Runtime storage fingerprint mismatch'):
        rig.module.Adapter._schema(rig.adapter, 'migrate')
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [('2',)]
    called.clear()
    current_pins = {name: sha(ADAPTER_PATH.parent.parent / name) for name in rig.module.CANDIDATE_FILES}
    monkeypatch.setattr(rig.module, 'CANDIDATE_FILES', current_pins)
    backup2 = rig.module.Adapter._schema(rig.adapter, "migrate")
    add_sample(rig.database, "sample-after-process-migration")
    backup3 = rig.module.Adapter._schema(rig.adapter, "rollback")
    assert called == ["migrate", "rollback"]
    for backup, version, count in ((backup2, "2", 1), (backup3, "3", 2)):
        assert Path(backup).stat().st_mode & 0o777 == 0o600
        assert sql(backup, "PRAGMA integrity_check") == [("ok",)]
        assert sql(backup, "SELECT value FROM meta WHERE key='schema'") == [(version,)]
        assert sql(backup, "SELECT count(*) FROM samples") == [(count,)]
    assert sql(rig.database, "SELECT count(*) FROM samples") == [(2,)]


def test_historical_adapter_pins_match_its_exact_release_receipt(adapter_module):
    # This adapter intentionally remains frozen for 0.4.1 -> 1.0.1. A patch
    # candidate has a separate adapter and its own current-source pin test.
    receipt = json.loads(ADAPTER_PATH.with_name('historical-1.0.1.json').read_text())
    assert receipt['version'] == '1.0.1'
    assert receipt['commit'] == '69deb9039c291739741600092c75fe0eefc4b292'
    assert receipt['adapter_sha256'] == sha(ADAPTER_PATH)
    assert receipt['candidate_files'] == adapter_module.CANDIDATE_FILES


@pytest.fixture
def verified_release(rig, monkeypatch):
    rig.adapter.stage()
    previous_store = rig.previous / "src/tesla_plugin/store.py"
    previous_store.parent.mkdir(parents=True)
    previous_store.write_text("synthetic reviewed schema2 store\n")
    monkeypatch.setattr(rig.module, "PREVIOUS_STORE", sha(previous_store))
    sources = {"VERSION": b"1.0.1\n", "requirements.lock": b"synthetic dependencies\n",
               "src/tesla_plugin/store.py": b"synthetic reviewed schema3 store\n",
               "src/tesla_plugin/schema_migrations.py": b"synthetic reviewed migration\n",
               "src/tesla_plugin/service.py": b"synthetic reviewed application behavior\n"}
    manifest = json.dumps({name: hashlib.sha256(value).hexdigest() for name, value in sources.items()}).encode()
    with zipfile.ZipFile(rig.archive, "w") as output:
        for name, data in sources.items():
            output.writestr(name, data)
            target = rig.adapter.release / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        output.writestr("SHA256SUMS.json", manifest)
    (rig.adapter.release / "SHA256SUMS.json").write_bytes(manifest)
    rig.profile["source_archive_sha256"] = sha(rig.archive)
    monkeypatch.setattr(rig.module, "CANDIDATE_FILES",
                        {name: sha(rig.adapter.release / name) for name in rig.module.CANDIDATE_FILES})
    rig.module.Adapter._verify_release(rig.adapter)
    return rig


def test_historical_transition_refuses_patch_version_even_with_reviewed_storage(verified_release):
    rig = verified_release
    (rig.adapter.release / 'VERSION').write_text('1.0.2\n')
    with pytest.raises(ValueError, match='0.4.1 to 1.0.1'):
        rig.module.Adapter._verify_release(rig.adapter)


@pytest.mark.parametrize("change", ("store", "migration", "application", "manifest_and_application", "archive", "previous_store"))
def test_release_verification_rejects_modified_reviewed_sources(verified_release, change):
    rig = verified_release
    names = {"store": "src/tesla_plugin/store.py", "migration": "src/tesla_plugin/schema_migrations.py",
             "application": "src/tesla_plugin/service.py", "manifest_and_application": "src/tesla_plugin/service.py"}
    if change == "archive":
        rig.archive.write_bytes(rig.archive.read_bytes() + b"synthetic archive change")
    elif change == "previous_store":
        (rig.previous / "src/tesla_plugin/store.py").write_text("changed previous implementation")
    else:
        target = rig.adapter.release / names[change]
        target.write_bytes(target.read_bytes() + b"changed implementation\n")
        if change == "manifest_and_application":
            path = rig.adapter.release / "SHA256SUMS.json"
            manifest = json.loads(path.read_text())
            manifest[names[change]] = sha(target)
            path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        rig.module.Adapter._verify_release(rig.adapter)


def test_success_removes_own_restart_guards_after_committing_runtime_outcome(rig):
    rig.adapter.stage()
    rig.adapter.activate()
    assert not rig.adapter.hold.exists()
    for name in OWNERS:
        path = rig.units / (name + ".service.d") / "90-tesla-schema3-maintenance.conf"
        assert not path.exists()
        assert not rig.ops.startup_inhibited(name)
    assert receipt(rig)["maintenance_cleanup_complete"] is True
    rig.ops.reboot()
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
    rig.adapter.rollback()
    assert not rig.adapter.hold.exists()
    rig.ops.reboot()
    assert_old_runtime(rig)


def test_failed_recovery_hold_blocks_both_services_after_reboot(rig, monkeypatch):
    rig.adapter.stage()
    rig.adapter.activate()

    def unavailable(action):
        raise OSError("synthetic rollback backup unavailable")

    monkeypatch.setattr(rig.adapter, "_schema", unavailable)
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.rollback()
    assert receipt(rig, "rollback.json")["restart_inhibited"] is True
    assert rig.adapter.hold.read_text() == CANDIDATE
    rig.ops.reboot()
    assert_stopped(rig)
    rig.ops.run(["systemctl", "start", "tesla-personal.service", "tesla-consumer.service"])
    assert_stopped(rig)
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [("3",)]


@pytest.mark.parametrize("phase", ("committed_migration", "first_unit_switched"))
def test_new_operator_instance_recovers_interrupted_activation_after_reboot(rig, monkeypatch, phase):
    class PowerLoss(BaseException):
        pass

    rig.adapter.stage()
    if phase == "committed_migration":
        def interrupted_migration(action):
            result = rig.real_schema(action)
            if action == "migrate":
                raise PowerLoss()
            return result
        monkeypatch.setattr(rig.adapter, "_schema", interrupted_migration)
    else:
        original_atomic = rig.ops.atomic

        def interrupted_switch(path, value):
            original_atomic(path, value)
            if Path(path) == rig.units / "tesla-personal.service" and CANDIDATE.encode() in value:
                raise PowerLoss()
        monkeypatch.setattr(rig.ops, "atomic", interrupted_switch)
    with pytest.raises(PowerLoss):
        rig.adapter.activate()
    assert_maintenance_lock_released(rig)
    assert receipt(rig)["state"] in ("started", "migrated")
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [("3",)]
    rig.ops.reboot()
    assert_stopped(rig)
    restarted_profile = json.loads((rig.adapter.recovery / "profile.json").read_text())
    restarted = rig.module.Adapter(restarted_profile, rig.ops, unit_root=rig.units)
    monkeypatch.setattr(restarted, "_verify_release", lambda: None)
    monkeypatch.setattr(restarted, "_schema", rig.real_schema)
    monkeypatch.setattr(restarted, "_health", rig.real_health)
    recovered = restarted.recover()
    assert recovered["state"] == "rolled_back"
    assert_old_runtime(rig)
    assert rig.schema_calls == ["migrate", "rollback"]
    assert receipt(rig)["state"] == "rolled_back"
    assert not rig.adapter.hold.exists()
    with pytest.raises(ValueError, match="No interrupted activation"):
        restarted.recover()


@pytest.mark.parametrize("foreign", ("contents", "file_symlink", "directory_symlink"))
def test_foreign_maintenance_dropin_is_preserved_and_never_used_to_migrate(rig, foreign, tmp_path):
    rig.adapter.stage()
    directory = rig.units / "tesla-consumer.service.d"
    outside = tmp_path / "foreign-configuration"
    outside.mkdir()
    path = directory / "90-tesla-schema3-maintenance.conf"
    original = "[Unit]\nConditionPathExists=/synthetic-independent-condition\n"
    if foreign == "directory_symlink":
        directory.symlink_to(outside, target_is_directory=True)
        target = outside / path.name
        target.write_text(original)
    else:
        directory.mkdir()
        target = outside / "original.conf" if foreign == "file_symlink" else path
        target.write_text(original)
        if foreign == "file_symlink":
            path.symlink_to(target)
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.activate()
    assert target.read_text() == original
    assert rig.schema_calls == []
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [("2",)]
    assert receipt(rig)["restart_inhibited"] is False
    assert_stopped(rig)


def test_missing_loaded_systemd_condition_blocks_before_migration(rig, monkeypatch):
    rig.adapter.stage()
    original_run = rig.ops.run

    def failed_reload(arguments, **kwargs):
        if arguments[0] == "busctl" and "get-property" in arguments:
            return json.dumps({"type": "a(sbbsi)", "data": []})
        return original_run(arguments, **kwargs)

    monkeypatch.setattr(rig.ops, "run", failed_reload)
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.activate()
    assert rig.schema_calls == []
    assert receipt(rig)["restart_inhibited"] is False
    assert_stopped(rig)


@pytest.mark.parametrize("writer", OWNERS)
@pytest.mark.parametrize("lookup", ("call", "get-property"), ids=("GetUnit", "Conditions"))
def test_busctl_lookup_failure_for_either_writer_never_falls_back_to_dropins(rig, monkeypatch, writer, lookup):
    rig.adapter.stage()
    original_run = rig.ops.run
    completed_queries = []
    failed_queries = []

    def failing_busctl(arguments, **kwargs):
        if arguments[0] != "busctl":
            return original_run(arguments, **kwargs)
        name = arguments[-1] if arguments[4] == "call" else next(
            name for name, path in rig.ops.unit_objects.items() if path == arguments[6])
        query = (name, arguments[4])
        if query == (writer + ".service", lookup):
            failed_queries.append(query)
            raise subprocess.CalledProcessError(1, arguments, output="synthetic D-Bus lookup failure")
        result = original_run(arguments, **kwargs)
        completed_queries.append(query)
        return result

    monkeypatch.setattr(rig.ops, "run", failing_busctl)
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.activate()
    assert failed_queries
    if writer == "tesla-consumer":
        assert ("tesla-personal.service", "call") in completed_queries
        assert ("tesla-personal.service", "get-property") in completed_queries
    if lookup == "get-property":
        assert (writer + ".service", "call") in completed_queries
    assert rig.schema_calls == [] and rig.health_calls == []
    assert not any(call[:2] == ["systemctl", "start"] for call in rig.ops.calls)
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [("2",)]
    failed = receipt(rig)
    assert failed["state"] == "recovery_incomplete"
    assert failed["writers_stopped"] is True
    assert failed["restart_inhibited"] is False  # A file cannot prove what systemd loaded.
    assert rig.adapter.hold.read_text() == CANDIDATE
    for name in OWNERS:
        guard = rig.units / (name + ".service.d") / "90-tesla-schema3-maintenance.conf"
        assert guard.read_text() == "[Unit]\nConditionPathExists=!" + str(rig.adapter.hold) + "\n"
        assert (rig.units / (name + ".service")).read_bytes() == rig.initial_units[name]
    assert_stopped(rig)


@pytest.mark.parametrize("evidence", ("verified", "missing", "before_unknown_expiry", "future", "wrong_source",
                                      "unsynchronized", "mismatch", "before_target", "missing_target"))
def test_historical_unknown_requires_matching_authoritative_later_readback(rig, evidence):
    add_intent(rig.database, "historical-unknown", "unknown", created=100, expires=200)
    add_intent(rig.database, "newer-acknowledged", "acknowledged", created=210)
    target = json.loads(sql(rig.database, "SELECT data FROM snapshots WHERE section='telemetry_target'")[0][0])
    observed = {"synced": evidence != "unsynchronized", "config": target}
    if evidence == "mismatch":
        observed["config"]["fields"]["Location"]["interval_seconds"] = 1800
    received = 200 if evidence == "before_unknown_expiry" else 1e30 if evidence == "future" else 300
    if evidence == "before_target":
        sql(rig.database, "UPDATE snapshots SET received=400 WHERE section='telemetry_target'")
    if evidence == "missing_target":
        sql(rig.database, "DELETE FROM snapshots WHERE section='telemetry_target'")
    if evidence != "missing":
        sql(rig.database, "INSERT INTO snapshots VALUES(?,?,?,?,?,?)",
            ("synthetic-vehicle", "telemetry_remote", json.dumps(observed),
             "local_preview" if evidence == "wrong_source" else "tesla_api", received, received))
    refresh_review(rig)
    if evidence == "verified":
        assert rig.adapter.inspect()["pending_collection_count"] == 0
        rig.adapter.stage()
        rig.adapter.activate()
        rig.adapter.rollback()
        assert_old_runtime(rig)
    else:
        assert rig.adapter.inspect()["pending_collection_count"] == 1
        with pytest.raises(ValueError, match="obligation changed"):
            rig.adapter.stage()
        assert not rig.adapter.recovery.exists()
        assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
    assert sql(rig.database, "SELECT status FROM intents WHERE id='historical-unknown'") == [("unknown",)]


def test_expired_preparation_pruning_is_allowed_without_weakening_owner_change_guard(rig):
    add_intent(rig.database, "old-preparation", "prepared", expires=200)
    refresh_review(rig)
    rig.adapter.stage()
    sql(rig.database, "UPDATE intents SET status='expired' WHERE id='old-preparation'")
    assert rig.adapter.inspect()["owner_digest"] == rig.profile["expected_owner_digest"]
    rig.adapter.activate()
    assert rig.adapter.inspect()["owner_digest"] == rig.profile["expected_owner_digest"]
    sql(rig.database, "UPDATE intents SET status='cancelled' WHERE id='old-preparation'")
    with pytest.raises(ValueError, match="Owner operation changed"):
        rig.adapter.rollback()
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
    assert sql(rig.database, "SELECT status FROM intents") == [("cancelled",)]


@pytest.mark.parametrize("observed", ({"synced": True, "config": None}, {"synced": True}, [], 42, None))
def test_paused_readback_requires_explicit_config_and_valid_envelope(rig, observed):
    add_intent(rig.database, "uncertain-pause", "unknown", created=100, expires=200,
               operation="vehicle_fleet_telemetry_config_delete")
    sql(rig.database, "UPDATE snapshots SET data='null',received=210 WHERE section='telemetry_target'")
    sql(rig.database, "INSERT INTO snapshots VALUES(?,?,?,?,?,?)",
        ("synthetic-vehicle", "telemetry_remote", json.dumps(observed), "tesla_api", 300, 300))
    resolved = observed == {"synced": True, "config": None}
    assert rig.adapter.inspect()["pending_collection_count"] == (0 if resolved else 1)


def test_preparation_expiry_between_review_and_stage_is_not_owner_activity(rig):
    add_intent(rig.database, "already-expired-preparation", "prepared", created=100, expires=200)
    refresh_review(rig)
    sql(rig.database, "UPDATE intents SET status='expired' WHERE id='already-expired-preparation'")
    assert rig.adapter.inspect()["intent_digest"] == rig.profile["expected_intent_digest"]
    assert rig.adapter.stage()["state"] == "staged"


@pytest.mark.parametrize("change", ("retention_prunes_old", "deletes_recent", "adds_new", "changes_existing"))
def test_intent_retention_allowance_does_not_hide_owner_operations(rig, change):
    created = 100 if change == "retention_prunes_old" else time.time() - 60
    add_intent(rig.database, "baseline-intent", "acknowledged", created=created,
               operation="vehicle_honk_horn")
    refresh_review(rig)
    rig.adapter.stage()
    if change in ("retention_prunes_old", "deletes_recent"):
        sql(rig.database, "DELETE FROM intents WHERE id='baseline-intent'")
    elif change == "adds_new":
        add_intent(rig.database, "new-owner-intent", "rejected", created=time.time(), operation="vehicle_honk_horn")
    else:
        sql(rig.database, "UPDATE intents SET arguments='{\"changed\":true}' WHERE id='baseline-intent'")
    if change == "retention_prunes_old":
        rig.adapter.activate()
        rig.adapter.rollback()
        assert_old_runtime(rig)
        assert sql(rig.database, "SELECT count(*) FROM intents") == [(0,)]
    else:
        with pytest.raises(ValueError, match="intent loss|owner operation|Owner operation"):
            rig.adapter.activate()
        assert not (rig.adapter.recovery / "activation.json").exists()
        assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
        assert rig.schema_calls == []


def test_cleanup_failure_preserves_committed_candidate_without_starting_new_rollback(rig, monkeypatch):
    rig.adapter.stage()
    original_unlink = Path.unlink
    consumer_guard = rig.units / "tesla-consumer.service.d" / "90-tesla-schema3-maintenance.conf"

    def unavailable_cleanup(path, *args, **kwargs):
        if path == consumer_guard:
            raise OSError("synthetic guard cleanup unavailable")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unavailable_cleanup)
    active = rig.adapter.activate()
    assert active["state"] == "active" and active["maintenance_cleanup_complete"] is False
    assert receipt(rig)["state"] == "active"
    assert receipt(rig)["maintenance_cleanup_complete"] is False
    assert not rig.adapter.hold.exists()
    assert consumer_guard.exists()
    assert rig.schema_calls == ["migrate"]
    rig.ops.reboot()
    assert all(rig.ops.states[name]["ActiveState"] == "active" for name in OWNERS)
    monkeypatch.setattr(Path, "unlink", original_unlink)
    rig.adapter.rollback()
    assert_old_runtime(rig)
    assert not consumer_guard.exists()


def test_interrupted_explicit_rollback_resumes_without_repeating_schema_change(rig, monkeypatch):
    class PowerLoss(BaseException):
        pass

    rig.adapter.stage()
    rig.adapter.activate()

    def interrupted_rollback(action):
        result = rig.real_schema(action)
        if action == "rollback":
            raise PowerLoss()
        return result

    monkeypatch.setattr(rig.adapter, "_schema", interrupted_rollback)
    with pytest.raises(PowerLoss):
        rig.adapter.rollback()
    assert_maintenance_lock_released(rig)
    assert receipt(rig, "rollback.json")["state"] == "started"
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [("2",)]
    rig.ops.reboot()
    assert_stopped(rig)
    restarted = rig.module.Adapter(json.loads((rig.adapter.recovery / "profile.json").read_text()), rig.ops, unit_root=rig.units)
    monkeypatch.setattr(restarted, "_verify_release", lambda: None)
    monkeypatch.setattr(restarted, "_schema", rig.real_schema)
    monkeypatch.setattr(restarted, "_health", rig.real_health)
    assert restarted.recover()["state"] == "rolled_back"
    assert_old_runtime(rig)
    assert rig.schema_calls == ["migrate", "rollback"]
    assert receipt(rig)["state"] == "rolled_back"
    with pytest.raises(ValueError, match="No interrupted activation"):
        restarted.recover()


def test_explicit_recovery_can_resume_its_own_incomplete_attempt(rig, monkeypatch):
    class PowerLoss(BaseException):
        pass

    rig.adapter.stage()

    def interrupted_migration(action):
        rig.real_schema(action)
        raise PowerLoss()

    monkeypatch.setattr(rig.adapter, "_schema", interrupted_migration)
    with pytest.raises(PowerLoss):
        rig.adapter.activate()

    def backup_unavailable(action):
        raise OSError("synthetic backup temporarily unavailable")

    monkeypatch.setattr(rig.adapter, "_schema", backup_unavailable)
    with pytest.raises(rig.module.RecoveryIncomplete):
        rig.adapter.recover()
    assert receipt(rig, "recovery.json")["state"] == "recovery_incomplete"
    rig.ops.reboot()
    assert_stopped(rig)
    monkeypatch.setattr(rig.adapter, "_schema", rig.real_schema)
    assert rig.adapter.recover()["state"] == "rolled_back"
    assert_old_runtime(rig)
    assert rig.schema_calls == ["migrate", "rollback"]


@pytest.mark.parametrize("action", ("stage", "activate", "rollback", "recover"))
def test_all_mutating_entrypoints_refuse_competing_lock_without_service_actions(rig, action):
    if action != "stage":
        rig.adapter.stage()
    if action == "rollback":
        rig.adapter.activate()
    path = rig.adapter.recovery.parent / "schema3-maintenance.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        calls, schema_calls = list(rig.ops.calls), list(rig.schema_calls)
        before = rig.database.read_bytes()
        with pytest.raises(ValueError, match="Another maintenance process"):
            getattr(rig.adapter, action)()
        assert rig.ops.calls == calls
        assert rig.schema_calls == schema_calls
        assert rig.database.read_bytes() == before
        # Status inspection remains available while another operator owns the lock.
        assert rig.adapter.inspect()["schema"] in (2, 3)
    finally:
        os.close(fd)
    assert_maintenance_lock_released(rig)


def _hold_maintenance_lock_in_child(path, connection):
    """A separate local process holds only a synthetic file lock."""
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        connection.send("held")
        assert connection.recv() == "release"
    finally:
        os.close(fd)
        connection.close()


def test_actual_child_process_lock_excludes_activation_until_released(rig):
    rig.adapter.stage()
    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe()
    child = context.Process(target=_hold_maintenance_lock_in_child,
                            args=(rig.adapter.recovery.parent / "schema3-maintenance.lock", child_connection))
    child.start()
    child_connection.close()
    try:
        assert parent_connection.poll(5), "Synthetic lock process did not become ready"
        assert parent_connection.recv() == "held"
        calls = list(rig.ops.calls)
        with pytest.raises(ValueError, match="Another maintenance process"):
            rig.adapter.activate()
        assert rig.ops.calls == calls and rig.schema_calls == []
        assert not (rig.adapter.recovery / "activation.json").exists()
        parent_connection.send("release")
        child.join(timeout=5)
        assert child.exitcode == 0
    finally:
        parent_connection.close()
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)
    assert_maintenance_lock_released(rig)
    assert rig.adapter.activate()["state"] == "active"


@pytest.mark.parametrize("action", ("migrate", "rollback"))
def test_known_sample_loss_during_stopped_schema_change_requires_manual_integrity_review(rig, monkeypatch, action):
    rig.adapter.stage()
    if action == "rollback":
        rig.adapter.activate()

    def losing_schema(operation):
        backup = rig.real_schema(operation)
        sql(rig.database, "DELETE FROM samples")
        return backup

    monkeypatch.setattr(rig.adapter, "_schema", losing_schema)
    with pytest.raises(rig.module.RecoveryIncomplete):
        (rig.adapter.activate if action == "migrate" else rig.adapter.rollback)()
    failed_receipt = receipt(rig, "activation.json" if action == "migrate" else "rollback.json")
    assert failed_receipt["state"] == "recovery_incomplete"
    assert failed_receipt["data_integrity_failed"] is True
    assert failed_receipt["restart_inhibited"] is True
    assert rig.schema_calls == (["migrate"] if action == "migrate" else ["migrate", "rollback"])
    rig.ops.reboot()
    assert_stopped(rig)
    calls = list(rig.ops.calls)
    with pytest.raises(ValueError, match="integrity requires separate operator review"):
        rig.adapter.recover()
    assert rig.ops.calls == calls
    assert not (rig.adapter.recovery / "recovery.json").exists()
    backup = failed_receipt["migration_backup" if action == "migrate" else "rollback_backup"]
    assert sql(backup, "PRAGMA integrity_check") == [("ok",)]
    assert sql(backup, "SELECT count(*) FROM samples") == [(1,)]


def _operator_parent_waiting_on_schema_child(adapter_path, profile, root, arguments):
    """Actual operator subprocess using only a synthetic DB and current identity."""
    spec = importlib.util.spec_from_file_location("synthetic_child_operator", adapter_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profile = profile | {"service_user": pwd.getpwuid(os.geteuid()).pw_name}
    adapter = module.Adapter(profile, FakeOps(Path(root)), unit_root=Path(root) / "units")
    with adapter._exclusive():
        adapter._schema_process(arguments)


@pytest.mark.parametrize("phase", ("before_begin", "after_begin"))
def test_schema_child_keeps_maintenance_lock_after_operator_is_killed(rig, phase):
    rig.adapter.stage()
    ready = rig.adapter.recovery / "synthetic-child-ready"
    release = rig.adapter.recovery / "synthetic-child-release"
    script = """
import os, sqlite3, sys, time
from pathlib import Path
database, ready_name, release_name, phase = sys.argv[1:]
db = sqlite3.connect(database)
if phase == 'after_begin':
    db.execute('BEGIN IMMEDIATE')
Path(ready_name).write_text(str(os.getpid()))
deadline = time.monotonic() + 15
while not Path(release_name).exists() and time.monotonic() < deadline:
    time.sleep(0.01)
if not Path(release_name).exists():
    raise SystemExit(2)
if phase == 'before_begin':
    db.execute('BEGIN IMMEDIATE')
db.execute('CREATE TABLE synthetic_child_probe (completed INTEGER)')
db.execute('INSERT INTO synthetic_child_probe VALUES(1)')
db.commit()
db.close()
"""
    arguments = [sys.executable, "-c", script, str(rig.database), str(ready), str(release), phase]
    context = multiprocessing.get_context("spawn")
    operator = context.Process(target=_operator_parent_waiting_on_schema_child,
                               args=(ADAPTER_PATH, rig.profile, rig.ops.root, arguments))
    child_pid = None
    child_finished = False
    operator.start()
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if ready.exists() and ready.read_text().isdigit():
                child_pid = int(ready.read_text())
                break
            assert operator.is_alive(), "Synthetic operator exited before child synchronization"
            time.sleep(0.01)
        assert child_pid is not None, "Synthetic schema child did not become ready"
        # The before-BEGIN case has no SQLite writer lock; only the inherited
        # maintenance descriptor can exclude another operator in that window.
        with closing(sqlite3.connect(rig.database, timeout=0)) as probe:
            if phase == "before_begin":
                probe.execute("BEGIN IMMEDIATE")
                probe.rollback()
            else:
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    probe.execute("BEGIN IMMEDIATE")
        operator.kill()
        operator.join(timeout=5)
        assert not operator.is_alive()
        os.kill(child_pid, 0)
        calls = list(rig.ops.calls)
        with pytest.raises(ValueError, match="Another maintenance process"):
            rig.adapter.stage()
        assert rig.ops.calls == calls and rig.schema_calls == []
        release.write_text("continue synthetic child")
        deadline = time.monotonic() + 5
        while True:
            try:
                assert_maintenance_lock_released(rig)
                child_finished = True
                break
            except BlockingIOError:
                assert time.monotonic() < deadline, "Schema child did not release inherited lock"
                time.sleep(0.01)
        assert sql(rig.database, "SELECT completed FROM synthetic_child_probe") == [(1,)]
    finally:
        release.write_text("continue synthetic child")
        if operator.is_alive():
            operator.terminate()
            operator.join(timeout=5)
        if child_pid is not None and not child_finished:
            try:
                os.kill(child_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


def test_schema_failure_output_is_bounded_private_and_absent_from_public_error(rig, monkeypatch):
    rig.adapter.stage()
    output = b"synthetic-private-diagnostic:" + b"x" * 70000

    def failed_process(arguments, **kwargs):
        assert kwargs["pass_fds"] == (rig.adapter._lock_fd,)
        os.fstat(kwargs["pass_fds"][0])
        return SimpleNamespace(returncode=1, stdout=output)

    monkeypatch.setattr(rig.module.subprocess, "run", failed_process)
    with rig.adapter._exclusive():
        with pytest.raises(RuntimeError, match="Candidate schema operation failed") as failure:
            rig.adapter._schema_process([sys.executable, "-c", "synthetic code never executed"])
    assert "synthetic-private-diagnostic" not in str(failure.value)
    logs = list(rig.adapter.recovery.glob("schema-failure-*.log"))
    assert len(logs) == 1 and str(logs[0]) == rig.adapter._schema_failure_log
    assert logs[0].stat().st_mode & 0o777 == 0o600
    assert logs[0].read_bytes() == output[-65536:]
    assert logs[0].stat().st_size == 65536
    assert_maintenance_lock_released(rig)


def test_unprintable_systemctl_conditions_do_not_block_verified_typed_bus_condition(rig):
    assert rig.adapter._state("tesla-personal.service", "Conditions") == "[unprintable]"
    rig.adapter.stage()
    assert rig.adapter.activate()["state"] == "active"
    calls = [call for call in rig.ops.calls if call[0] == "busctl"]
    for name in OWNERS:
        assert any(call[4] == "call" and call[-1] == name + ".service" for call in calls)
        assert any(call[4] == "get-property" and call[6] == rig.ops.unit_objects[name + ".service"] for call in calls)
    assert rig.schema_calls == ["migrate"]


@pytest.mark.parametrize("kind,trigger,negate,path_variant,status,expected", (
    ("ConditionPathExists", False, True, "exact", 0, True),
    ("ConditionPathExists", False, True, "exact", -1, True),
    ("ConditionPathExists", False, True, "exact", 1, True),
    ("ConditionPathExists", True, True, "exact", 0, False),
    ("ConditionPathExists", False, False, "exact", 0, False),
    ("ConditionPathExistsGlob", False, True, "exact", 0, False),
    ("AssertPathExists", False, True, "exact", 0, False),
    ("ConditionPathExists", False, True, "prefix", 0, False),
    ("ConditionPathExists", False, True, "suffix", 0, False),
))
def test_typed_conditions_require_exact_mandatory_negated_path(rig, monkeypatch, kind, trigger, negate, path_variant, status, expected):
    path = str(rig.adapter.hold)
    if path_variant == "prefix":
        path = "/unrelated" + path
    elif path_variant == "suffix":
        path += ".unrelated"
    condition = [kind, trigger, negate, path, status]
    queries = []
    object_path = "/org/freedesktop/systemd1/unit/opaque_manager_result"

    def typed_reply(arguments, **kwargs):
        queries.append(arguments)
        if arguments[4] == "call":
            return json.dumps({"type": "o", "data": [object_path]})
        assert arguments[6] == object_path
        return json.dumps({"type": "a(sbbsi)", "data": [condition]})

    monkeypatch.setattr(rig.ops, "run", typed_reply)
    assert rig.adapter._restart_condition_loaded("tesla-personal.service") is expected
    assert queries[0][-1] == "tesla-personal.service"
    assert len(queries) == 2


@pytest.mark.parametrize("case,expected", (("other_conditions", True), ("missing", False), ("duplicate_guard", False)))
def test_typed_condition_array_retains_other_conditions_and_rejects_ambiguous_guard(rig, monkeypatch, case, expected):
    guard = ["ConditionPathExists", False, True, str(rig.adapter.hold), 0]
    other = ["ConditionPathExists", True, False, "/synthetic/optional-condition", 1]
    conditions = [other, guard] if case == "other_conditions" else [other] if case == "missing" else [guard, guard]

    def typed_reply(arguments, **kwargs):
        if arguments[4] == "call":
            return json.dumps({"type": "o", "data": ["/org/freedesktop/systemd1/unit/loaded"]})
        return json.dumps({"type": "a(sbbsi)", "data": conditions})

    monkeypatch.setattr(rig.ops, "run", typed_reply)
    assert rig.adapter._restart_condition_loaded("tesla-personal.service") is expected


@pytest.mark.parametrize("case", ("wrong_signature", "missing_data", "outer_body_wrapper", "not_array", "short_tuple",
                                  "not_tuple", "numeric_trigger", "string_negate", "boolean_status", "nonstring_path",
                                  "nonstring_kind", "malformed_json"))
def test_malformed_typed_conditions_never_qualify_restart_inhibition(rig, monkeypatch, case):
    condition = ["ConditionPathExists", False, True, str(rig.adapter.hold), 0]
    value = {"type": "a(sbbsi)", "data": [condition]}
    if case == "wrong_signature":
        value["type"] = "as"
    elif case == "missing_data":
        del value["data"]
    elif case == "outer_body_wrapper":
        value["data"] = [[condition]]
    elif case == "not_array":
        value["data"] = "[unprintable]"
    elif case == "short_tuple":
        condition.pop()
    elif case == "not_tuple":
        value["data"] = [str(rig.adapter.hold)]
    elif case == "numeric_trigger":
        condition[1] = 0
    elif case == "string_negate":
        condition[2] = "true"
    elif case == "boolean_status":
        condition[4] = False
    elif case == "nonstring_path":
        condition[3] = [str(rig.adapter.hold)]
    elif case == "nonstring_kind":
        condition[0] = None

    def typed_reply(arguments, **kwargs):
        if arguments[4] == "call":
            return json.dumps({"type": "o", "data": ["/org/freedesktop/systemd1/unit/loaded"]})
        return "{invalid" if case == "malformed_json" else json.dumps(value)

    monkeypatch.setattr(rig.ops, "run", typed_reply)
    with pytest.raises(ValueError):
        rig.adapter._restart_condition_loaded("tesla-personal.service")


@pytest.mark.parametrize("value", (
    {"type": "s", "data": ["/org/freedesktop/systemd1/unit/loaded"]},
    {"type": "o", "data": "/org/freedesktop/systemd1/unit/loaded"},
    {"type": "o", "data": []},
    {"type": "o", "data": ["/org/freedesktop/systemd1/unit/one", "/org/freedesktop/systemd1/unit/two"]},
    {"type": "o", "data": ["/unrelated/object"]},
    {"type": "o", "data": [None]},
    [],
))
def test_invalid_getunit_response_is_rejected_before_property_lookup(rig, monkeypatch, value):
    queries = []

    def typed_reply(arguments, **kwargs):
        queries.append(arguments)
        assert arguments[4] == "call"
        return json.dumps(value)

    monkeypatch.setattr(rig.ops, "run", typed_reply)
    with pytest.raises(ValueError, match="Unexpected systemd unit object"):
        rig.adapter._restart_condition_loaded("tesla-personal.service")
    assert len(queries) == 1


PRIVATE_DBUS_SERVICE = r'''
import json, sys
from pathlib import Path
from gi.repository import Gio, GLib
address, conditions_path = sys.argv[1:]
connection = Gio.DBusConnection.new_for_address_sync(
    address, Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
    None, None)
manager = Gio.DBusNodeInfo.new_for_xml(
    '<node><interface name="org.freedesktop.systemd1.Manager"><method name="GetUnit">'
    '<arg type="s" direction="in"/><arg type="o" direction="out"/>'
    '</method></interface></node>').interfaces[0]
unit = Gio.DBusNodeInfo.new_for_xml(
    '<node><interface name="org.freedesktop.systemd1.Unit">'
    '<property name="Conditions" type="a(sbbsi)" access="read"/>'
    '</interface></node>').interfaces[0]
def get_unit(connection, sender, path, interface, name, parameters, invocation):
    if parameters.unpack() != ('tesla-personal.service',):
        invocation.return_dbus_error('org.freedesktop.systemd1.NoSuchUnit', 'Synthetic fixture has one unit')
        return
    invocation.return_value(GLib.Variant('(o)', ('/org/freedesktop/systemd1/unit/opaque_fixture',)))
def get_conditions(connection, sender, path, interface, name):
    return GLib.Variant('a(sbbsi)', [tuple(row) for row in json.loads(Path(conditions_path).read_text())])
connection.register_object('/org/freedesktop/systemd1', manager, get_unit, None, None)
connection.register_object('/org/freedesktop/systemd1/unit/opaque_fixture', unit, None, get_conditions, None)
connection.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus',
    'RequestName', GLib.Variant('(su)', ('org.freedesktop.systemd1', 0)), None,
    Gio.DBusCallFlags.NONE, 5000, None)
print('ready', flush=True)
GLib.MainLoop().run()
'''


def private_dbus_prerequisite_missing(reason):
    if os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("CI") in {"true", "1"}:
        pytest.fail(reason)
    pytest.skip(reason)


def test_ci_missing_private_dbus_binary_fails_instead_of_skipping(monkeypatch):
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    fixture = private_systemd_bus.__wrapped__()
    with pytest.raises(pytest.fail.Exception, match="requires dbus-daemon"):
        try:
            next(fixture)
        except pytest.skip.Exception:
            pytest.fail("CI prerequisite was silently skipped")


@pytest.fixture
def private_systemd_bus():
    """Real busctl wire-format qualification on an isolated, disposable bus."""
    daemon_command, busctl_command = shutil.which("dbus-daemon"), shutil.which("busctl")
    system_python = Path("/usr/bin/python3")
    if not daemon_command or not busctl_command or not system_python.is_file():
        private_dbus_prerequisite_missing("Private D-Bus qualification requires dbus-daemon, busctl and system Python")
    gio = subprocess.run([str(system_python), "-c", "from gi.repository import Gio, GLib"],
                         capture_output=True, timeout=5)
    if gio.returncode:
        private_dbus_prerequisite_missing("Private D-Bus qualification requires system Python Gio/GLib")

    def ready_line(process):
        readable, _, _ = select.select([process.stdout], [], [], 5)
        assert readable, "Private D-Bus fixture did not become ready"
        line = process.stdout.readline().strip()
        assert line, "Private D-Bus fixture exited before readiness"
        return line

    # A short /tmp path also stays below the Unix-domain socket path limit.
    with tempfile.TemporaryDirectory(prefix="tesla-private-bus-") as directory:
        conditions = Path(directory) / "conditions.json"
        conditions.write_text("[]")
        daemon = subprocess.Popen(
            [daemon_command, "--session", "--nofork", "--print-address=1", "--address=unix:path=" + directory + "/bus"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        service = None
        try:
            address = ready_line(daemon)
            assert address.startswith("unix:path=" + directory + "/bus")
            service = subprocess.Popen([str(system_python), "-u", "-c", PRIVATE_DBUS_SERVICE, address, str(conditions)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert ready_line(service) == "ready"
            yield SimpleNamespace(address=address, conditions=conditions, busctl=busctl_command)
        finally:
            for process in (service, daemon):
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                    process.stdout.close()
                    process.stderr.close()


@pytest.mark.parametrize("case,expected", (("valid", True), ("trigger", False), ("not_negated", False),
                                          ("wrong_kind", False), ("wrong_path", False), ("missing", False),
                                          ("other_conditions", True), ("duplicate_guard", False)))
def test_actual_private_dbus_busctl_condition_contract(rig, monkeypatch, private_systemd_bus, case, expected):
    condition = ["ConditionPathExists", False, True, str(rig.adapter.hold), 0]
    conditions = [condition]
    if case == "trigger":
        condition[1] = True
    elif case == "not_negated":
        condition[2] = False
    elif case == "wrong_kind":
        condition[0] = "ConditionPathExistsGlob"
    elif case == "wrong_path":
        condition[3] += ".different"
    elif case == "missing":
        conditions = []
    elif case == "other_conditions":
        conditions.insert(0, ["ConditionPathExists", True, False, "/synthetic/optional", 1])
    elif case == "duplicate_guard":
        conditions.append(list(condition))
    private_systemd_bus.conditions.write_text(json.dumps(conditions))
    replies = []

    def private_bus_only(arguments, **kwargs):
        assert arguments[:4] == ["busctl", "--system", "--json=short", "--timeout=10"]
        # Never execute --system: every actual call is bound to this private bus.
        command = [private_systemd_bus.busctl, "--address=" + private_systemd_bus.address, *arguments[2:]]
        assert "--system" not in command and "--user" not in command
        completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=12)
        replies.append(json.loads(completed.stdout))
        return completed.stdout

    monkeypatch.setattr(rig.ops, "run", private_bus_only)
    assert rig.adapter._restart_condition_loaded("tesla-personal.service") is expected
    assert replies == [
        {"type": "o", "data": ["/org/freedesktop/systemd1/unit/opaque_fixture"]},
        {"type": "a(sbbsi)", "data": conditions},
    ]
    assert rig.schema_calls == []

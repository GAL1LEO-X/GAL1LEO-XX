"""Offline qualification of an explicit legacy repair on a SQLite copy only.

No install-time cleanup is introduced. The adapter must still refuse the
original fixture; only the separately reviewed copy receives expire_unstarted.
"""
from contextlib import closing
from copy import copy
import json
from pathlib import Path
import socket
import sqlite3

import pytest

from tesla_plugin.temporary_collection import expire_unstarted
from test_patch_update import patch_rig, patch_module, schema_rig, adapter_module
from test_schema3_update import OWNER, OWNERS, add_intent, sql

CUTOFF = 1_800_000_000.0
PLAN = json.dumps({'duration_seconds': 60, 'baseline_config': None,
                   'restore_policy': 'restore_only_if_temporary_configuration_still_matches'}, sort_keys=True)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError('Legacy qualification never opens a network connection')
    monkeypatch.setattr(socket.socket, 'connect', denied)
    monkeypatch.setattr(socket.socket, 'connect_ex', denied)
    monkeypatch.setattr(socket, 'create_connection', denied)


def seed(rig, *, intent_status='prepared', consent_expires=CUTOFF-1,
         window_status='prepared', started=None, restore_status=None):
    identifier = 'legacy-consent-synthetic'
    if intent_status is not None:
        add_intent(rig.database, identifier, intent_status, created=CUTOFF-600, expires=consent_expires)
    restore = None
    if restore_status is not None:
        restore = 'legacy-restore-synthetic'
        add_intent(rig.database, restore, restore_status, created=CUTOFF-30, expires=CUTOFF+300)
    sql(rig.database, 'INSERT INTO temporary_collections '
        '(intent_id,vehicle,plan,generation,status,started,expires,restore_intent,updated) VALUES(?,?,?,?,?,?,?,?,?)',
        (identifier, 'synthetic-vehicle', PLAN, 7, window_status, started,
         None if started is None else started+60, restore, CUTOFF-600))
    return identifier


def rows(path, table):
    return sql(path, 'SELECT * FROM '+table+' ORDER BY rowid')


def reviewed_copy(rig):
    path = Path(rig.module.backup_database(rig.database, OWNER))
    assert path != rig.database and path.stat().st_mode & 0o777 == 0o600
    assert sql(path, 'PRAGMA integrity_check') == [('ok',)]
    adapter = copy(rig.adapter)
    adapter.database = path
    return path, adapter


def terminalize_copy(path):
    with closing(sqlite3.connect(path)) as db:
        db.execute('BEGIN IMMEDIATE')
        assert db.execute("SELECT value FROM meta WHERE key='owner'").fetchall() == [(OWNER,)]
        assert db.execute("SELECT value FROM meta WHERE key='schema'").fetchall() == [('3',)]
        expire_unstarted(db, CUTOFF)
        db.commit()


def assert_gate_blocked(adapter):
    snapshot = adapter.inspect()
    with pytest.raises(ValueError, match='collection obligation'):
        adapter._guard(3, snapshot['owner_digest'], adapter.old_units)
    return snapshot


@pytest.mark.parametrize('status,expires', [('prepared', CUTOFF-1), ('prepared', CUTOFF),
    ('cancelled', CUTOFF+1), ('expired', CUTOFF+1), (None, CUTOFF-1)])
def test_expired_unstarted_copy_can_clear_gate_without_mutating_source_or_installing(patch_rig, monkeypatch, status, expires):
    rig = patch_rig
    monkeypatch.setattr(rig.module.base.time, 'time', lambda: CUTOFF)
    identifier = seed(rig, intent_status=status, consent_expires=expires)
    original_intents = rows(rig.database, 'intents')
    original_windows = rows(rig.database, 'temporary_collections')
    original_samples = rows(rig.database, 'samples')
    before = assert_gate_blocked(rig.adapter)
    assert before['pending_temporaries'] == 1
    assert before['pending_collection_count'] == before['sending_count'] == 0
    with pytest.raises(ValueError, match='collection obligation'):
        rig.adapter.stage()
    assert not rig.adapter.release.exists()  # No staging to bypass the refusal.
    assert not any(call[:2] == ['systemctl', 'stop'] for call in rig.ops.calls)
    assert all(rig.ops.states[name]['ActiveState'] == 'active' for name in OWNERS)

    path, inspected_copy = reviewed_copy(rig)
    terminalize_copy(path)
    after = inspected_copy._guard(3, before['owner_digest'], inspected_copy.old_units)
    assert after['pending_temporaries'] == after['pending_collection_count'] == after['sending_count'] == 0
    assert after['owner_digest'] == before['owner_digest']
    assert after['intent_digest'] == before['intent_digest']  # Intent/history not rewritten.
    assert sql(path, 'SELECT status,started,plan,error,updated,lease_owner,lease_until FROM temporary_collections WHERE intent_id=?',
               (identifier,)) == [('cancelled', None, PLAN, 'CONFIRMATION_EXPIRED_OR_CANCELLED', CUTOFF, None, 0)]
    assert rows(path, 'intents') == original_intents
    assert rows(path, 'samples') == original_samples
    terminalize_copy(path)  # Explicit repair is idempotent on this fixed cutoff.
    assert inspected_copy.inspect() == after
    assert rows(rig.database, 'intents') == original_intents
    assert rows(rig.database, 'temporary_collections') == original_windows
    assert rows(rig.database, 'samples') == original_samples
    assert assert_gate_blocked(rig.adapter)['pending_temporaries'] == 1


@pytest.mark.parametrize('options', [
    {'consent_expires': CUTOFF+1},
    {'intent_status': 'sending'},
    {'intent_status': 'unknown'},
    {'intent_status': 'acknowledged'},
    {'started': CUTOFF-120},
    {'window_status': 'active', 'started': CUTOFF-120, 'intent_status': 'acknowledged'},
    {'window_status': 'start_unknown', 'started': CUTOFF-120, 'intent_status': 'unknown'},
    {'window_status': 'restore_pending', 'started': CUTOFF-120, 'intent_status': 'acknowledged', 'restore_status': 'prepared'},
    {'window_status': 'restore_unknown', 'started': CUTOFF-120, 'intent_status': 'acknowledged', 'restore_status': 'unknown'},
    {'window_status': 'restore_accepted', 'started': CUTOFF-120, 'intent_status': 'acknowledged', 'restore_status': 'acknowledged'},
    {'window_status': 'blocked', 'started': CUTOFF-120, 'intent_status': 'acknowledged'},
])
def test_started_uncertain_and_restore_obligations_survive_copy_review_and_keep_gate_closed(patch_rig, monkeypatch, options):
    rig = patch_rig
    monkeypatch.setattr(rig.module.base.time, 'time', lambda: CUTOFF)
    seed(rig, **options)
    before = assert_gate_blocked(rig.adapter)
    original_intents = rows(rig.database, 'intents')
    original_windows = rows(rig.database, 'temporary_collections')
    path, inspected_copy = reviewed_copy(rig)
    terminalize_copy(path)
    assert rows(path, 'temporary_collections') == original_windows
    assert rows(path, 'intents') == original_intents
    assert assert_gate_blocked(inspected_copy) == before
    assert rows(rig.database, 'temporary_collections') == original_windows
    assert rows(rig.database, 'intents') == original_intents

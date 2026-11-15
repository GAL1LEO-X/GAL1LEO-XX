"""Synthetic loss/replacement checks: never contact a real account."""
from dataclasses import replace
import json
import os
import sqlite3

import pytest

from sally_whatsapp.server import Service, create_app
from sally_whatsapp.config import Settings
from sally_whatsapp.state_continuity import StateContinuityError, register_external_identity, STATE_KEY
from sally_whatsapp.store import Store


def service(environment, **changes):
    settings, receiver, gateway, _ = environment
    return Service(replace(settings, **changes), gateway=gateway, event_transport=receiver)


def test_missing_known_database_refuses_restart_and_never_recreates(environment):
    first = service(environment)
    path = first.store.path
    first.store.reserve_send('retained-uncertain-key', 'test-owner', {'text': 'synthetic'})
    path.unlink()
    with pytest.raises(StateContinuityError):
        service(environment)
    assert not path.exists()
    assert environment[2].sent == []


def test_missing_database_in_running_service_never_recreates(environment):
    first = service(environment)
    first.store.path.unlink()
    with pytest.raises(StateContinuityError):
        first.store.reserve_send('never-created-send', 'test-owner', {'text': 'synthetic'})
    assert not first.store.path.exists()
    assert environment[2].sent == []


def test_valid_replacement_database_is_rejected(environment, tmp_path):
    first = service(environment)
    other = Store(tmp_path/'replacement.sqlite')
    os.replace(other.path, first.store.path)
    with pytest.raises(StateContinuityError):
        first.store.state()
    with pytest.raises(StateContinuityError):
        service(environment)
    assert environment[2].sent == []


def test_corruption_is_rejected_before_service_can_start(environment):
    settings = environment[0]
    settings.database.write_bytes(b'invalid SQLite synthetic data')
    with pytest.raises(StateContinuityError):
        service(environment)
    assert settings.database.read_bytes() == b'invalid SQLite synthetic data'


def test_check_missing_database_does_not_initialize(environment):
    settings, receiver, gateway, _ = environment
    with pytest.raises(StateContinuityError):
        create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False, recover_inflight=False)
    assert not settings.database.exists()


def test_check_existing_legacy_database_does_not_enroll_or_recover(environment):
    settings, receiver, gateway, _ = environment
    store = Store(settings.database)
    store.reserve_send('still-inflight-key', 'test-owner', {'text': 'synthetic'})
    create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False, recover_inflight=False)
    with store.db() as db:
        assert db.execute('SELECT value FROM state WHERE key=?', (STATE_KEY,)).fetchone() is None
    assert not settings.database.with_name(settings.database.name+'.identity.json').exists()
    assert store.send_status('still-inflight-key')['state'] == 'sending'


def test_check_empty_file_does_not_initialize_schema(environment):
    settings, receiver, gateway, _ = environment
    settings.database.touch()
    with pytest.raises(StateContinuityError):
        create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False, recover_inflight=False)
    assert settings.database.stat().st_size == 0


def test_identity_is_private_and_restart_preserves_uncertainty(environment):
    first = service(environment)
    first.store.reserve_send('retained-key', 'test-owner', {'text': 'synthetic'})
    marker = first.continuity.marker.read_bytes()
    restarted = service(environment)
    assert restarted.continuity.marker.read_bytes() == marker
    assert restarted.store.send_status('retained-key')['state'] == 'uncertain'
    assert STATE_KEY not in restarted.store.state()
    assert environment[2].sent == []


def test_marker_loss_requires_review_instead_of_new_identity(environment):
    first = service(environment)
    first.continuity.marker.unlink()
    with pytest.raises(StateContinuityError):
        service(environment)


def test_external_registration_is_explicit_and_survives_directory_loss(environment, tmp_path):
    settings = replace(environment[0], database=tmp_path/'data'/'archive.sqlite',
                       state_identity_file=tmp_path/'configuration'/'technical-state.json')
    Store(settings.database)
    with pytest.raises(StateContinuityError):
        service(environment, database=settings.database, state_identity_file=settings.state_identity_file)
    register_external_identity(settings)
    instance = service(environment, database=settings.database, state_identity_file=settings.state_identity_file)
    marker = settings.state_identity_file.read_bytes()
    instance.store.path.unlink()
    with pytest.raises(StateContinuityError):
        service(environment, database=settings.database, state_identity_file=settings.state_identity_file)
    assert settings.state_identity_file.read_bytes() == marker
    assert not settings.database.exists()


def test_external_registration_preserves_identity_and_refuses_cross_tenant(environment, tmp_path):
    first = service(environment, database=tmp_path/'data'/'archive.sqlite')
    original = json.loads(first.continuity.marker.read_text())
    settings = replace(first.settings, state_identity_file=tmp_path/'configuration'/'identity.json')
    register_external_identity(settings)
    assert json.loads(settings.state_identity_file.read_text()) == original
    with pytest.raises(StateContinuityError):
        service(environment, database=settings.database, state_identity_file=settings.state_identity_file, owner_subject='other-owner')
    with pytest.raises(StateContinuityError):
        register_external_identity(replace(settings, owner_subject='other-owner'))


def test_external_registration_rejects_unknown_empty_database(environment, tmp_path):
    settings = replace(environment[0], state_identity_file=tmp_path/'configuration'/'identity.json')
    sqlite3.connect(settings.database).close()
    with pytest.raises(StateContinuityError):
        register_external_identity(settings)
    assert not settings.state_identity_file.exists()


def test_lost_media_cache_does_not_invalidate_technical_state(environment):
    first = service(environment)
    cache = first.store.path.parent/'media'
    cache.mkdir(exist_ok=True)
    (cache/'synthetic.bin').write_bytes(b'temporary data')
    (cache/'synthetic.bin').unlink()
    cache.rmdir()
    assert service(environment).store.state()
    assert environment[2].sent == []


def test_file_config_requires_external_identity_without_rewriting_legacy_toml(environment, tmp_path):
    settings = replace(environment[0], database=tmp_path/'data'/'archive.sqlite')
    config = tmp_path/'configuration'/'bridge.toml'
    config.parent.mkdir()
    # Only the pre-0.5.0 fields are written; the deployed 0.4.9 parser therefore
    # receives its original contract while a pre-release backup restarts it.
    names = ('database','public_url','issuer','owner_subject','webhook_secret_file',
             'encryption_key_file','public_key_file','oauth_client_ids')
    config.write_text('[bridge]\n'+'\n'.join(
        name+' = '+json.dumps(str(getattr(settings,name)) if name.endswith('_file') or name=='database'
                              else getattr(settings,name)) for name in names)+'\n')
    original = config.read_bytes()
    loaded = Settings.load(str(config))
    assert loaded.state_identity_file == config.parent/'technical-state.json'
    with pytest.raises(StateContinuityError):
        Service(loaded, gateway=environment[2], event_transport=environment[1])
    assert not loaded.database.exists()
    Store(loaded.database)  # Explicit preparation of a genuinely new installation.
    register_external_identity(loaded)
    Service(loaded, gateway=environment[2], event_transport=environment[1])
    assert config.read_bytes() == original and b'state_identity_file' not in original

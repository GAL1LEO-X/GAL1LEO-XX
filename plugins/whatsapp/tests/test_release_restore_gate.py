"""A receiver must not install code that ignores an unreconciled restore gate."""
from pathlib import Path

import pytest

from test_release_recovery import publication
import github_release as release
import github_release_common as common


@pytest.mark.parametrize('dry_run', [False, True])
@pytest.mark.parametrize('kind', ['valid', 'malformed', 'empty', 'directory', 'dangling-link'])
def test_any_restore_marker_blocks_before_candidate_or_service_effects(publication, monkeypatch, dry_run, kind):
    p = publication
    # Even a suspended peer is affected by the shared backend replacement.
    marker = release.instances(p.root)[1]['config'].parent / 'restore-maintenance.json'
    if kind == 'directory':
        marker.mkdir()
    elif kind == 'dangling-link':
        marker.symlink_to(marker.parent / 'absent-receipt')
    else:
        marker.write_text({'valid': '{}', 'malformed': '{broken', 'empty': ''}[kind])
    for name in ('literal', 'active', 'health', 'build_backend', 'runtime_backups', 'activate'):
        monkeypatch.setattr(release, name, lambda *a, **k: pytest.fail('Effect or candidate probe before restore gate'))
    with pytest.raises(common.ReleaseError, match='Restore maintenance'):
        release.publish(p.checkout, {**p.target, 'dryRun': dry_run}, {})
    assert not p.commands and not p.backups
    assert not (p.state / 'whatsapp/pending.json').exists()


def test_unreadable_marker_fails_closed(publication, monkeypatch):
    p = publication
    marker = release.instances(p.root)[0]['config'].parent / 'restore-maintenance.json'
    original = Path.lstat
    def denied(path, *args, **kwargs):
        if path == marker:
            raise PermissionError('synthetic permission denial')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', denied)
    with pytest.raises(common.ReleaseError, match='cannot be verified'):
        release.publish(p.checkout, p.target, {})
    assert not p.commands and not p.backups


def test_missing_or_symlink_configuration_directory_is_not_clearance(tmp_path):
    missing = tmp_path / 'absent/config.toml'
    with pytest.raises(common.ReleaseError, match='cannot be verified'):
        release.require_restore_reconciled([{'config': missing}])
    target = tmp_path / 'real'
    target.mkdir()
    link = tmp_path / 'linked'
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(common.ReleaseError, match='Restore maintenance'):
        release.require_restore_reconciled([{'config': link / 'config.toml'}])


def test_marker_created_during_preparation_is_rechecked_under_tenant_lock(publication, monkeypatch):
    p = publication
    marker = release.instances(p.root)[0]['config'].parent / 'restore-maintenance.json'
    actual_build = release.build_backend
    def build(source):
        candidate = actual_build(source)
        marker.write_text('{}')
        return candidate
    monkeypatch.setattr(release, 'build_backend', build)
    with pytest.raises(common.ReleaseError, match='Restore maintenance'):
        release.publish(p.checkout, p.target, {})
    assert not p.commands and not p.backups
    assert not (p.state / 'whatsapp/pending.json').exists()


def test_physical_absence_allows_normal_release(publication):
    assert release.publish(publication.checkout, publication.target, {})['status'] == 'published'
    assert len(publication.backups) == 1


@pytest.mark.parametrize('kind', ['marker', 'dangling-link', 'unreadable'])
def test_broker_receiver_callback_rechecks_gate_under_publication_lease(tmp_path, monkeypatch, kind):
    import sys
    from types import SimpleNamespace
    from test_web_admin_broker import broker
    configuration = tmp_path / 'config'
    configuration.mkdir()
    marker = configuration / 'restore-maintenance.json'
    def obstruct():
        if kind == 'marker':
            marker.write_text('{}')
        elif kind == 'dangling-link':
            marker.symlink_to(configuration / 'absent')
        else:
            original = Path.lstat
            def denied(path, *args, **kwargs):
                if path == marker:
                    raise PermissionError('synthetic marker denial')
                return original(path, *args, **kwargs)
            monkeypatch.setattr(Path, 'lstat', denied)
    generation = SimpleNamespace(path=tmp_path, state='dedicated', epoch='a' * 32, manifest_sha256='b' * 64)
    administration = SimpleNamespace(load_generation=lambda **kw: generation, pin_generation=lambda g: None,
                                     require_current=lambda *a, **kw: generation)
    receiver = SimpleNamespace(__file__=str(tmp_path / 'github_release.py'), ROOT=tmp_path,
        instances=lambda root: [{'slug': 'alpha', 'config': configuration / 'config.toml'}],
        publish=lambda *a: pytest.fail('Publication bypassed the restore gate'))
    phases = []
    def receiver_main(project, handler, *, preflight):
        preflight()
        phases.append('publication_lock_held')
        obstruct()
        preflight()
        pytest.fail('Receiver created work or checkout despite restore gate')
    common_receiver = SimpleNamespace(__file__=str(tmp_path / 'github_release_common.py'), main=receiver_main)
    monkeypatch.setattr(sys, 'path', list(sys.path))
    monkeypatch.setitem(sys.modules, 'host_integration', SimpleNamespace(load_administration=lambda: administration))
    monkeypatch.setitem(sys.modules, 'release_admin', administration)
    monkeypatch.setitem(sys.modules, 'github_release', receiver)
    monkeypatch.setitem(sys.modules, 'github_release_common', common_receiver)
    monkeypatch.setattr(broker, 'artifact', lambda v: broker.encoded({'dry_run': False, 'expected_commit': 'c' * 40}))
    with pytest.raises(broker.Rejected, match='BROKER_RESTORE_RECONCILIATION_REQUIRED'):
        broker.release_dispatch({'owner': broker.owner_record(generation)}, {
            'operation': 'release.activate', 'affected_instances': ['alpha'], 'parameters': {'request': {}}})
    assert phases == ['publication_lock_held']


def test_receiver_start_refuses_before_download_or_work_directory(publication, monkeypatch):
    p = publication
    marker = release.instances(p.root)[0]['config'].parent / 'restore-maintenance.json'
    marker.write_text('{}')
    def admitted_main(project, handler, *, preflight):
        assert project == 'whatsapp' and handler is release.publish
        preflight()
        pytest.fail('Receiver started preparation despite restore gate')
    monkeypatch.setattr(release, 'main', admitted_main)
    with pytest.raises(common.ReleaseError, match='Restore maintenance'):
        release.receive()
    assert not p.commands and not p.backups

"""Synthetic private policy/ledger/UNIX tests: no installed service or account."""
from contextlib import contextmanager
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import sys
import threading
import time
from types import SimpleNamespace

import pytest

SCRIPTS = Path(__file__).parents[1] / 'scripts'
spec = importlib.util.spec_from_file_location('tested_web_admin_broker', SCRIPTS / 'web_admin_broker.py')
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)


@pytest.fixture
def tmp_path(short_socket_tmp_path):
    """Keep the entire socket fixture physical and below the AF_UNIX limit."""
    return short_socket_tmp_path


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(broker.encoded(content) if isinstance(content, dict) else content)
    path.chmod(0o600)


@pytest.fixture
def policy(tmp_path, monkeypatch):
    monkeypatch.setattr(broker, 'TRUST_ROOT', tmp_path)
    monkeypatch.setattr(broker, 'TRUST_UID', os.getuid())
    project = tmp_path / 'project'
    state = tmp_path / 'state'
    project.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    value = {
        'format': broker.FORMAT, 'enabled': True, 'project': str(project),
        'installation_sha256': 'a' * 64,
        'owner': {'protocol': 1, 'epoch': 'b' * 32, 'state': 'dedicated',
                  'generation': '/usr/local/whatsapp/generation', 'manifest_sha256': 'c' * 64},
        'sources': {'scripts/web_admin_broker.py': 'd' * 64},
        'state_directory': str(state), 'socket': '/run/whatsapp-broker/control.sock', 'socket_gid': 123,
        'principals': [{'uid': 1234, 'owner': 'oidc-owner-alpha', 'instance': 'alpha',
                        'targets': ['alpha'], 'operations': ['backup.create'], 'global_admin': False}],
        'approvals': {'e' * 32: {'uid': 1234, 'operation': 'backup.create', 'target': 'alpha',
                               'scope': 'instance', 'affected_instances': ['alpha'], 'description': 'Backup alpha',
                               'expires': 253402300000, 'parameters': {}}},
    }
    path = tmp_path / 'policy.json'
    write(path, value)
    return value, path


def envelope(method='execute', *, identifier='f' * 32, approval='e' * 32, operation='backup.create', target='alpha'):
    request = {'id': identifier, 'operation': operation, 'target': target,
               'arguments': {'approval': approval}, 'confirmation': operation + ':' + target}
    if method == 'status':
        request = {'id': identifier}
    elif method == 'capabilities':
        request = {}
    return {'version': 1, 'method': method, 'owner': 'oidc-owner-alpha', 'instance': 'alpha', 'request': request}


def make(policy, execute=None, preflight=None):
    return broker.Broker(policy[1], executor=execute or (lambda p, a, fd: {
        'completed': True, 'operation': p['approvals'][a]['operation'], 'target': p['approvals'][a]['target'],
        **({'allocation_released': False, 'instance_reusable': False, 'administrative_records_retained': True}
           if p['approvals'][a]['operation'] == 'instance.cancel' else {})}),
        preflight=preflight or (lambda p, a: None))


def assert_error(response, code):
    assert response['ok'] is False
    assert response['error_code'] == code
    assert set(response) == {'ok', 'error_code', 'message'}


def assert_before_intent(response, code):
    assert response['ok'] is True
    assert response['result']['state'] == 'failed_before_execution'
    assert response['result']['execution_phase'] == 'before_intent'
    assert response['result']['error_code'] == code


def test_real_sqlite_journal_idempotence_and_restart(policy):
    calls = []
    def execute(p, a, fd):
        calls.append(a)
        assert os.fstat(fd).st_nlink == 1
        # The durable running receipt is readable while the worker acts.
        status = make(policy).handle(1234, envelope('status'))
        assert status['result']['state'] == 'uncertain'
        return {'completed': True, 'operation': 'backup.create', 'target': 'alpha'}
    service = make(policy, execute)
    first = service.handle(1234, envelope())
    assert first['result']['state'] == 'completed'
    assert first['result']['result']['exit_code'] == 0
    assert make(policy).handle(1234, envelope()) == first
    assert calls == ['e' * 32]
    assert_error(service.handle(1234, envelope(identifier='1' * 32)), 'BROKER_APPROVAL_CONSUMED')
    receipts = service.handle(1234, envelope('capabilities'))['result']
    assert receipts['receipts'][0]['id'] == 'f' * 32
    assert receipts['actions'][0]['request_id'] == 'f' * 32
    assert receipts['actions'][0]['available'] is False


@pytest.mark.parametrize('shared_broker', [True, False], ids=['same-broker', 'independent-brokers'])
def test_concurrent_first_capabilities_share_private_journal(policy, monkeypatch, shared_broker):
    from concurrent.futures import ThreadPoolExecutor
    journal = Path(policy[0]['state_directory']) / 'journal.sqlite'
    ready = threading.Barrier(2)
    original_open = os.open
    effects = []
    first = make(policy, execute=lambda *_: effects.append('unexpected execution'))
    services = [first, first if shared_broker else make(policy)]

    def concurrent_open(path, flags, *args, **kwargs):
        if Path(path) == journal and flags & os.O_EXCL:
            # Both first observations reach atomic creation before either
            # creates the file. The losing reader must use the valid winner.
            ready.wait(timeout=5)
        return original_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as race:
        race.setattr(os, 'open', concurrent_open)
        with ThreadPoolExecutor(max_workers=2) as workers:
            pending = [workers.submit(service.handle, 1234, envelope('capabilities'))
                       for service in services]
            replies = [future.result(timeout=10) for future in pending]
    assert all(reply['ok'] for reply in replies), replies
    for reply in replies:
        assert reply['result']['actions'][0]['affected_instances'] == ['alpha']
        assert reply['result']['actions'][0]['available'] is True
        assert reply['result']['receipts'] == []
    assert effects == []
    info = journal.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
    assert info.st_uid == os.getuid()
    with first.database(policy[0]) as db:
        assert db.execute('SELECT count(*) FROM requests').fetchone()[0] == 0


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'public-file', 'directory'])
def test_untrusted_concurrent_journal_is_rejected_without_mutation(policy, tmp_path, monkeypatch, kind):
    journal = Path(policy[0]['state_directory']) / 'journal.sqlite'
    target = tmp_path / 'preserved-file'
    preserved = b'Synthetic file which must not become a journal.'
    write(target, preserved)
    original_open = os.open
    created = []

    def concurrent_open(path, flags, *args, **kwargs):
        if Path(path) == journal and flags & os.O_EXCL and not created:
            if kind == 'symlink':
                journal.symlink_to(target)
            elif kind == 'hardlink':
                os.link(target, journal)
            elif kind == 'public-file':
                journal.write_bytes(preserved)
                journal.chmod(0o644)
            else:
                journal.mkdir(mode=0o700)
            created.append(journal.lstat())
        return original_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as race:
        race.setattr(os, 'open', concurrent_open)
        reply = make(policy).handle(1234, envelope('capabilities'))
    assert len(created) == 1
    expected = 'BROKER_INPUT_REJECTED' if kind == 'hardlink' else 'BROKER_UNTRUSTED_PATH'
    assert_error(reply, expected)
    after = journal.lstat()
    assert (after.st_ino, after.st_mode, after.st_nlink) == (
        created[0].st_ino, created[0].st_mode, created[0].st_nlink)
    assert target.read_bytes() == preserved
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    if kind == 'directory':
        assert list(journal.iterdir()) == []
    else:
        assert journal.read_bytes() == preserved
    assert list(journal.parent.iterdir()) == [journal]


@pytest.mark.parametrize('change', [
    lambda r: r.update(owner='other-owner'), lambda r: r.update(instance='bravo'),
])
def test_peer_cannot_assert_another_principal(policy, change):
    request = envelope()
    change(request)
    assert_error(make(policy).handle(1234, request), 'BROKER_NOT_AUTHORIZED')


def test_wrong_kernel_uid_and_cross_tenant_target_denied(policy):
    service = make(policy)
    assert_error(service.handle(9876, envelope()), 'BROKER_NOT_AUTHORIZED')
    assert_error(service.handle(1234, envelope(target='bravo')), 'BROKER_NOT_AUTHORIZED')
    assert not (Path(policy[0]['state_directory']) / 'journal.sqlite').exists()


@pytest.mark.parametrize('field,value', [('command', 'sh -c id'), ('path', '/etc/passwd'), ('token', 'secret')])
def test_no_raw_parameters_or_privilege_escape(policy, field, value):
    request = envelope()
    request['request']['arguments'][field] = value
    assert_error(make(policy).handle(1234, request), 'BROKER_INPUT_REJECTED')


def test_unknown_action_confirmation_and_duplicate_fields_rejected(policy):
    service = make(policy)
    bad = envelope()
    bad['request']['confirmation'] = ''
    assert_error(service.handle(1234, bad), 'BROKER_INPUT_REJECTED')
    assert_error(service.handle(1234, envelope(operation='shell.execute')), 'BROKER_NOT_AUTHORIZED')
    with pytest.raises(broker.Rejected):
        broker.decode(b'{"uid":1234,"uid":0}')
    with pytest.raises(broker.Rejected):
        broker.decode(b'{"expires":NaN}')


def test_same_id_new_payload_conflict(policy):
    service = make(policy)
    assert service.handle(1234, envelope())['ok']
    p, path = policy
    p['approvals']['1' * 32] = deepcopy(p['approvals']['e' * 32])
    write(path, p)
    assert_error(make(policy).handle(1234, envelope(approval='1' * 32)), 'BROKER_IDEMPOTENCY_CONFLICT')


@pytest.mark.parametrize('result', [None, {}, {'completed': False}, {'completed': True, 'operation': 'backup.create', 'target': 'bravo'}])
def test_exit_zero_or_incomplete_receipt_is_not_completion(policy, result):
    service = make(policy, lambda *args: result)
    response = service.handle(1234, envelope())
    assert response['result']['state'] == 'uncertain'
    assert make(policy).handle(1234, envelope())['result']['state'] == 'uncertain'


def test_exception_after_effects_blocks_new_ids_and_new_approvals(policy):
    def fail(*args):
        raise RuntimeError('SECRET raw operational exception')
    response = make(policy, fail).handle(1234, envelope())
    assert response['result']['state'] == 'uncertain'
    assert 'SECRET' not in json.dumps(response)
    p, path = policy
    p['approvals']['1' * 32] = deepcopy(p['approvals']['e' * 32])
    write(path, p)
    assert_before_intent(make(policy).handle(1234, envelope(identifier='2' * 32, approval='1' * 32)),
                         'BROKER_RECONCILIATION_REQUIRED')


def test_process_interruption_keeps_durable_uncertain_intent(policy):
    def crash(*args):
        raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        make(policy, crash).handle(1234, envelope())
    assert make(policy).handle(1234, envelope('status'))['result']['state'] == 'uncertain'
    assert make(policy).handle(1234, envelope())['result']['state'] == 'uncertain'


def test_concurrent_execution_is_fenced_and_status_remains_readable(policy):
    entered, release = threading.Event(), threading.Event()
    def execute(*args):
        entered.set()
        assert release.wait(5)
        return {'completed': True, 'operation': 'backup.create', 'target': 'alpha'}
    service = make(policy, execute)
    results = []
    thread = threading.Thread(target=lambda: results.append(service.handle(1234, envelope())))
    thread.start()
    try:
        assert entered.wait(5)
        assert service.handle(1234, envelope('status'))['result']['state'] == 'uncertain'
        assert_error(make(policy).handle(1234, envelope(identifier='1' * 32)), 'BROKER_BUSY')
    finally:
        release.set()
        thread.join(5)
    assert results[0]['result']['state'] == 'completed'


def test_policy_change_requires_restart_and_receipts_survive_expiry(policy):
    service = make(policy)
    assert service.handle(1234, envelope())['ok']
    p, path = policy
    p['approvals'] = {}
    write(path, p)
    assert_error(service.handle(1234, envelope('capabilities')), 'BROKER_POLICY_RESTART_REQUIRED')
    fresh = make(policy)
    assert fresh.handle(1234, envelope('capabilities'))['result']['receipts'][0]['state'] == 'completed'
    assert fresh.handle(1234, envelope('status'))['result']['state'] == 'completed'


def test_expired_approval_rejected_before_execution(policy):
    p, path = policy
    p['approvals']['e' * 32]['expires'] = 1
    write(path, p)
    assert_before_intent(make(policy).handle(1234, envelope()), 'BROKER_APPROVAL_EXPIRED')


@pytest.mark.parametrize('mode', [0o644, 0o660, 0o666])
def test_policy_must_be_private_not_just_owned(policy, mode):
    policy[1].chmod(mode)
    assert_error(make(policy).handle(1234, envelope()), 'BROKER_UNTRUSTED_PATH')


def test_policy_symlink_and_journal_symlink_rejected(policy, tmp_path):
    p, path = policy
    linked = tmp_path / 'linked'
    linked.symlink_to(path)
    assert_error(make((p, linked)).handle(1234, envelope()), 'BROKER_UNTRUSTED_PATH')
    journal = Path(p['state_directory']) / 'journal.sqlite'
    journal.symlink_to(path)
    assert_error(make(policy).handle(1234, envelope('status')), 'BROKER_UNTRUSTED_PATH')


def test_shared_release_needs_explicit_global_scope_and_complete_targets(policy):
    p, path = policy
    approval = p['approvals']['e' * 32]
    approval.update(operation='release.activate', target='installation', scope='installation',
                    affected_instances=['alpha', 'bravo'], parameters={'request': {'path': '/protected/release.json', 'sha256': '1' * 64}})
    principal = p['principals'][0]
    principal['operations'] = ['release.activate']
    write(path, p)
    request = envelope(operation='release.activate', target='installation')
    assert_error(make(policy).handle(1234, request), 'BROKER_NOT_AUTHORIZED')
    principal['global_admin'] = True
    write(path, p)
    assert_error(make(policy).handle(1234, request), 'BROKER_NOT_AUTHORIZED')
    principal['targets'].append('bravo')
    write(path, p)
    assert make(policy).handle(1234, request)['result']['state'] == 'completed'


def test_manifest_pins_templates_images_schemas_and_rejects_bytecode(policy):
    p, _ = policy
    project = Path(p['project'])
    files = ['scripts/web_admin_broker.py', 'scripts/backup_schemas/8.sql',
             'sally_whatsapp/__init__.py', 'deploy/whatsapp-personal.service',
             'deploy/images.lock.json', 'deploy/whatsapp-waha.container']
    for name in files:
        write(project / name, b'original')
    first = broker.source_files(project)
    assert set(first) == set(files)
    write(project / 'deploy/images.lock.json', b'changed image')
    assert broker.source_files(project) != first
    write(project / 'scripts/__pycache__/spoof.pyc', b'bytecode')
    with pytest.raises(broker.Rejected, match='BROKER_SOURCE_BYTECODE'):
        broker.source_files(project)


def test_artifact_exact_digest_and_no_duplicate_keys(policy, tmp_path):
    path = tmp_path / 'plan'
    write(path, {'a': 1})
    value = {'path': str(path), 'sha256': broker.digest(path.read_bytes())}
    assert broker.artifact(value) == path.read_bytes()
    write(path, {'a': 2})
    with pytest.raises(broker.Rejected, match='BROKER_ARTIFACT_CHANGED'):
        broker.artifact(value)


def prepare_recovery(policy):
    p, path = policy
    p['principals'][0]['operations'] = ['instance.prepare', 'instance.cancel']
    a = p['approvals']['e' * 32]
    setup = {key: 'synthetic' for key in ('name', 'hostname', 'issuer', 'jwks_url', 'subject',
                                        'oauth_client_id', 'link_client_id', 'chatgpt_callback')}
    setup['auth_mode'] = 'external-oidc'
    a.update(operation='instance.prepare', parameters={'entry': 'add', 'attempt_id': 'a' * 32,
             'host_plan': {'path': '/approved/plan', 'sha256': 'b' * 64}, 'setup': setup})
    write(path, p)
    response = make(policy, lambda *args: {}).handle(1234, envelope(operation='instance.prepare'))
    assert response['result']['state'] == 'uncertain'
    recovery = deepcopy(a)
    recovery.update(operation='instance.cancel', recovers='e' * 32,
                    parameters={key: a['parameters'][key] for key in ('attempt_id', 'host_plan')})
    p['approvals']['1' * 32] = recovery
    write(path, p)
    return p, path


def test_explicit_recovery_only_for_bound_attempt_and_then_unblocks(policy):
    prepare_recovery(policy)
    service = make(policy)
    result = service.handle(1234, envelope(identifier='2' * 32, approval='1' * 32, operation='instance.cancel'))
    assert result['result']['state'] == 'completed'
    previous = service.handle(1234, envelope('status'))['result']
    assert previous['state'] == 'uncertain'
    assert previous['reconciled_by'] == '2' * 32


def test_wrong_attempt_cannot_use_recovery_escape(policy):
    p, path = prepare_recovery(policy)
    p['approvals']['1' * 32]['parameters']['attempt_id'] = 'c' * 32
    write(path, p)
    result = make(policy).handle(1234, envelope(identifier='2' * 32, approval='1' * 32, operation='instance.cancel'))
    assert_before_intent(result, 'BROKER_RECOVERY_MISMATCH')


def test_unix_transport_reads_kernel_peer_uid_not_claimed_json(policy, tmp_path):
    path = str(tmp_path / 'socket')
    observed = []
    service = make(policy)
    actual_handle = service.handle
    def handle(uid, request):
        observed.append(uid)
        return actual_handle(uid, request)
    service.handle = handle
    with broker.Server(path, broker.Handler) as server:
        server.broker = service
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
        thread.start()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(path)
                client.sendall(broker.encoded(envelope()))
                response = broker.decode(client.recv(broker.MAX_FRAME))
            assert observed == [os.getuid()]
            if os.getuid() != 1234:
                assert_error(response, 'BROKER_NOT_AUTHORIZED')
        finally:
            server.shutdown()
            thread.join(5)


def test_admission_owner_is_rechecked_after_both_leases(tmp_path, monkeypatch):
    sys.path.insert(0, str(SCRIPTS))
    import host_integration as integration
    root = tmp_path / 'project'
    (root / 'private').mkdir(parents=True)
    expected = {'protocol': 1, 'epoch': 'b' * 32, 'state': 'dedicated',
                'generation': '/synthetic/generation', 'manifest_sha256': 'c' * 64}
    current = SimpleNamespace(epoch=expected['epoch'], state='dedicated', path=expected['generation'],
                              manifest_sha256=expected['manifest_sha256'])
    calls = []
    @contextmanager
    def publication_lock(**kwargs):
        calls.append('publication')
        current.epoch = 'd' * 32
        yield
    admin = SimpleNamespace(load_generation=lambda **kwargs: current, publication_lock=publication_lock,
                            trusted_path=lambda path, **kwargs: path, _trusted_uid=lambda uid: uid == os.getuid())
    with integration.constrained_admission(expected):
        with pytest.raises(ValueError, match='owner differs'):
            with integration.runtime_admission(root, administration=admin):
                pytest.fail('Changed owner was admitted')
    assert calls == ['publication']


def test_preflight_uses_actual_installation_paths_and_pin(policy, monkeypatch, tmp_path):
    from sally_whatsapp.installation import Installation
    p, _ = policy
    # Installation roots describe the host, not the test runner checkout (which
    # may live under /home or /tmp). Translate only filesystem access into the
    # sandbox; keep real Installation validation, digest and path APIs intact.
    host = Path('/srv/synthetic-whatsapp-broker')
    def sandbox_path(value):
        path = Path(value)
        return tmp_path / 'host' / path.relative_to(host) if path.is_relative_to(host) else path
    monkeypatch.setattr(broker, 'Path', sandbox_path)
    value = json.loads((SCRIPTS.parent / 'deploy/installation.example.json').read_bytes())
    value['paths'] = {field: str(host / field) for field in value['paths']}
    profile = Installation.from_dict(value)
    p['project'] = profile.path('project')
    project = sandbox_path(p['project'])
    project.mkdir(parents=True, mode=0o700)
    for account in profile.accounts():
        sandbox_path(profile.instance_paths(account)['configuration']).mkdir(parents=True, mode=0o700)
    # The policy fixture target is independent from example initial slugs.
    sandbox_path(profile.instance_paths('alpha')['configuration']).mkdir(parents=True, exist_ok=True, mode=0o700)
    p['installation_sha256'] = profile.sha256
    p['state_directory'] = profile.mapped('/var/lib/develative-deploy/whatsapp/web-admin')
    for name in ('scripts/web_admin_broker.py', 'sally_whatsapp/__init__.py', 'deploy/images.lock.json'):
        write(project / name, b'approved source')
    p['sources'] = broker.source_files(project)
    generation = SimpleNamespace(epoch=p['owner']['epoch'], state='dedicated', path=p['owner']['generation'],
                                 manifest_sha256=p['owner']['manifest_sha256'])
    monkeypatch.setitem(sys.modules, 'installation_layout', SimpleNamespace(active=lambda: profile))
    monkeypatch.setitem(sys.modules, 'host_integration', SimpleNamespace(
        load_administration=lambda: SimpleNamespace(load_generation=lambda **kwargs: generation)))
    service = broker.Broker(policy[1])
    service.check_installation(p, p['approvals']['e' * 32])
    generation.epoch = 'd' * 32
    with pytest.raises(broker.Rejected, match='BROKER_OWNER_CHANGED'):
        service.check_installation(p, p['approvals']['e' * 32])
    generation.epoch = p['owner']['epoch']
    write(project / 'deploy/images.lock.json', b'altered image')
    with pytest.raises(broker.Rejected, match='BROKER_SOURCE_CHANGED'):
        service.check_installation(p, p['approvals']['e' * 32])


def test_failed_recovery_can_be_followed_by_same_attempt_recovery(policy):
    p, path = prepare_recovery(policy)
    first = make(policy, lambda *args: {}).handle(1234, envelope(identifier='2' * 32, approval='1' * 32, operation='instance.cancel'))
    assert first['result']['state'] == 'uncertain'
    p['approvals']['3' * 32] = deepcopy(p['approvals']['1' * 32])
    p['approvals']['3' * 32]['recovers'] = '1' * 32
    write(path, p)
    service = make(policy)
    result = service.handle(1234, envelope(identifier='4' * 32, approval='3' * 32, operation='instance.cancel'))
    assert result['result']['state'] == 'completed'
    assert service.handle(1234, envelope('status'))['result']['reconciled_by'] == '4' * 32
    assert service.handle(1234, envelope('status', identifier='2' * 32))['result']['reconciled_by'] == '4' * 32


def test_restore_recovery_requires_same_exact_plan(policy):
    p, path = policy
    p['principals'][0]['operations'] = ['backup.restore']
    a = p['approvals']['e' * 32]
    a.update(operation='backup.restore', parameters={'plan': {'path': '/approved/restore', 'sha256': 'a' * 64}})
    write(path, p)
    assert make(policy, lambda *args: {}).handle(1234, envelope(operation='backup.restore'))['result']['state'] == 'uncertain'
    p['approvals']['1' * 32] = deepcopy(a)
    p['approvals']['1' * 32]['recovers'] = 'e' * 32
    write(path, p)
    assert make(policy).handle(1234, envelope(identifier='2' * 32, approval='1' * 32,
                                             operation='backup.restore'))['result']['state'] == 'completed'


def test_capabilities_have_protocol_bounds_and_explicit_truncation(policy):
    p, path = policy
    original = p['approvals']['e' * 32]
    p['approvals'] = {f'{index:032x}': deepcopy(original) for index in range(129)}
    write(path, p)
    response = make(policy).handle(1234, envelope('capabilities'))
    assert response['ok']
    assert len(response['result']['actions']) == 128
    assert response['result']['actions_truncated'] is True
    assert len(broker.encoded(response)) < broker.MAX_FRAME


def test_protected_policy_hardlink_rejected(policy, tmp_path):
    other = tmp_path / 'other-policy'
    os.link(policy[1], other)
    assert_error(make(policy).handle(1234, envelope()), 'BROKER_INPUT_REJECTED')


def test_failed_cancel_can_recover_using_original_prepare_snapshot_only(policy):
    p, path = prepare_recovery(policy)
    result = make(policy, lambda *args: {}).handle(1234, envelope(identifier='2' * 32, approval='1' * 32, operation='instance.cancel'))
    assert result['result']['state'] == 'uncertain'
    p['approvals']['3' * 32] = deepcopy(p['approvals']['e' * 32])
    p['approvals']['3' * 32]['recovers'] = '1' * 32
    write(path, p)
    assert make(policy).handle(1234, envelope(identifier='4' * 32, approval='3' * 32,
                                             operation='instance.prepare'))['result']['state'] == 'completed'


def test_failed_cancel_does_not_authorize_different_prepare_setup(policy):
    p, path = prepare_recovery(policy)
    make(policy, lambda *args: {}).handle(1234, envelope(identifier='2' * 32, approval='1' * 32, operation='instance.cancel'))
    p['approvals']['3' * 32] = deepcopy(p['approvals']['e' * 32])
    p['approvals']['3' * 32]['parameters']['setup']['subject'] = 'different-owner'
    p['approvals']['3' * 32]['recovers'] = '1' * 32
    write(path, p)
    assert_before_intent(make(policy).handle(1234, envelope(identifier='4' * 32, approval='3' * 32, operation='instance.prepare')),
                         'BROKER_RECOVERY_MISMATCH')


@pytest.mark.skipif(not hasattr(os, 'pidfd_open'), reason='Linux process identity fencing')
def test_killed_broker_cannot_race_its_surviving_worker(policy):
    """Real SIGKILL, durable SQLite intent and inherited flock, synthetic child."""
    import multiprocessing
    import select
    import signal
    import subprocess
    context = multiprocessing.get_context('fork')
    receiver, sender = context.Pipe(duplex=False)
    def execute(p, a, fd):
        child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(30)'], pass_fds=(fd,))
        sender.send(child.pid)
        child.wait()
        return {'completed': True, 'operation': 'backup.create', 'target': 'alpha'}
    service = make(policy, execute)
    parent = context.Process(target=lambda: service.handle(1234, envelope()))
    parent.start()
    child_fd = None
    try:
        assert receiver.poll(5)
        child_pid = receiver.recv()
        child_fd = os.pidfd_open(child_pid)
        parent.kill()
        parent.join(5)
        assert not parent.is_alive()
        fresh = make(policy)
        assert fresh.handle(1234, envelope('status'))['result']['state'] == 'uncertain'
        assert_error(fresh.handle(1234, envelope(identifier='1' * 32)), 'BROKER_BUSY')
        signal.pidfd_send_signal(child_fd, signal.SIGKILL)
        poller = select.poll()
        poller.register(child_fd, select.POLLIN)
        assert poller.poll(5000)
        # Its approval remains consumed even after the worker stops.
        assert_error(fresh.handle(1234, envelope(identifier='1' * 32)), 'BROKER_APPROVAL_CONSUMED')
    finally:
        if parent.is_alive():
            parent.kill()
            parent.join(5)
        if child_fd is not None:
            try:
                signal.pidfd_send_signal(child_fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(child_fd)
        receiver.close()
        sender.close()


@pytest.fixture
def serving_policy(policy, tmp_path, monkeypatch):
    """Real serve/transport/worker, with only root admission and host effects synthetic."""
    value, path = policy
    endpoint = tmp_path / 'control.sock'
    logical_endpoint = value['socket']
    monkeypatch.setattr(broker, 'Path', lambda value: endpoint if str(value) == logical_endpoint else Path(value))
    class SyntheticRootAdmission:
        def __getattr__(self, name):
            return getattr(os, name)
        @staticmethod
        def geteuid():
            return 0
        @staticmethod
        def chown(path, uid, gid):
            assert Path(path) == endpoint and uid == 0 and gid == 123
    monkeypatch.setattr(broker, 'os', SyntheticRootAdmission())
    monkeypatch.setattr(broker.Broker, 'check_installation', lambda *args: None)
    value['principals'][0]['uid'] = os.getuid()
    value['approvals']['e' * 32]['uid'] = os.getuid()
    write(path, value)
    project = Path(value['project'])
    interpreter = project / '.venv/bin/python'
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(Path(sys.executable).resolve())
    write(project / '.venv/pyvenv.cfg', b'include-system-site-packages = false\n')
    actual_protected = broker.protected
    def protected(selected, **kwargs):
        if Path(selected) == Path(sys.executable).resolve():
            return Path(selected)
        return actual_protected(selected, **kwargs)
    monkeypatch.setattr(broker, 'protected', protected)
    probe = tmp_path / 'worker-observation.json'
    release = tmp_path / 'release-worker'
    source = f'''
import json, os, stat, tempfile, time
from pathlib import Path
mask = os.umask(0o077)
os.umask(mask)
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    (directory / 'payload').write_text('synthetic')
    observation = {{'umask': mask, 'mode': stat.S_IMODE(directory.stat().st_mode), 'wrote': True}}
Path({str(probe)!r}).write_text(json.dumps(observation))
deadline = time.monotonic() + 15
while not Path({str(release)!r}).exists():
    if time.monotonic() > deadline:
        raise RuntimeError('synthetic worker timed out')
    time.sleep(0.01)
print(json.dumps({{'completed': True, 'operation': 'backup.create', 'target': 'alpha'}}))
'''
    write(project / 'scripts/web_admin_broker.py', source.encode())
    return policy, endpoint, probe, release


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < deadline, 'synthetic process did not reach expected state'
        time.sleep(0.01)


def start_serving(path, caller_umask=0o117):
    import multiprocessing
    context = multiprocessing.get_context('fork')
    receive, send = context.Pipe(duplex=False)
    def serve():
        os.umask(caller_umask)
        original_serve = broker.Server.serve_until_stopped
        def observe_server_mask(server):
            mask = os.umask(caller_umask)
            assert mask == caller_umask
            original_serve(server)
        broker.Server.serve_until_stopped = observe_server_mask
        try:
            broker.main(['serve', '--policy', str(path)])
        finally:
            previous = os.umask(0o077)
            send.send(previous)
            send.close()
    process = context.Process(target=serve)
    process.start()
    send.close()
    return process, receive


def socket_response(endpoint, request):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(endpoint))
        client.sendall(broker.encoded(request))
        return broker.decode(client.recv(broker.MAX_FRAME))


@pytest.mark.parametrize('stop_signal,caller_umask', [(signal.SIGTERM, 0o022), (signal.SIGINT, 0o117)])
def test_main_serve_private_worker_drains_on_signal_and_restarts(serving_policy, stop_signal, caller_umask):
    policy, endpoint, probe, release = serving_policy
    process, receive = start_serving(policy[1], caller_umask)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        wait_for(endpoint.exists)
        assert stat.S_IMODE(endpoint.stat().st_mode) == 0o660
        client.connect(str(endpoint))
        client.sendall(broker.encoded(envelope()))
        wait_for(probe.exists)
        assert json.loads(probe.read_text()) == {'umask': 0o077, 'mode': 0o700, 'wrote': True}
        os.kill(process.pid, stop_signal)
        # The listener closes before the in-flight handler drains. The owned
        # pathname and execution lease remain until that worker has finished.
        def listener_closed():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as check:
                return check.connect_ex(str(endpoint)) != 0
        wait_for(listener_closed)
        assert process.is_alive() and endpoint.exists()
        assert_error(make(policy).handle(os.getuid(), envelope(identifier='1' * 32)), 'BROKER_BUSY')
        release.touch()
        assert broker.decode(client.recv(broker.MAX_FRAME))['result']['state'] == 'completed'
        process.join(5)
        assert process.exitcode == 0 and not endpoint.exists()
        assert receive.poll(1) and receive.recv() == caller_umask
    finally:
        release.touch()
        client.close()
        if process.is_alive():
            process.kill()
            process.join(5)
        receive.close()
    restarted, receive = start_serving(policy[1])
    try:
        wait_for(endpoint.exists)
        assert socket_response(endpoint, envelope('status'))['result']['state'] == 'completed'
        os.kill(restarted.pid, signal.SIGTERM)
        restarted.join(5)
        assert restarted.exitcode == 0 and not endpoint.exists()
    finally:
        if restarted.is_alive():
            restarted.kill()
            restarted.join(5)
        receive.close()


def test_direct_worker_resets_inherited_socket_umask(policy, tmp_path, monkeypatch):
    import tempfile
    value, path = policy
    monkeypatch.setattr(broker.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(broker.Broker, 'check_installation', lambda *args: None)
    def dispatch(*args):
        with tempfile.TemporaryDirectory(dir=tmp_path) as work:
            assert stat.S_IMODE(Path(work).stat().st_mode) == 0o700
            (Path(work) / 'payload').write_bytes(b'synthetic')
        return {'completed': True}
    monkeypatch.setattr(broker, 'dispatch', dispatch)
    previous = os.umask(0o117)
    try:
        broker.main(['worker', '--policy', str(path), '--policy-sha256', broker.digest(broker.encoded(value)),
                     '--approval', 'e' * 32])
    finally:
        os.umask(previous)


@pytest.mark.parametrize('kind', ['socket', 'file', 'symlink'])
def test_socket_cleanup_preserves_replacement_inode(tmp_path, kind):
    endpoint = tmp_path / 'control.sock'
    replacement = None
    with broker.Server(str(endpoint), broker.Handler):
        endpoint.unlink()
        if kind == 'socket':
            replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            replacement.bind(str(endpoint))
        elif kind == 'file':
            endpoint.write_bytes(b'foreign')
        else:
            endpoint.symlink_to(tmp_path / 'foreign')
        identity = endpoint.lstat()
    try:
        assert (endpoint.lstat().st_dev, endpoint.lstat().st_ino) == (identity.st_dev, identity.st_ino)
    finally:
        if replacement is not None:
            replacement.close()


def test_socket_cleanup_pins_parent_directory(tmp_path):
    parent = tmp_path / 'socket-directory'
    parent.mkdir()
    endpoint = parent / 'control.sock'
    moved = tmp_path / 'moved'
    with broker.Server(str(endpoint), broker.Handler):
        parent.rename(moved)
        parent.mkdir()
        endpoint.write_bytes(b'foreign')
    assert endpoint.read_bytes() == b'foreign'
    assert not (moved / 'control.sock').exists()


def test_socket_bind_failure_does_not_remove_existing_socket(tmp_path):
    endpoint = tmp_path / 'control.sock'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as existing:
        existing.bind(str(endpoint))
        identity = endpoint.stat()
        with pytest.raises(OSError):
            broker.Server(str(endpoint), broker.Handler)
        assert endpoint.stat().st_ino == identity.st_ino


def test_main_startup_failure_cleans_owned_socket_and_restores_umask(serving_policy, monkeypatch):
    policy, endpoint, _, _ = serving_policy
    def fail(*args):
        raise PermissionError('synthetic setup failure')
    monkeypatch.setattr(broker.os, 'chown', fail)
    previous = os.umask(0o027)
    try:
        with pytest.raises(PermissionError, match='synthetic setup failure'):
            broker.main(['serve', '--policy', str(policy[1])])
        actual = os.umask(0o027)
        assert actual == 0o027 and not endpoint.exists()
    finally:
        os.umask(previous)


def test_main_crash_keeps_socket_and_refuses_automatic_adoption(serving_policy):
    policy, endpoint, _, _ = serving_policy
    process, receive = start_serving(policy[1])
    try:
        wait_for(endpoint.exists)
        assert socket_response(endpoint, envelope('capabilities'))['ok']
        identity = endpoint.stat()
        process.kill()
        process.join(5)
        with pytest.raises(broker.Rejected, match='BROKER_SOCKET_EXISTS'):
            broker.main(['serve', '--policy', str(policy[1])])
        assert endpoint.stat().st_ino == identity.st_ino
    finally:
        if process.is_alive():
            process.kill()
            process.join(5)
        receive.close()


@pytest.mark.parametrize('kind', ['executable_pth', 'external_pth', 'external_directory',
                                 'writable_shadow', 'writable_namespace', 'external_namespace',
                                 'global_site', 'duplicate_config'])
def test_worker_import_closure_rejects_escape_before_process_start(serving_policy, monkeypatch, tmp_path, kind):
    policy, _, _, _ = serving_policy
    project = Path(policy[0]['project'])
    venv = project / '.venv'
    external = tmp_path / 'outside-imports'
    external.mkdir(mode=0o755)
    write(external / 'sitecustomize.py', b'raise RuntimeError("untrusted startup code")\n')
    (external / 'sitecustomize.py').chmod(0o666)
    if kind == 'executable_pth':
        write(venv / 'lib/custom.pth', b'import sys; sys.path.insert(0, "/outside")\n')
    elif kind == 'external_pth':
        write(venv / 'lib/custom.pth', (str(external) + '\n').encode())
    elif kind == 'external_directory':
        (venv / 'outside').symlink_to(external, target_is_directory=True)
    elif kind == 'writable_shadow':
        write(project / 'fractions.py', b'raise RuntimeError("untrusted import")\n')
        (project / 'fractions.py').chmod(0o666)
    elif kind == 'writable_namespace':
        write(project / 'private/plugin/module.py', b'raise RuntimeError("namespace injection")\n')
        (project / 'private/plugin/module.py').chmod(0o666)
    elif kind == 'external_namespace':
        (project / 'namespace').symlink_to(external, target_is_directory=True)
    elif kind == 'global_site':
        write(venv / 'pyvenv.cfg', b'include-system-site-packages = true\n')
    else:
        write(venv / 'pyvenv.cfg', b'include-system-site-packages = false\ninclude-system-site-packages = false\n')
    monkeypatch.setattr(broker.subprocess, 'run', lambda *args, **kwargs: pytest.fail('untrusted interpreter launched'))
    with pytest.raises(broker.Rejected, match='BROKER_(RUNTIME_UNTRUSTED|UNTRUSTED_PATH)'):
        broker.Broker(policy[1]).execute_child(policy[0], 'e' * 32, -1)


def test_worker_import_closure_accepts_internal_pth_and_directory_links(serving_policy):
    policy, _, _, _ = serving_policy
    project = Path(policy[0]['project'])
    venv = project / '.venv'
    write(venv / 'lib/site-packages/contained/sitecustomize.py', b'# reviewed synthetic hook\n')
    write(venv / 'lib/site-packages/internal.pth', b'# passive internal path\ncontained\n')
    (venv / 'lib64').symlink_to('lib', target_is_directory=True)
    assert broker.runtime_interpreter(project) == venv / 'bin/python'


def test_worker_import_closure_scans_release_virtual_environment_link(serving_policy, tmp_path):
    policy, _, _, _ = serving_policy
    project = Path(policy[0]['project'])
    venv = project / '.venv'
    release_venv = tmp_path / 'release-venv'
    venv.rename(release_venv)
    venv.symlink_to(release_venv, target_is_directory=True)
    assert broker.runtime_interpreter(project) == release_venv / 'bin/python'
    write(release_venv / 'lib/site-packages/sitecustomize.py', b'raise RuntimeError("untrusted release import")\n')
    (release_venv / 'lib/site-packages/sitecustomize.py').chmod(0o666)
    with pytest.raises(broker.Rejected, match='BROKER_UNTRUSTED_PATH'):
        broker.runtime_interpreter(project)

"""Offline allocation, recovery and isolation with real protected filesystem journals."""
from contextlib import contextmanager, nullcontext
import base64
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import instance_expansion as expansion

layout = expansion.layout_module()
ADDITION = {'later': {'account': 'messages-later', 'bridge': 22001, 'gateway': 22009}}


def write(host, logical, content, mode=0o644):
    target = host / str(logical).lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    target.chmod(mode)
    return target


def row(profile, slug):
    return {'spec': {'slug': slug, 'installation': profile.as_dict(),
                    'bridge_port': profile.instance_ports(slug)['bridge'], 'auth_mode': 'external-oidc'},
            'phase': 'ready', 'enabled': False}


def fixture_at(host):
    host.mkdir(mode=0o700, parents=True)
    profile = layout.Installation.from_dict(json.loads(
        (SCRIPTS.parent / 'deploy/installation.example.json').read_bytes()))
    for path in profile.as_dict()['paths'].values():
        (host / path.lstrip('/')).mkdir(parents=True, exist_ok=True)
    write(host, layout.IDENTITY, layout.identity_bytes(profile))
    write(host, layout.PROFILE, profile._encoded)
    registry = expansion.encoded({'format': 1, 'instances': {'personal': row(profile, 'personal')}})
    write(host, profile.path('project') + '/private/tenants.json', registry, 0o600)
    owner = {'protocol': 1, 'epoch': 'a' * 32, 'state': 'dedicated',
             'manifest_sha256': 'b' * 64,
             'generation': profile.mapped('/usr/local/lib/develative-deploy/whatsapp-generations/') + 'b' * 64}
    write(host, profile.mapped('/etc/develative-deploy/recovery-owners/whatsapp.json'), expansion.encoded(owner))
    source = (SCRIPTS / 'installation_layout.py').read_bytes()
    for logical in (
        owner['generation'] + '/installation_layout.py',
        profile.mapped('/usr/local/lib/develative-deploy/whatsapp-bootstrap/installation_layout.py'),
        profile.path('project') + '/scripts/installation_layout.py',
        profile.path('project') + '/sally_whatsapp/installation.py',
    ):
        write(host, logical, source)
    preserved = {}
    for name, path in profile.instance_paths('personal').items():
        target = write(host, path + '/synthetic-' + name, b'private original fixture ' + name.encode(), 0o600)
        preserved[target] = target.read_bytes()
    for logical in (layout.IDENTITY, layout.PROFILE, profile.path('project') + '/private/tenants.json'):
        target = host / str(logical).lstrip('/')
        preserved[target] = target.read_bytes()
    case = SimpleNamespace(host=host, profile=profile, owner=owner, registry=registry, preserved=preserved)
    case.operation = operation(case)
    return case


def operation(case, profile=None, additions=None, operation_id='c' * 32, registry=None):
    return expansion.decode(expansion.compile_operation(profile or case.profile,
        ADDITION if additions is None else additions,
        registry_bytes=case.registry if registry is None else registry,
        owner=case.owner, operation_id=operation_id, source_revision='d' * 40))


def advance(case, op=None, **kwargs):
    with expansion.filesystem_module().Root(case.host) as root:
        return expansion.advance(root, op or case.operation,
            admission=kwargs.pop('admission', lambda _: nullcontext()),
            resource_check=kwargs.pop('resource_check', lambda *_: None), **kwargs)


def selected(case):
    return layout.read_installation(root=case.host, trusted_uid=os.getuid())


@pytest.fixture
def allocated_case(tmp_path):
    return fixture_at(tmp_path / 'host')


def test_addition_changes_only_roster_and_journal_without_provisioning(allocated_case, monkeypatch):
    case = allocated_case
    result = advance(case)
    assert result['status'] == 'allocated'
    assert result['provisioned'] is result['live_enabled'] is False
    new = selected(case)
    assert new.sha256 == case.profile.sha256
    assert new.as_dict() == case.profile.as_dict()
    assert new.account('later') == 'messages-later'
    assert new.instance_ports('later') == {'bridge': 22001, 'gateway': 22009}
    assert new.account('personal') == case.profile.account('personal')
    assert new.mapped('/etc/whatsapp-later/config.toml') == '/etc/messages/later/config.toml'
    for path, raw in case.preserved.items():
        assert path.read_bytes() == raw
    assert all(not (case.host / path.lstrip('/')).exists() for path in new.instance_paths('later').values())
    from sally_whatsapp import tenancy
    monkeypatch.setattr(tenancy, 'active', lambda: new)
    instance = tenancy.Instance('later', 'Later', 'exact-later-subject', 22001,
        public_hostname='later.example.test', issuer='https://identity.example.test',
        jwks_url='https://identity.example.test/jwks', auth_mode='external-oidc',
        oauth_client_id='later-mcp', pairing_client_id='later-link', installation=new.as_dict())
    assert instance.service_user == 'messages-later'
    assert instance.config_dir == Path('/etc/messages/later')
    assert asdict(instance)['installation'] == case.profile.as_dict()
    assert advance(case) == result


@pytest.mark.parametrize('changes', [
    {'personal': ADDITION['later']},
    {'later': {'account': 'messages-owner', 'bridge': 22001, 'gateway': 22009}},
    {'later': {'account': 'root', 'bridge': 22001, 'gateway': 22009}},
    {'later': {'account': 'messages-later', 'bridge': 19001, 'gateway': 22009}},
    {'later': {'account': 'messages-later', 'bridge': 22001, 'gateway': 22001}},
    {'later': {'account': 'messages-later', 'bridge': True, 'gateway': 22009}},
    {'../escape': ADDITION['later']},
    {'administration': ADDITION['later']},
    {'backup': ADDITION['later']},
    {'later': {**ADDITION['later'], 'enabled': True}},
])
def test_collision_or_implicit_authority_rejected_before_any_write(allocated_case, changes):
    with pytest.raises(ValueError):
        operation(allocated_case, additions=changes)
    assert not (allocated_case.host / allocated_case.profile.roster_pointer().lstrip('/')).exists()


def test_second_expansion_and_inverse_keep_prior_allocation(allocated_case):
    case = allocated_case
    advance(case)
    first = selected(case)
    second_op = operation(case, first,
        {'third': {'account': 'messages-third', 'bridge': 23001, 'gateway': 23009}},
        operation_id='e' * 32)
    advance(case, second_op)
    second = selected(case)
    assert second.roster['revision'] == 2
    assert second.roster['previous'] == first.roster_sha256
    assert second.account('later') == first.account('later')
    with pytest.raises(ValueError, match='pointer changed'):
        advance(case, rollback=True)
    advance(case, second_op, rollback=True)
    assert selected(case).selection == first.selection
    assert advance(case, second_op, rollback=True)['status'] == 'rolled_back'
    with pytest.raises(ValueError, match='rolled back'):
        advance(case, second_op)
    advance(case, rollback=True)
    assert selected(case).selection == case.profile.selection
    assert (case.host / first.roster_snapshot(first.roster_sha256).lstrip('/')).is_file()
    for path, raw in case.preserved.items():
        assert path.read_bytes() == raw


@pytest.mark.parametrize('change', ['registry', 'artifact', 'account', 'reader'])
def test_drift_prevents_first_publication_or_unsafe_rollback(allocated_case, change):
    case = allocated_case
    if change != 'reader':
        advance(case)
    if change == 'registry':
        write(case.host, case.profile.path('project') + '/private/tenants.json', b'changed registry')
    elif change == 'artifact':
        write(case.host, case.profile.instance_paths('later')['configuration'] + '/config.toml', b'new state')
    elif change == 'reader':
        write(case.host, case.owner['generation'] + '/installation_layout.py', b'obsolete reader')
    def resource_check(*_):
        if change == 'account':
            raise ValueError('Allocated account is now in use')
    with pytest.raises(ValueError):
        advance(case, rollback=change != 'reader', resource_check=resource_check)
    assert (selected(case).roster is None) == (change == 'reader')


@pytest.mark.parametrize('artifact', ['writable-registry', 'unit-dropin', 'unit-enable-link'])
def test_unprotected_registry_or_leftover_unit_artifact_prevents_allocation(allocated_case, artifact):
    case = allocated_case
    if artifact == 'writable-registry':
        (case.host / case.profile.path('project').lstrip('/') / 'private/tenants.json').chmod(0o666)
    elif artifact == 'unit-dropin':
        write(case.host, '/etc/systemd/system/messages-later.service.d/override.conf', b'synthetic old override')
    else:
        link = case.host / 'etc/systemd/system/multi-user.target.wants/messages-later.service'
        link.parent.mkdir(parents=True)
        link.symlink_to('../messages-later.service')
    with pytest.raises(ValueError):
        advance(case)
    assert selected(case).roster is None


def test_same_snapshot_from_another_operation_cannot_claim_publication(allocated_case):
    case = allocated_case
    advance(case)
    other = operation(case, operation_id='f' * 32)
    with pytest.raises(ValueError, match='another operation'):
        advance(case, other)


def test_process_pins_roster_and_rejects_stale_selection(allocated_case, monkeypatch):
    case = allocated_case
    for field in ('_selected', '_locator_state', '_installed_context'):
        monkeypatch.setattr(layout, field, None)
    layout.activate_installation(root=case.host, trusted_uid=os.getuid())
    advance(case)
    with pytest.raises(ValueError, match='changed'):
        layout.active()


def test_pointer_change_between_reads_is_rejected(allocated_case, monkeypatch):
    case = allocated_case
    advance(case)
    original = layout._read_protected
    pointer = case.host / case.profile.roster_pointer().lstrip('/')
    count = 0
    def race(path, **kwargs):
        nonlocal count
        raw = original(path, **kwargs)
        if path == pointer:
            count += 1
            if count == 1:
                pointer.write_bytes(raw + b' ')
        return raw
    monkeypatch.setattr(layout, '_read_protected', race)
    with pytest.raises(ValueError, match='changed'):
        selected(case)


@pytest.mark.parametrize('damage', ['snapshot-bytes', 'snapshot-link', 'pointer-writable', 'foreign-identity'])
def test_protected_roster_rejects_untrusted_material(allocated_case, damage):
    case = allocated_case
    advance(case)
    profile = selected(case)
    pointer = case.host / profile.roster_pointer().lstrip('/')
    snapshot = case.host / profile.roster_snapshot(profile.roster_sha256).lstrip('/')
    if damage == 'snapshot-bytes':
        snapshot.write_bytes(snapshot.read_bytes() + b' ')
    elif damage == 'snapshot-link':
        other = snapshot.with_suffix('.other')
        snapshot.rename(other)
        snapshot.symlink_to(other)
    elif damage == 'pointer-writable':
        pointer.chmod(0o666)
    else:
        value = json.loads(pointer.read_bytes())
        value['installation_sha256'] = '0' * 64
        pointer.write_bytes(layout.encoded(value))
    with pytest.raises(ValueError):
        selected(case)


def test_preflight_checks_run_under_the_administrative_lease(allocated_case):
    held = False
    @contextmanager
    def admission(_):
        nonlocal held
        assert not held
        held = True
        try:
            yield
        finally:
            held = False
    checks = []
    def check(*_):
        assert held
        checks.append('under-lease')
    advance(allocated_case, admission=admission, resource_check=check)
    assert checks == ['under-lease'] and not held


def test_another_tenant_mutation_cannot_overlap_allocation(allocated_case):
    import host_integration
    case = allocated_case
    administration = SimpleNamespace(load_generation=lambda **_: object(),
        publication_lock=lambda **_: nullcontext(), trusted_path=lambda path, **_: Path(path),
        _trusted_uid=lambda uid: uid == os.getuid())
    project = case.host / case.profile.path('project').lstrip('/')
    admission = lambda _: host_integration.runtime_admission(project, administration=administration)
    def competing_operation(*_):
        with pytest.raises(RuntimeError, match='already in progress'):
            advance(case, admission=admission)
    advance(case, admission=admission, resource_check=competing_operation)


def test_schema_plan_pins_current_roster_and_rejects_stale_binding(allocated_case, monkeypatch):
    import host_integration
    import admin_handoff
    import runtime_lifecycle
    case = allocated_case
    advance(case)
    profile = selected(case)
    # The wrong digest fails before any generation file or administrative
    # inventory is read, even when all other synthetic fields are present.
    from sally_whatsapp import tenancy
    monkeypatch.setattr(tenancy, 'active', lambda: profile)
    instance = tenancy.Instance('later', 'Later', 'subject', 22001,
        public_hostname='later.example.test', issuer='https://identity.example.test',
        jwks_url='https://identity.example.test/jwks', auth_mode='external-oidc',
        oauth_client_id='later-mcp', pairing_client_id='later-link', installation=profile.as_dict())
    plan = dict(format=1, operation_id='a' * 32, instance={}, generation={}, qos=None,
                frontend={}, tools={}, allocation_sha256='0' * 64)
    with pytest.raises(ValueError, match='allocation changed'):
        host_integration.Integration(instance, plan, 'f' * 64)
    monkeypatch.setattr(admin_handoff, 'installation_profile', lambda: profile)
    administrative = dict(format=admin_handoff.FORMAT, id='a' * 32, mode='upgrade',
        inventory_digest='b' * 64, evidence_digests={}, owner={}, previous_owner={},
        owner_metadata={}, journal={}, control_directories={}, actions={}, allocation_sha256='0' * 64)
    with pytest.raises(ValueError, match='allocation changed'):
        admin_handoff.validate_plan(administrative, {}, expansion.filesystem_module())
    monkeypatch.setattr(runtime_lifecycle, 'installation_profile', lambda: profile)
    retirement = dict.fromkeys(('format', 'operation_id', 'source_sha256', 'admin_plan_sha256',
        'admin_profile_sha256', 'attestation', 'tenants', 'scope', 'generation_id',
        'before', 'after', 'qos_policy'), None)
    retirement['allocation_sha256'] = '0' * 64
    with pytest.raises(runtime_lifecycle.RuntimeError, match='allocation changed'):
        runtime_lifecycle.validate_plan(retirement)


def test_cold_cli_compilation_and_inspection_never_read_installed_identity(allocated_case, tmp_path):
    case = allocated_case
    inputs = dict(installation=case.profile.as_dict(), before_roster=None, additions=ADDITION,
        registry_base64=base64.b64encode(case.registry).decode(), owner=case.owner,
        id='c' * 32, source_revision='d' * 40)
    source = tmp_path / 'inputs.json'
    source.write_bytes(expansion.encoded(inputs))
    target = tmp_path / 'operation.json'
    driver = """import runpy,sys
def audit(event,args):
    if event=='open' and isinstance(args[0],str) and args[0].startswith('/etc/whatsapp-installation'):
        raise AssertionError('Offline expansion compiler read an installed identity')
sys.addaudithook(audit)
sys.argv=sys.argv[1:]
runpy.run_path(sys.argv[0],run_name='__main__')
"""
    cli = [sys.executable, '-I', '-B', '-c', driver, str(SCRIPTS / 'instance_expansion.py')]
    result = subprocess.run([*cli, 'compile', '--inputs', str(source), '--inputs-sha256',
        expansion.digest(source.read_bytes()), '--output', str(target)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['host_changed'] is False
    assert target.read_bytes() == expansion.encoded(case.operation)
    inspected = subprocess.run([*cli, 'inspect', '--operation', str(target),
        '--sha256', expansion.digest(target.read_bytes())], capture_output=True, text=True, timeout=20)
    assert inspected.returncode == 0, inspected.stderr
    result = json.loads(inspected.stdout)
    assert result['instances'] == ['later'] and result['host_changed'] is result['provisioned'] is False
    assert selected(case).roster is None


class Crash(Exception):
    pass


@pytest.mark.parametrize('rollback', [False, True])
def test_every_durable_fault_boundary_resumes_exact_operation(tmp_path, rollback):
    reference = fixture_at(tmp_path / 'reference')
    if rollback:
        advance(reference)
    events = []
    advance(reference, rollback=rollback, fault=lambda *event: events.append(event))
    assert len(events) >= 6
    for point in range(len(events)):
        case = fixture_at(tmp_path / ('crash-' + str(point)))
        if rollback:
            advance(case)
        seen = 0
        def interrupt(*event):
            nonlocal seen
            seen += 1
            if seen == point + 1:
                raise Crash()
        with pytest.raises(Crash):
            advance(case, rollback=rollback, fault=interrupt)
        result = advance(case, rollback=rollback)
        assert result['status'] == ('rolled_back' if rollback else 'allocated')
        assert selected(case).selection == (case.profile.selection if rollback else expansion.profiles(case.operation)[1].selection)
        for path, raw in case.preserved.items():
            assert path.read_bytes() == raw


def test_cancelling_unstarted_allocation_never_publishes_or_stages_it(allocated_case, monkeypatch):
    case = allocated_case
    before = selected(case).selection
    monkeypatch.setattr(expansion, '_stage', lambda *_: pytest.fail('cancel must not stage a new allocation'))
    monkeypatch.setattr(expansion, '_publish', lambda *_a, **_k: pytest.fail('cancel must not publish a new allocation'))
    result = advance(case, rollback=True)
    assert result['status'] == 'rolled_back'
    assert selected(case).selection == before
    assert advance(case, rollback=True) == result
    with pytest.raises(ValueError, match='rolled back'):
        advance(case)


def test_read_only_status_distinguishes_allocation_from_runtime_readiness(allocated_case):
    case = allocated_case
    def status():
        with expansion.filesystem_module().Root(case.host) as root:
            return expansion.operation_status(root, case.operation)
    before_files = sorted(str(path.relative_to(case.host)) for path in case.host.rglob('*'))
    assert status()['status'] == 'not_started'
    assert sorted(str(path.relative_to(case.host)) for path in case.host.rglob('*')) == before_files
    advance(case)
    report = status()
    assert report['status'] == 'allocated'
    assert report['runtime_verified'] is False
    assert report['instances'] == {'later': {'registered': False, 'phase': None}}
    assert report['steps']['publish'] == 'committed'
    advance(case, rollback=True)
    assert status()['status'] == 'rolled_back'


def test_partial_staging_can_be_cancelled_without_finishing_publication(allocated_case):
    case = allocated_case
    events = []
    def interrupt(*event):
        events.append(event)
        raise Crash()
    with pytest.raises(Crash):
        advance(case, fault=interrupt)
    assert selected(case).roster is None
    result = advance(case, rollback=True)
    assert result['status'] == 'rolled_back'
    assert selected(case).roster is None
    with expansion.filesystem_module().Root(case.host) as root:
        report = expansion.operation_status(root, case.operation)
    assert report['status'] == 'rolled_back'
    assert 'publish' not in report['steps']
    with pytest.raises(ValueError, match='rolled back'):
        advance(case)


def test_cancellation_every_durable_boundary_resumes_without_publication(tmp_path):
    reference = fixture_at(tmp_path / 'reference')
    events = []
    advance(reference, rollback=True, fault=lambda *event: events.append(event))
    assert events
    for point in range(len(events)):
        case = fixture_at(tmp_path / ('cancel-crash-' + str(point)))
        seen = 0
        def interrupt(*event):
            nonlocal seen
            seen += 1
            if seen == point + 1:
                raise Crash()
        with pytest.raises(Crash):
            advance(case, rollback=True, fault=interrupt)
        assert selected(case).roster is None
        assert advance(case, rollback=True)['status'] == 'rolled_back'
        with expansion.filesystem_module().Root(case.host) as root:
            report = expansion.operation_status(root, case.operation)
        assert report['status'] == 'rolled_back' and 'publish' not in report['steps']
        for path, raw in case.preserved.items():
            assert path.read_bytes() == raw


def test_cancelled_operation_cannot_be_rebound_to_different_additions(allocated_case):
    case = allocated_case
    advance(case, rollback=True)
    other = operation(case, additions={'another': {
        'account': 'messages-another', 'bridge': 23001, 'gateway': 23009}})
    with pytest.raises(ValueError, match='exact operation'):
        advance(case, other, rollback=True)
    with expansion.filesystem_module().Root(case.host) as root:
        with pytest.raises(ValueError, match='Saved operation differs'):
            expansion.operation_status(root, other)
    assert selected(case).roster is None


def test_cancelling_second_unstarted_expansion_preserves_first(allocated_case):
    case = allocated_case
    advance(case)
    first = selected(case)
    second = operation(case, first, {'third': {
        'account': 'messages-third', 'bridge': 23001, 'gateway': 23009}}, operation_id='e' * 32)
    advance(case, second, rollback=True)
    assert selected(case).selection == first.selection
    with expansion.filesystem_module().Root(case.host) as root:
        report = expansion.operation_status(root, second)
    assert report['status'] == 'rolled_back' and 'publish' not in report['steps']
    for path, raw in case.preserved.items():
        assert path.read_bytes() == raw


@pytest.mark.parametrize('partially_staged', [False, True])
def test_unpublished_cancellation_does_not_claim_unrelated_later_resources(allocated_case, partially_staged):
    case = allocated_case
    if partially_staged:
        with pytest.raises(Crash):
            advance(case, fault=lambda *_: (_ for _ in ()).throw(Crash()))
    path = expansion.profiles(case.operation)[1].instance_paths('later')['state'] + '/unrelated-state'
    unrelated = write(case.host, path, b'created by a different operation', 0o600)
    def occupied(*_):
        raise ValueError('Port/account belongs to a later unrelated consumer')
    assert advance(case, rollback=True, resource_check=occupied)['status'] == 'rolled_back'
    assert unrelated.read_bytes() == b'created by a different operation'
    assert selected(case).roster is None
    with pytest.raises(ValueError, match='rolled back'):
        advance(case)

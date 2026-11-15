"""Actual tracked prepare/SQLite flow, with all host effects replaced by fakes."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_provisioning_attempt import fixture, Interrupted, StopAt, ATTEMPT, PLAN


@pytest.fixture
def tracked(fixture, monkeypatch):
    root = fixture.tmp
    subuid, subgid = root / 'subuid', root / 'subgid'
    subuid.write_text('unrelated:100000:65536\n')
    subgid.write_text('unrelated:200000:65536\n')
    units = root / 'units'
    units.mkdir(mode=0o700)
    fixture.roots[-1] = units / (fixture.instance.base + '.service')
    original_path = fixture.module.Path
    mapping = {'/etc/subuid': subuid, '/etc/subgid': subgid, '/etc/systemd/system': units}
    monkeypatch.setattr(fixture.module, 'Path', lambda value: mapping.get(str(value), original_path(value)))
    # Identity services are synthetic, so do not chown files to their fictional UID.
    monkeypatch.setattr(fixture.module.os, 'chown', lambda *a, **k: None)
    from sally_whatsapp import state_initialization as initialization
    monkeypatch.setattr(initialization, '_administrative_directory',
                        lambda path: path.stat().st_uid == os.geteuid() and not path.stat().st_mode & 0o022)
    monkeypatch.setattr(initialization, 'os', SimpleNamespace(**{
        **{key: getattr(os, key) for key in dir(os) if not key.startswith('__')},
        'fchown': lambda *a, **k: None, 'chown': lambda *a, **k: None,
    }))
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts'))
    import tenant_admin
    host_calls, commands, secret_labels = [], [], {}
    monkeypatch.setattr(tenant_admin, 'grant_project_access', lambda instance: host_calls.append('project-acl'))
    monkeypatch.setattr(tenant_admin, 'grant_runtime_access', lambda instance: host_calls.append('runtime-acl'))
    fixture.host.begin_runtime = lambda: host_calls.append('begin')
    fixture.host.enroll_runtime = lambda account: host_calls.append(('enroll', account.pw_uid))
    fixture.host.ensure_https = lambda apache: host_calls.append(('https', PLAN))
    def run(args, **kwargs):
        args = [str(value) for value in args]
        commands.append(args)
        if args[0] == 'useradd':
            fixture.run(args)
        elif args[0] == 'usermod':
            assert args[1] in ('--add-subuids', '--add-subgids')
            path = subuid if args[1] == '--add-subuids' else subgid
            begin, end = map(int, args[2].split('-'))
            with path.open('a') as stream:
                stream.write(f'{args[-1]}:{begin}:{end - begin + 1}\n')
        elif args[0] == 'loginctl':
            assert args == ['loginctl', 'enable-linger', fixture.instance.service_user]
        elif args[0] == 'systemctl':
            assert args in (['systemctl', 'start', 'user@61001.service'], ['systemctl', 'daemon-reload'])
        elif args[1:4] == ['podman', 'secret', 'create']:
            assert args[4:6] == ['--label', 'wa.attempt=' + ATTEMPT]
            assert kwargs['input']  # Private input goes only to this synthetic adapter.
            assert args[-2] not in secret_labels
            secret_labels[args[-2]] = ATTEMPT
        else:
            assert args == [str(fixture.instance.wrapper), 'systemctl', '--user', 'daemon-reload']
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
    def command(args, **kwargs):
        args = [str(value) for value in args]
        assert args[:4] == [str(fixture.instance.wrapper), 'podman', 'secret', 'inspect']
        name = args[-1]
        if name not in secret_labels:
            return SimpleNamespace(returncode=1, stdout=b'', stderr=b'')
        body = [{'Spec': {'Labels': {'wa.attempt': secret_labels[name]}}}]
        return SimpleNamespace(returncode=0, stdout=json.dumps(body).encode(), stderr=b'')
    fields = {
        'database': str(fixture.instance.state_dir / 'archive.sqlite'),
        'public_url': 'https://later.example.test',
        'issuer': 'https://identity.example.test',
        'owner_subject': 'synthetic-owner',
        'webhook_secret_file': str(fixture.instance.config_dir / 'webhook.key'),
        'encryption_key_file': str(fixture.instance.config_dir / 'encryption.key'),
        'waha_key_file': str(fixture.instance.config_dir / 'waha.key'),
        'jwks_url': 'https://identity.example.test/jwks',
        'oauth_client_ids': ['synthetic-mcp'],
        'link_client_id': 'synthetic-pairing',
        'live_account_enabled': False,
        'link_enabled': False,
    }
    config = '[bridge]\n' + '\n'.join(name + ' = ' + json.dumps(value) for name, value in fields.items()) + '\n'
    artifacts = {'bridge': '[Service]\nExecStart=/bin/false\n',
                 'gateway': '[Container]\nImage=synthetic.invalid/unused\n',
                 'apache': '<VirtualHost *:443>\nServerName later.example.test\n</VirtualHost>\n'}
    def prepare(attempt):
        return fixture.module.prepare(fixture.instance, artifacts, config, fixture.host, attempt,
                                      run=run, command=command)
    fixture.prepare = prepare
    fixture.host_calls = host_calls
    fixture.commands = commands
    fixture.secret_labels = secret_labels
    fixture.subuid, fixture.subgid = subuid, subgid
    return fixture


def assert_real_state(tracked):
    from sally_whatsapp.config import Settings
    from sally_whatsapp.state_continuity import StateContinuity
    settings = Settings.load(tracked.instance.config_dir / 'config.toml')
    StateContinuity(settings, allow_bootstrap=False)
    assert not settings.live_account_enabled and not settings.link_enabled
    assert settings.database.is_file() and settings.state_identity_file.is_file()
    return settings


def test_tracked_prepare_completes_real_database_and_keeps_phone_disabled(tracked):
    with tracked.open() as attempt:
        result = tracked.prepare(attempt)
        assert result['state'] == 'prepared'
        before = (attempt.status(), list(tracked.commands), list(tracked.host_calls))
        assert tracked.prepare(attempt) == result
        assert before == (attempt.status(), tracked.commands, tracked.host_calls)
    assert_real_state(tracked)
    assert tracked.secret_labels == {'whatsapp-waha-api-key': ATTEMPT,
                                     'whatsapp-waha-disabled-ui-key': ATTEMPT}
    assert not any('whatsapp-waha.service' in call or tracked.instance.base + '.service' in call
                   for call in tracked.commands)


@pytest.mark.parametrize('phase', ['staged', 'published', 'recorded'])
@pytest.mark.parametrize('resource', ['database', 'marker', 'config'])
def test_tracked_prepare_recovers_each_database_marker_config_boundary(tracked, phase, resource):
    paths = {'database': tracked.instance.state_dir / 'archive.sqlite',
             'marker': tracked.instance.config_dir / 'technical-state.json',
             'config': tracked.instance.config_dir / 'config.toml'}
    with pytest.raises(Interrupted):
        with tracked.open(fault=StopAt(phase + ':' + str(paths[resource]))) as attempt:
            tracked.prepare(attempt)
    receipt_path = tracked.module.root_for(tracked.instance) / (ATTEMPT + '.json')
    receipt = tracked.module.read_private(receipt_path)
    seed = receipt['database_seed']
    database = Path(seed['database']).read_bytes()
    marker = Path(seed['marker']).read_bytes()
    with tracked.open() as attempt:
        assert tracked.prepare(attempt)['state'] == 'prepared'
        assert attempt.data['database_seed'] == seed
    settings = assert_real_state(tracked)
    assert settings.database.read_bytes() == database
    assert settings.state_identity_file.read_bytes() == marker
    assert len([call for call in tracked.commands if call[0] == 'useradd']) == 1


@pytest.mark.parametrize('resource', ['database', 'marker', 'config'])
def test_cancel_partial_initialization_before_acl_removes_only_attempt(tracked, resource):
    paths = {'database': tracked.instance.state_dir / 'archive.sqlite',
             'marker': tracked.instance.config_dir / 'technical-state.json',
             'config': tracked.instance.config_dir / 'config.toml'}
    unrelated = tracked.tmp / 'unrelated-runtime'
    unrelated.mkdir()
    (unrelated / 'database').write_bytes(b'old instance bytes')
    with pytest.raises(Interrupted):
        with tracked.open(fault=StopAt('published:' + str(paths[resource]))) as attempt:
            tracked.prepare(attempt)
    with tracked.open() as attempt:
        assert attempt.cancel(tracked.system)['state'] == 'cancelled'
    assert not tracked.instance.config_dir.exists()
    assert not tracked.instance.state_dir.exists()
    assert not tracked.instance.gateway_home.exists()
    assert tracked.accounts == {} and tracked.groups == {}
    assert tracked.subuid.read_text() == 'unrelated:100000:65536\n'
    assert tracked.subgid.read_text() == 'unrelated:200000:65536\n'
    assert (unrelated / 'database').read_bytes() == b'old instance bytes'
    assert tracked.host_calls == []


def test_lost_https_result_recovers_same_plan_and_preserves_database(tracked):
    with pytest.raises(Interrupted):
        with tracked.open(fault=StopAt('after:host-https')) as attempt:
            tracked.prepare(attempt)
    settings = assert_real_state(tracked)
    before = settings.database.read_bytes(), settings.state_identity_file.read_bytes()
    with tracked.open() as attempt:
        cancelled = attempt.cancel(tracked.system)
        assert cancelled['state'] == 'recovery_required'
        assert 'host-https' in cancelled['residuals']
        assert tracked.prepare(attempt)['state'] == 'prepared'
    assert (settings.database.read_bytes(), settings.state_identity_file.read_bytes()) == before
    assert [item for item in tracked.host_calls if isinstance(item, tuple) and item[0] == 'https'] == [
        ('https', PLAN), ('https', PLAN)]
    assert len([call for call in tracked.commands if call[0] == 'useradd']) == 1


def test_secret_from_another_attempt_blocks_and_is_not_replaced(tracked):
    tracked.secret_labels['whatsapp-waha-api-key'] = 'f' * 32
    with tracked.open() as attempt:
        with pytest.raises(ValueError, match='provenance'):
            tracked.prepare(attempt)
        assert attempt.status()['effects']['secret:whatsapp-waha-api-key'] == 'pending'
    assert tracked.secret_labels['whatsapp-waha-api-key'] == 'f' * 32
    assert not any(call[1:4] == ['podman', 'secret', 'create'] for call in tracked.commands)

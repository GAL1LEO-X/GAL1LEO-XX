"""Actual restore health contract, with synthetic HTTP and protected source trees."""
import copy
import http.client
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sally_whatsapp import __version__
from test_restore_runtime import host, lifecycle, restore, write


def ready(version=__version__):
    return {'process': 'running', 'version': version, 'restore_maintenance': True,
            'readiness': {'state': 'ready', 'ready': True, 'workers': {'portal': True}}}


@pytest.fixture
def health(host, monkeypatch):
    source = Path(__file__).parents[1] / 'sally_whatsapp'
    roots = (host.ctx.project / 'sally_whatsapp',
             host.ctx.project / '.venv/lib/python3.13/site-packages/sally_whatsapp')
    for root in roots:
        for name in {*restore.RESTORE_GATE_SOURCES, '__init__.py'}:
            write(root / name, (source / name).read_bytes())
    host.ctx.instance.bridge_port = 8123
    state = SimpleNamespace(roots=roots, requests=[], closed=0, opened=0, reads=[], now=0,
                            ports=[], allowed_ports={8123}, responses_by_port={},
                            responses=[(200, restore.encoded(ready()))])

    def sleep(delay):
        assert delay == .1
        # Simulate scheduling delay without wall-clock waits or global clock changes.
        state.now += 1
    monkeypatch.setattr(restore, 'time', SimpleNamespace(monotonic=lambda: state.now, sleep=sleep))

    class Connection:
        def __init__(self, hostname, port, timeout):
            assert hostname == '127.0.0.1' and port in state.allowed_ports and timeout == 2
            self.port = port
            state.ports.append(port)
            state.opened += 1
        def request(self, method, path):
            assert (method, path) == ('GET', '/healthz')
            state.requests.append((method, path))
        def getresponse(self):
            responses = state.responses_by_port.get(self.port, state.responses)
            response = responses.pop(0) if len(responses) > 1 else responses[0]
            if isinstance(response, Exception):
                raise response
            status, body = response
            def read(limit):
                state.reads.append(limit)
                return body[:limit]
            return SimpleNamespace(status=status, read=read)
        def close(self):
            state.closed += 1
    monkeypatch.setattr(restore.http.client, 'HTTPConnection', Connection)
    return state


@pytest.mark.parametrize('status', [200, 503])
def test_current_installed_maintenance_version_is_accepted(host, health, status):
    health.responses[:] = [(status, restore.encoded(ready()))]
    restore.maintenance_health(host.ctx)
    assert health.opened == health.closed == 1 and health.reads == [65537]


def test_previous_hardcoded_version_is_not_accepted(host, health):
    health.responses[:] = [(200, restore.encoded(ready('0.8.4')))]
    with pytest.raises(ValueError, match='Bridge maintenance startup is not verified'):
        restore.maintenance_health(host.ctx)
    assert health.opened == health.closed == 16


def test_nonobject_health_can_recover_within_existing_observation_budget(host, health):
    health.responses[:] = [(200, b'[]'), (200, restore.encoded(ready()))]
    restore.maintenance_health(host.ctx)
    assert health.opened == health.closed == 2


@pytest.mark.parametrize('body', [b'null', b'[]', b'42', b'"private-provider-text"',
    b'{"restore_maintenance":true,"readiness":[]}',
    b'{"restore_maintenance":true,"readiness":null}', b'{invalid',
    b'{"restore_maintenance":true,"restore_maintenance":false}',
    b'[' * 10000 + b'0' + b']' * 10000, b'x' * 65537])
def test_invalid_health_is_bounded_content_free_and_never_success(host, health, body):
    health.responses[:] = [(200, body)]
    with pytest.raises(ValueError, match='^Bridge maintenance startup is not verified$'):
        restore.maintenance_health(host.ctx)
    assert health.opened == health.closed == 16
    assert set(health.reads) == {65537}


@pytest.mark.parametrize('change', ['normal', 'not-ready', 'false-ready-type', 'false-marker-type',
                                    'missing-version', 'wrong-version', 'redirect', 'server-error'])
def test_unconfirmed_health_never_completes_restore(host, health, change):
    value = ready()
    status = 200
    if change == 'normal': value.pop('restore_maintenance')
    elif change == 'not-ready': value['readiness']['ready'] = False
    elif change == 'false-ready-type': value['readiness']['ready'] = 1
    elif change == 'false-marker-type': value['restore_maintenance'] = 1
    elif change == 'missing-version': value.pop('version')
    elif change == 'wrong-version': value['version'] = '9.99.999'
    elif change == 'redirect': status = 302
    else: status = 500
    health.responses[:] = [(status, restore.encoded(value))]
    with pytest.raises(ValueError, match='Bridge maintenance startup is not verified'):
        restore.maintenance_health(host.ctx)
    assert health.opened == health.closed == 16


@pytest.mark.parametrize('error', [TimeoutError('private-address'), ConnectionRefusedError('private-address'),
                                  http.client.BadStatusLine('private-provider-text')])
def test_transient_health_read_failure_only_reobserves_health(host, health, error):
    health.responses[:] = [error, (200, restore.encoded(ready()))]
    restore.maintenance_health(host.ctx)
    assert health.opened == health.closed == 2
    assert health.requests == [('GET', '/healthz')] * 2


@pytest.mark.parametrize('root_index', [0, 1])
@pytest.mark.parametrize('damage', ['old-version', 'writable', 'code', 'backend'])
def test_source_drift_refused_before_health_request(host, health, root_index, damage):
    root = health.roots[root_index]
    if damage == 'writable': (root / '__init__.py').chmod(0o666)
    elif damage == 'old-version': write(root / '__init__.py', '__version__ = "0.8.4"\n')
    elif damage == 'code': write(root / '__init__.py', 'raise AssertionError("must not execute")\n')
    else: write(root / 'server.py', 'raise AssertionError("must not execute")\n')
    with pytest.raises(ValueError, match='reviewed restoration fence|not protected'):
        restore.maintenance_health(host.ctx)
    assert health.opened == 0


def test_health_follows_explicitly_reviewed_new_version_without_a_fixed_literal(host, health, monkeypatch):
    raw = b'__version__ = "0.9.1"\n'
    pins = {**restore.RESTORE_GATE_SOURCES, '__init__.py': restore.sha(raw)}
    monkeypatch.setattr(restore, 'RESTORE_GATE_SOURCES', pins)
    for root in health.roots:
        write(root / '__init__.py', raw)
    health.responses[:] = [(200, restore.encoded(ready('0.9.1')))]
    restore.maintenance_health(host.ctx)
    assert health.opened == health.closed == 1


@pytest.mark.parametrize('raw', [b'__version__ = make_version()\n', b'__version__ = 123\n',
    b'__version__ = "bad"\n', b'__version__ = "0.8.10"\n__version__ = "0.8.4"\n'])
def test_reviewed_version_metadata_must_be_one_literal(host, health, monkeypatch, raw):
    monkeypatch.setattr(restore, 'RESTORE_GATE_SOURCES',
                        {**restore.RESTORE_GATE_SOURCES, '__init__.py': restore.sha(raw)})
    for root in health.roots:
        write(root / '__init__.py', raw)
    with pytest.raises(ValueError, match='version'):
        restore.maintenance_health(host.ctx)
    assert health.opened == 0


def test_real_restore_health_failure_preserves_data_and_resume_does_not_restart(host, health, monkeypatch):
    actual_health = restore.maintenance_health
    values, calls = lifecycle(host, monkeypatch, restart='maintenance')
    monkeypatch.setattr(restore, 'maintenance_health', actual_health)
    health.responses[:] = [(200, restore.encoded(ready('0.8.4')))]
    with pytest.raises(ValueError, match='Bridge maintenance startup is not verified'):
        restore.apply(host.plan, administration=host.admin)
    directory = host.ctx.state / host.plan['id']
    journal = json.loads((directory / 'journal.json').read_text())
    assert journal['phase'] == 'data_restored' and journal['restart_intent'] is True
    assert values['gateway']['ActiveState'] == 'inactive'
    before = {key: restore.inventory(directory / 'old' / key) for key in restore.targets(host.ctx)}
    current = restore.current_digest(host.ctx)
    health.responses[:] = [(200, restore.encoded(ready()))]
    result = restore.apply(host.plan, administration=host.admin)
    assert result['state'] == 'completed' and result['maintenance_active'] is True
    assert result['gateway_started'] is False and calls.count(('start', 'bridge')) == 1
    assert ('start', 'gateway') not in calls
    assert restore.current_digest(host.ctx) == current
    assert {key: restore.inventory(directory / 'old' / key) for key in restore.targets(host.ctx)} == before
    fence = json.loads((host.ctx.instance.config_dir / 'restore-maintenance.json').read_text())
    assert fence['phase'] == 'maintenance' and fence['instance'] == host.ctx.instance.slug


def test_health_is_scoped_to_the_selected_instance(host, health):
    other = copy.copy(host.ctx)
    other.instance = copy.copy(host.ctx.instance)
    other.instance.bridge_port = 8999
    other.instance.slug = 'other'
    # The ready peer cannot satisfy a selected instance still outside maintenance.
    selected = ready()
    selected['restore_maintenance'] = False
    health.allowed_ports.add(other.instance.bridge_port)
    health.responses_by_port = {8123: [(200, restore.encoded(ready()))],
                               8999: [(200, restore.encoded(selected))]}
    restore.maintenance_health(host.ctx)
    with pytest.raises(ValueError, match='Bridge maintenance startup is not verified'):
        restore.maintenance_health(other)
    assert health.opened == health.closed == 17
    assert health.ports == [8123] + [8999] * 16


@pytest.mark.parametrize('root_index', [0, 1])
def test_changed_version_refuses_before_marker_stops_or_data_swaps(host, health, monkeypatch, root_index):
    _, calls = lifecycle(host, monkeypatch, restart='maintenance')
    monkeypatch.setattr(restore, 'verify_start_context', lambda ctx, *args: restore.verify_gate_sources(ctx))
    write(health.roots[root_index] / '__init__.py', '__version__ = "0.8.4"\n')
    before = restore.current_digest(host.ctx)
    with pytest.raises(ValueError, match='reviewed restoration fence'):
        restore.apply(host.plan, administration=host.admin)
    assert restore.current_digest(host.ctx) == before
    assert not (host.ctx.instance.config_dir / 'restore-maintenance.json').exists()
    assert not any(action in ('stop', 'start', 'mask') for action, component in calls)


@pytest.mark.parametrize('deployment_entrypoint', [False, True])
def test_restore_accepts_actual_asgi_maintenance_health_without_reopening_data_workers(
        host, health, environment, monkeypatch, deployment_entrypoint, tmp_path):
    import asyncio
    import time
    from starlette.testclient import TestClient
    from sally_whatsapp.server import create_app
    from test_restore_maintenance import configuration, marker_body

    settings, receiver, gateway, _ = environment
    settings = configuration(settings)
    (settings.encryption_key_file.parent / 'restore-maintenance.json').write_text(marker_body())
    event = asyncio.Event() if deployment_entrypoint else None
    gate = tmp_path / 'deployment-gate'
    app = create_app(settings, gateway=gateway, event_transport=receiver,
                     activation_event=event, maintenance_gate=gate if deployment_entrypoint else None)
    served = app
    if deployment_entrypoint:
        from deploy_runtime import ReleaseAdmission
        served = ReleaseAdmission(app, event, gate, 'a' * 40)
    actual_health = restore.maintenance_health
    values, calls = lifecycle(host, monkeypatch, restart='maintenance')
    monkeypatch.setattr(restore, 'maintenance_health', actual_health)
    with TestClient(served, base_url=settings.public_url) as client:
        deadline = time.monotonic() + 5
        while not app.state.readiness.ready and time.monotonic() < deadline:
            time.sleep(.01)
        response = client.get('/healthz')
        if deployment_entrypoint:
            assert response.headers['x-whatsapp-release-commit'] == 'a' * 40
        assert response.json()['readiness']['workers'] == {'portal': True}
        health.responses[:] = [(response.status_code, response.content)]
        result = restore.apply(host.plan, administration=host.admin)
        assert result['state'] == 'completed' and result['maintenance_active'] is True
        assert client.post('/mcp', json={}).status_code == 503
        assert not app.state.service.settings.live_account_enabled
    assert values['gateway']['ActiveState'] == 'inactive'
    assert calls.count(('start', 'bridge')) == 1 and ('start', 'gateway') not in calls
    assert not gateway.sent and not receiver.requests

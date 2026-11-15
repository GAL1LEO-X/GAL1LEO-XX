"""Probe compatibility uses the real app/lifespan, replacing only health output."""
import json
import sqlite3
from pathlib import Path
import subprocess
import sys

import pytest
from starlette.responses import JSONResponse
from starlette.routing import Route

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_probe


def test_cold_offline_probe_requires_no_installed_identity(tmp_path):
    """Real SQLite/app/lifespan; filesystem isolation is an audited temp tree."""
    plugin = Path(__file__).resolve().parents[1]
    driver = '''import runpy,sys
from pathlib import Path
def audit(event,args):
    if event=='open' and isinstance(args[0],str) and args[0].startswith((
        '/etc/whatsapp-installation','/etc/box-installation',
        '/srv/openai-codex','/var/lib/sally-browser')):
        raise AssertionError('Offline probe consulted an installed or legacy identity')
sys.addaudithook(audit)
plugin=Path(sys.argv[1]);root=Path(sys.argv[2])
sys.path[:0]=[str(plugin/'scripts'),str(plugin)]
from sally_whatsapp.store import Store
databases=[root/'alpha.sqlite',root/'bravo.sqlite']
for path in databases:Store(path,recover_inflight=False)
sys.argv=[str(plugin/'scripts/release_probe.py'),*map(str,databases)]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', driver, str(plugin), str(tmp_path)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt['passed'] is True and receipt['offlineDatabases'] == 2
    assert receipt['workersGated'] is True and receipt['maintenanceGate'] is True
    assert {path.name for path in tmp_path.glob('*.sqlite')} == {'alpha.sqlite', 'bravo.sqlite'}


def health_output(monkeypatch, transform):
    create_app = release_probe.create_app

    def create(*args, **kwargs):
        app = create_app(*args, **kwargs)
        for index, route in enumerate(app.routes):
            if getattr(route, 'path', None) != '/healthz':
                continue
            original = route.endpoint

            async def health(request):
                response = await original(request)
                payload = json.loads(response.body)
                transform(payload)
                return JSONResponse(payload, status_code=response.status_code)

            app.routes[index] = Route('/healthz', health, methods=['GET'])
            break
        else:
            raise AssertionError('Real health route not found')
        return app

    monkeypatch.setattr(release_probe, 'create_app', create)


@pytest.mark.parametrize('legacy', [False, True])
def test_probe_accepts_current_and_absent_legacy_contract(monkeypatch, capsys, legacy):
    monkeypatch.setattr(sys, 'argv', ['release_probe'])
    if legacy:
        health_output(monkeypatch, lambda payload: payload.pop('readiness'))
    release_probe.main()
    result = json.loads(capsys.readouterr().out)
    assert result == {'passed': True, 'offlineDatabases': 0, 'maintenanceGate': True,
                      'workersGated': True, 'readinessContract': not legacy}


def test_probe_explicitly_prepares_only_its_disposable_fixture(monkeypatch, capsys):
    create_app = release_probe.create_app
    observed = []

    def create(settings, **kwargs):
        assert kwargs['recover_inflight'] is False
        assert settings.database.is_file()
        assert settings.live_account_enabled is False
        with sqlite3.connect(settings.database) as db:
            assert db.execute("SELECT 1 FROM sqlite_master WHERE name='state'").fetchone()
        observed.append(settings.database)
        return create_app(settings, **kwargs)

    monkeypatch.setattr(release_probe, 'create_app', create)
    monkeypatch.setattr(sys, 'argv', ['release_probe'])
    release_probe.main()
    assert len(observed) == 1 and not observed[0].exists()
    assert json.loads(capsys.readouterr().out)['passed'] is True


@pytest.mark.parametrize('invalid', [None, {}, {'state': 'waiting', 'ready': False,
                                              'workers': {}}])
def test_probe_rejects_present_invalid_contract(monkeypatch, invalid):
    monkeypatch.setattr(sys, 'argv', ['release_probe'])
    health_output(monkeypatch, lambda payload: payload.update(readiness=invalid))
    with pytest.raises(AssertionError):
        release_probe.main()


@pytest.mark.parametrize('change', ['missing', 'worker_integer', 'unexpected_contract'])
def test_probe_rejects_contract_changes_after_activation(monkeypatch, change):
    monkeypatch.setattr(sys, 'argv', ['release_probe'])

    def transform(payload):
        active = payload['readiness']['state'] == 'ready'
        if change == 'missing' and active:
            payload.pop('readiness')
        elif change == 'worker_integer' and active:
            payload['readiness']['workers']['events'] = 1
        elif change == 'unexpected_contract' and not active:
            payload.pop('readiness')

    health_output(monkeypatch, transform)
    with pytest.raises(AssertionError):
        release_probe.main()

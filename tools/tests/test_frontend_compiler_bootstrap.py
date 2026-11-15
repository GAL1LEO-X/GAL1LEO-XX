"""Cold source admission in synthetic trees; no host inspection or services."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

import test_fresh_frontend_profile as fixture


@pytest.mark.parametrize('relative,argument', [
    ('host/frontend/fresh_profile.py', '--input-template'),
    ('host/frontend/existing_profile.py', '--help'),
])
def test_cold_cli_does_not_import_unadmitted_siblings(tmp_path, relative, argument):
    source = tmp_path / relative
    source.parent.mkdir(parents=True)
    source.write_bytes((fixture.REPOSITORY / relative).read_bytes())
    marker = tmp_path / 'sibling-executed'
    # A sibling that would be observable if an ordinary import preceded the
    # source-manifest check. No application or operational input is loaded.
    hostile = ('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\n')
    (tmp_path / 'host/__init__.py').write_text('')
    (tmp_path / 'host/installation.py').write_text(hostile)
    (tmp_path / 'host/frontend/provider.py').write_text(hostile)
    completed = subprocess.run([sys.executable, '-I', '-B', str(source), argument],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=10)
    assert completed.returncode == 0, completed.stderr.decode()
    assert not marker.exists()
    if argument == '--help':
        assert b'--source-manifest' in completed.stdout and b'--source-sha256' in completed.stdout
    else:
        assert json.loads(completed.stdout)['format'] == 1


@pytest.mark.parametrize('kind', ['fresh', 'existing'])
def test_bootstrap_rejects_changed_sibling_before_compilation(tmp_path, monkeypatch, kind):
    relative = 'host/frontend/' + ('fresh_profile.py' if kind == 'fresh' else 'existing_profile.py')
    compiler = fixture.load('bootstrap_' + kind + '_test', relative)
    metadata = fixture.builder.build(fixture.REPOSITORY, tmp_path / 'bundle',
        source_revision='a' * 40, profile='general')
    bundle = tmp_path / 'bundle'
    entry = 'frontend_fresh' if kind == 'fresh' else 'frontend_profile'
    manifest = bundle / Path(metadata['bootstrap'][entry]['path']).name
    marker = tmp_path / 'unadmitted-code-ran'
    target = bundle / ('host/installation.py' if kind == 'fresh' else 'host/frontend/provider.py')
    target.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("bad")\n')
    scope = compiler.bootstrap.__globals__
    monkeypatch.setitem(scope, '__file__', str(bundle / relative))
    # Only physical trust metadata is a fixture seam. Real source capture,
    # manifest comparison and compiler code execute against the bundle bytes.
    def read(selected):
        path = Path(selected)
        assert path.is_relative_to(bundle)
        return path.read_bytes()
    monkeypatch.setitem(scope, 'protected_bytes', read)
    with pytest.raises(ValueError, match='source drift'):
        compiler.bootstrap(manifest, metadata['bootstrap'][entry]['sha256'])
    assert not marker.exists()


@pytest.mark.parametrize('kind', ['fresh', 'existing'])
def test_bootstrap_uses_captured_modules_without_importing_host(tmp_path, monkeypatch, kind):
    relative = 'host/frontend/' + ('fresh_profile.py' if kind == 'fresh' else 'existing_profile.py')
    compiler = fixture.load('captured_' + kind + '_test', relative)
    bundle = tmp_path / 'bundle'
    metadata = fixture.builder.build(fixture.REPOSITORY, bundle,
        source_revision='a' * 40, profile='general')
    entry = 'frontend_fresh' if kind == 'fresh' else 'frontend_profile'
    manifest = bundle / Path(metadata['bootstrap'][entry]['path']).name
    scope = compiler.bootstrap.__globals__
    monkeypatch.setitem(scope, '__file__', str(bundle / relative))
    reads = []
    def read(selected):
        path = Path(selected)
        assert path.is_relative_to(bundle)
        reads.append(path.relative_to(bundle).as_posix())
        return path.read_bytes()
    monkeypatch.setitem(scope, 'protected_bytes', read)
    import builtins
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name == 'host' or name.startswith('host.'):
            raise AssertionError('Uncaptured host import: ' + name)
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    modules, generation = compiler.bootstrap(manifest, metadata['bootstrap'][entry]['sha256'])
    assert modules['adapter'].provider is modules['provider']
    assert generation == {'path': str(bundle), 'sha256': metadata['generation']}
    assert all(reads.count(name) == 1 for name in compiler.SOURCES)
    if kind == 'fresh':
        assert modules['installation'].Installation.legacy().compatibility

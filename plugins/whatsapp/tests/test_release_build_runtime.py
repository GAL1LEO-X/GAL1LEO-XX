"""Build-only tooling never becomes part of the admitted runtime environment."""
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import github_release as release


@pytest.fixture
def build(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    project = source / 'pyproject.toml'
    project.write_text('[build-system]\nrequires = ["setuptools==84.0.0"]\n'
                       'build-backend = "setuptools.build_meta"\n'
                       '[project]\nname = "synthetic-runtime"\nversion = "1.0"\n'
                       'dependencies = ["example-runtime>=1"]\n')
    lock = source / 'requirements.lock'
    lock.write_text('# Runtime contract\nexample-runtime==1.0\n'
                    'windows-runtime==2.0 ; sys_platform == "win32"\n')
    candidate = tmp_path / 'candidate'
    operations = []
    monkeypatch.setattr(release, 'migration_contract', lambda path: None)
    def create(product, path, files):
        operations.append(('create', product, path, files))
        return candidate
    def sandbox(path, command, **kwargs):
        operations.append(('run', path, command, kwargs))
        return ''
    monkeypatch.setattr(release, 'create_build', create)
    monkeypatch.setattr(release, 'sandbox', sandbox)
    return source, candidate, operations


def test_release_removes_only_build_tool_after_package_install_before_dependency_check(build):
    source, candidate, operations = build
    original = (source / 'requirements.lock').read_bytes()
    assert release.build_backend(source) == candidate
    commands = [item[2] for item in operations if item[0] == 'run']
    assert len(commands) == 5
    dependency_install, package_install, removal, check = commands[1:]
    assert dependency_install[-2:] == [str(candidate / 'requirements.lock'), 'setuptools==84.0.0']
    assert package_install[-2:] == ['--no-build-isolation', str(candidate)]
    assert removal[-3:] == ['uninstall', '--yes', 'setuptools']
    assert check[-1] == 'check'
    assert all(command[0] == str(candidate / '.venv/bin/python') for command in commands[1:])
    assert (source / 'requirements.lock').read_bytes() == original
    # Removal has neither network access nor arbitrary runtime-package arguments.
    assert operations[-2][3] == {'timeout': 90}


@pytest.mark.parametrize('declaration', [
    'setuptools==84.0.0',
    'SetUpTools[core]==84.0.0',
    'setuptools==84.0.0 ; sys_platform == "win32"',
])
def test_build_tool_in_runtime_lock_refuses_before_creating_candidate(build, declaration):
    source, _, operations = build
    with (source / 'requirements.lock').open('a') as stream:
        stream.write(declaration + '\n')
    with pytest.raises(release.ReleaseError, match='also be declared runtime dependencies'):
        release.build_backend(source)
    assert operations == []


@pytest.mark.parametrize('declaration', ['setuptools>=84', 'Setuptools[core]==84.0.0'])
def test_build_tool_in_project_runtime_metadata_refuses_before_creating_candidate(build, declaration):
    source, _, operations = build
    project = source / 'pyproject.toml'
    project.write_text(project.read_text().replace('example-runtime>=1', declaration))
    with pytest.raises(release.ReleaseError, match='also be declared runtime dependencies'):
        release.build_backend(source)
    assert operations == []


@pytest.mark.parametrize('requires', ['["wheel==0.45.1"]', '["setuptools==84.0.0", "wheel==0.45.1"]', '[]'])
def test_unreviewed_build_tool_is_not_generically_uninstalled(build, requires):
    source, _, operations = build
    project = source / 'pyproject.toml'
    project.write_text(project.read_text().replace('["setuptools==84.0.0"]', requires))
    with pytest.raises(release.ReleaseError, match='Only the reviewed setuptools build tool'):
        release.build_backend(source)
    assert operations == []


@pytest.mark.parametrize('failure', ['package-install', 'build-tool-removal', 'dependency-check'])
def test_build_failure_never_returns_an_admitted_candidate(build, monkeypatch, failure):
    source, _, operations = build
    def sandbox(path, command, **kwargs):
        operations.append(command)
        if (failure == 'package-install' and '--no-build-isolation' in command
                or failure == 'build-tool-removal' and 'uninstall' in command
                or failure == 'dependency-check' and command[-1] == 'check'):
            raise subprocess.CalledProcessError(1, command)
        return ''
    monkeypatch.setattr(release, 'sandbox', sandbox)
    with pytest.raises(subprocess.CalledProcessError):
        release.build_backend(source)
    commands = [command for command in operations if isinstance(command, list)]
    if failure == 'package-install':
        assert not any('uninstall' in command for command in commands)
    if failure != 'dependency-check':
        assert not any(command[-1] == 'check' for command in commands)

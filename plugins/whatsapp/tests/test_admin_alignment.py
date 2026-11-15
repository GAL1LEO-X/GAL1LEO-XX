"""Real scoped filesystem updates, retained preimages and interrupted publication."""
import copy
from pathlib import Path
from types import SimpleNamespace
import sys
import os

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import admin_alignment as alignment
from host.lifecycle import filesystem


@pytest.fixture
def aligned_host(tmp_path):
    base = tmp_path / 'host'; base.mkdir()
    for path in ('srv/wa/app/private', 'var/lib/admin/whatsapp', 'var/lib/develative-host-lifecycle',
                 'srv/wa/releases/old/venv', 'srv/wa/releases/current/venv'):
        (base / path).mkdir(parents=True, exist_ok=True, mode=0o700)
    project = base / 'srv/wa/app'
    (project / '.venv').symlink_to('/srv/wa/releases/old/venv')
    (project / 'README.md').write_bytes(b'old public source\n')
    (project / 'private/tenants.json').write_bytes(b'{"fixture":"preserve untouched"}')
    (project / 'unmanaged.txt').write_bytes(b'preserve unknown original')
    profile = SimpleNamespace(sha256='a' * 64, path=lambda k: {'project': '/srv/wa/app',
                              'administration_state': '/var/lib/admin'}[k])
    runtime = SimpleNamespace(check_current=lambda: None, binding={'synthetic': 'pinned'},
                              venv=Path('/srv/wa/releases/current/venv'))
    source = Path(__file__).parents[1]
    with filesystem.Root(base) as root:
        plan = alignment.prepare(root, source, profile, runtime, commit='b' * 40,
                                 operation_id='c' * 32, owner={'synthetic': 'dedicated'})
    return SimpleNamespace(base=base, project=project, profile=profile, runtime=runtime, source=source, plan=plan)


def apply(host, *, fault=None):
    with filesystem.Root(host.base) as root:
        return alignment.apply(root, host.source, host.profile, host.runtime, host.plan,
                               expected_sha256=alignment.sha(alignment.encoded(host.plan)),
                               owner={'synthetic': 'dedicated'}, fault=fault)


def test_alignment_updates_complete_public_closure_and_retains_originals(aligned_host):
    h = aligned_host
    result = apply(h)
    assert result['phase'] == 'completed' and result['services_changed'] is False
    assert result['tenant_data_changed'] is False and result['configuration_changed'] is False
    assert os.readlink(h.project / '.venv') == '/srv/wa/releases/current/venv'
    assert (h.project / 'unmanaged.txt').read_bytes() == b'preserve unknown original'
    assert (h.project / 'private/tenants.json').read_bytes() == b'{"fixture":"preserve untouched"}'
    for name, raw in alignment.source_files(h.source).items():
        assert (h.project / name).read_bytes() == raw
    quarantine = result['file_receipt']['quarantine']['/srv/wa/app/README.md']
    assert (h.base / quarantine.lstrip('/')).read_bytes() == b'old public source\n'
    assert (h.base / 'srv/wa/releases/old/venv').is_dir()
    repeated = apply(h)
    assert repeated == result


@pytest.mark.parametrize('event', ['journal-staging', 'alignment-files-committed'])
def test_interrupted_alignment_resumes_same_plan_without_rebasing_preimages(aligned_host, event):
    h = aligned_host
    def fault(name, details):
        if name == event: raise RuntimeError('synthetic interruption')
    with pytest.raises(RuntimeError, match='interruption'): apply(h, fault=fault)
    assert os.readlink(h.project / '.venv') == '/srv/wa/releases/old/venv'
    assert apply(h)['phase'] == 'completed'


@pytest.mark.parametrize('damage', ['outside-project', 'data-target', 'permissions', 'owner', 'binding', 'source', 'pointer'])
def test_alignment_rejects_drift_and_scope_expansion_before_publication(aligned_host, damage):
    h = aligned_host
    if damage in ('outside-project', 'data-target'):
        name = '/etc/other-service.conf' if damage == 'outside-project' else '/srv/wa/app/private/tenants.json'
        h.plan['after']['files'][name] = copy.deepcopy(h.plan['after']['files']['/srv/wa/app/README.md'])
    elif damage == 'permissions': h.plan['after']['files']['/srv/wa/app/README.md']['mode'] = 0o666
    elif damage == 'owner': h.plan['owner'] = {'synthetic': 'foreign'}
    elif damage == 'binding': h.plan['deployment'] = {'synthetic': 'changed'}
    elif damage == 'source': h.plan['after']['files']['/srv/wa/app/README.md']['sha256'] = '0' * 64
    else:
        (h.project / '.venv').unlink(); (h.project / '.venv').symlink_to('/unrelated')
    with pytest.raises((ValueError, filesystem.LifecycleError)): apply(h)
    assert (h.project / 'README.md').read_bytes() == b'old public source\n'
    assert (h.project / 'private/tenants.json').read_bytes() == b'{"fixture":"preserve untouched"}'


def test_source_closure_includes_skills_and_restore_dependencies_but_no_private_data():
    sources = alignment.source_files(Path(__file__).parents[1])
    for name in ('scripts/admin_deployment.py', 'scripts/backup_validation.py', 'scripts/release_database.py',
                 'scripts/backup_schemas/8.sql', 'plugin/skills/whatsapp-transcription/SKILL.md',
                 'sally_whatsapp/restore_maintenance.py'):
        assert name in sources
    assert all(not name.startswith(('private/', 'work/', '.venv/', 'tests/')) for name in sources)

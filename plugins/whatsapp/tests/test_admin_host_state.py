"""Fresh administrative lock namespace, independent from app provisioning."""
import pytest

from host.lifecycle import filesystem
from test_admin_host import adapter, fixture


def prerequisites(root):
    for path in ('/var/lib/develative-deploy',
                 '/srv/openai-codex/projects/whatsapp-personal/private'):
        (root.base / path.lstrip('/')).mkdir(parents=True, mode=0o700)


def test_first_phase_creates_only_own_state_and_preserves_lock_identity(fixture):
    root, host, plan, _, _ = fixture
    prerequisites(root)
    with host.critical_section(plan):
        assert root.directory(adapter.STATE)['mode'] == 0o700
    lock = root.base / (adapter.STATE + '/publication.lock').lstrip('/')
    inode = lock.stat().st_ino
    with host.critical_section(plan):
        pass
    assert lock.stat().st_ino == inode
    assert len(list((root.base / 'var/lib/develative-host-lifecycle/whatsapp/operations').iterdir())) == 1
    assert not (root.base / 'var/lib/develative-host-lifecycle/box').exists()


def test_existing_protected_state_keeps_its_mode(fixture):
    root, host, plan, _, _ = fixture
    prerequisites(root)
    state = root.base / adapter.STATE.lstrip('/')
    state.mkdir(mode=0o755)
    state.chmod(0o755)
    with host.critical_section(plan):
        pass
    assert state.stat().st_mode & 0o777 == 0o755
    assert not (root.base / 'var/lib/develative-host-lifecycle').exists()


@pytest.mark.parametrize('failure', ['private-missing', 'state-writable', 'legacy-state-lost'])
def test_state_prelude_never_repairs_or_recreates_missing_existing_state(fixture, failure):
    root, host, plan, _, _ = fixture
    prerequisites(root)
    if failure == 'private-missing':
        (root.base / 'srv/openai-codex/projects/whatsapp-personal/private').rmdir()
    elif failure == 'state-writable':
        state = root.base / adapter.STATE.lstrip('/')
        state.mkdir(); state.chmod(0o777)
    else:
        plan['mode'] = 'legacy'
    with pytest.raises(filesystem.LifecycleError):
        with host.critical_section(plan):
            pytest.fail('Unsafe state accepted')
    assert not (root.base / 'var/lib/develative-host-lifecycle').exists()

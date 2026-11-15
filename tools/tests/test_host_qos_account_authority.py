"""Separate numerical authorities on real fixture roots; no chown privilege.

The only seam is the control Root's expected UID: the container cannot create
UID0/service-owned files. Target paths and ownership observations remain real.
"""
import os

import pytest
from test_host_qos_applicator import case, qos


def test_preflight_uses_account_authority_while_journals_keep_control_authority(case):
    control, base, _, _, _, _ = case
    with qos.engine.Root(base / 'var/lib/whatsapp-new-waha') as target:
        old_uid = control.uid
        try:
            control.uid = old_uid + 10000
            view = qos.adoption._account_engine(qos, target, control, '/var/lib/whatsapp-new-waha')
            assert view.uid == control.uid != target.uid
            assert view._directory_uid('/.config/systemd/user/app.slice.d') == target.uid
            assert view._directory_uid(qos.engine.STATE + '/host/operations') == control.uid
            spec = {'uid': target.uid, 'gid': target.gid, 'mode': 0o700, 'retention': 'retain'}
            before, after = qos.adoption.manifest(), qos.adoption.manifest(directories={'/.config': spec})
            qos.engine._preflight(view, before, after, 'd' * 32)
            wrong = qos.adoption.manifest(directories={'/.config': {**spec, 'uid': control.uid}})
            with pytest.raises(qos.engine.LifecycleError): qos.engine._preflight(view, before, wrong, 'd' * 32)
            for path in ('/outside', '/.config/systemd/users/foo', '/.config/../escape', qos.engine.STATE + '-other/x'):
                with pytest.raises((qos.QoSError, qos.engine.LifecycleError)):
                    view._directory_uid(path)
            # The real target remains untouched by read-only preflight.
            assert list(target.base.iterdir()) == []
        finally:
            control.uid = old_uid


def test_scoped_directory_hook_preserves_root_journal_route_and_rejects_symlink(case):
    control, base, _, _, _, _ = case
    home = base / 'var/lib/whatsapp-new-waha'; victim = base / 'outside'; victim.mkdir()
    (base / qos.engine.STATE.lstrip('/') / 'host').mkdir(parents=True, mode=0o700)
    with qos.engine.Root(home) as target:
        view = qos.adoption._account_engine(qos, target, control, '/var/lib/whatsapp-new-waha')
        (home / '.config').symlink_to(victim, target_is_directory=True)
        with pytest.raises((qos.QoSError, qos.engine.LifecycleError, OSError)):
            view.directory('/.config/systemd')
        assert list(victim.iterdir()) == []
        with view._parent(qos.engine.STATE + '/host/operation.lock') as (fd, name):
            assert name == 'operation.lock'
            assert os.readlink('/proc/self/fd/' + str(fd)).startswith(str(base / qos.engine.STATE.lstrip('/')))

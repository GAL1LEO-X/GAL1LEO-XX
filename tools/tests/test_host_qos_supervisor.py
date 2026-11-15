"""Real isolated child lifetime and captured-source bootstrap, no host commands."""
import os
import signal
import sys
import time
import types

import pytest
from test_host_qos_applicator import BASE, case, qos


def test_compiling_captured_source_does_not_reread_missing_siblings():
    module = types.ModuleType('captured_qos')
    module.__file__ = '/does-not-exist/generation/host/qos/applicator.py'
    dependencies = (qos.engine, qos.contract, qos.adoption, qos.processes)
    module.__dict__['_PINNED_MODULES'] = dependencies
    exec(compile((BASE / 'host/qos/applicator.py').read_bytes(), module.__file__, 'exec'), module.__dict__)
    assert (module.engine, module.contract, module.adoption, module.processes) == dependencies


def test_killed_caller_does_not_release_lease_while_its_client_remains_alive(case):
    root, base, _, _, _, _ = case
    started, release, finished = (base / name for name in ('client-started', 'release-client', 'client-finished'))
    source = ('from pathlib import Path\nimport os,time\n'
              'started,release,finished=map(Path,__import__("sys").argv[1:])\n'
              'started.write_text(str(os.getpid()))\n'
              'deadline=time.monotonic()+8\n'
              'while not release.exists() and time.monotonic()<deadline: time.sleep(.01)\n'
              'finished.write_text("reaped next")\n')
    child = os.fork()
    if child == 0:
        try:
            with qos.lease(root) as descriptor:
                qos.supervised([sys.executable, '-I', '-B', '-c', source, str(started), str(release), str(finished)], None, descriptor)
        finally:
            os._exit(0)
    try:
        deadline = time.monotonic() + 4
        while not started.exists() and time.monotonic() < deadline: time.sleep(.01)
        assert started.exists()
        os.kill(child, signal.SIGKILL); os.waitpid(child, 0); child = None
        with pytest.raises(qos.QoSError):
            with qos.lease(root): pass
        assert not finished.exists()
    finally:
        release.touch()
        if child is not None:
            os.kill(child, signal.SIGKILL); os.waitpid(child, 0)
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        try:
            with qos.lease(root): break
        except qos.QoSError: time.sleep(.01)
    else: pytest.fail('Supervisor did not release lease after its own client exit')
    assert finished.exists()

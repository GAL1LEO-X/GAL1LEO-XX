"""Independent real-process proof; never invokes systemctl or host services."""
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]


HARNESS = r"""
import ctypes, fcntl, json, os, pathlib, signal, subprocess, sys, time
root, source, mode = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
lock, ready, release, done, wrapper_pid = [root/name for name in
    ('lease', 'ready', 'release', 'done', 'wrapper-pid')]
lock.write_bytes(b'original lock inode')
initial = lock.stat().st_ino
client = root/'client.py'
client.write_text('''import os, pathlib, sys, time
ready, release, inherited = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), int(sys.argv[3])
# Explicitly discard every nonstandard FD: retention is the supervisor's job.
os.closerange(3, 65536)
try: os.fstat(inherited)
except OSError: pass
else: raise AssertionError("client unexpectedly owns the inherited lease")
ready.write_text(str(os.getpid()))
deadline=time.monotonic()+8
while not release.exists() and time.monotonic()<deadline: time.sleep(0.01)
if not release.exists(): raise RuntimeError("fixture was not bounded by its supervisor")
''')
wrapper = root/'wrapper.py'
wrapper.write_text('''import importlib.util, json, os, pathlib, sys
source, fd, client, ready, release, done, pid, mode = sys.argv[1:]
spec=importlib.util.spec_from_file_location("reviewed_service_client",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
pathlib.Path(pid).write_text(str(os.getpid()))
try:
    result=module.supervise([sys.executable,"-I","-B",client,ready,release,fd],
        (int(fd),), timeout=1 if mode=="timeout" else 6, max_bytes=4096)
except Exception as error:
    pathlib.Path(done).write_text(json.dumps({"outcome":"error","type":type(error).__name__}))
else:
    pathlib.Path(done).write_text(json.dumps({"outcome":"complete"}))
''')
parent = root/'parent.py'
parent.write_text('''import fcntl, os, pathlib, subprocess, sys, time
lock, wrapper, source, client, ready, release, done, pid, mode = sys.argv[1:]
with open(lock,"r+") as stream:
    fcntl.flock(stream,fcntl.LOCK_EX)
    subprocess.Popen([sys.executable,"-I","-B",wrapper,source,str(stream.fileno()),
        client,ready,release,done,pid,mode],pass_fds=(stream.fileno(),),
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    deadline=time.monotonic()+4
    while not pathlib.Path(ready).exists() and time.monotonic()<deadline: time.sleep(0.01)
    os._exit(73 if pathlib.Path(ready).exists() else 74)
''')
controller = subprocess.Popen([sys.executable,'-I','-B',str(parent),str(lock),str(wrapper),str(source),
    str(client),str(ready),str(release),str(done),str(wrapper_pid),mode],
    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
supervisor = child = None
try:
    assert controller.wait(timeout=5)==73
    supervisor, child = int(wrapper_pid.read_text()), int(ready.read_text())
    assert pathlib.Path('/proc',str(supervisor)).exists()
    assert pathlib.Path('/proc',str(child)).exists()
    with lock.open('r+') as probe:
        try: fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: pass
        else: raise AssertionError('Lease lost with live FD-closing client after controller death')
    with (root/'unrelated-box-lock').open('w') as unrelated:
        fcntl.flock(unrelated,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if mode=='release': release.write_text('finish')
    deadline=time.monotonic()+5
    while not done.exists() and time.monotonic()<deadline: time.sleep(0.01)
    assert done.exists(), 'Supervisor did not finish within its independent bound'
    result=json.loads(done.read_text())
    assert result['outcome']==('complete' if mode=='release' else 'error'),result
    waited,status=os.waitpid(supervisor,0)
    assert waited==supervisor and os.waitstatus_to_exitcode(status)==0
    supervisor=None
    assert not pathlib.Path('/proc',str(child)).exists(), 'Client was not reaped before lease release'
    child=None
    with lock.open('r+') as available: fcntl.flock(available,fcntl.LOCK_EX|fcntl.LOCK_NB)
    assert lock.stat().st_ino==initial and lock.read_bytes()==b'original lock inode'
    print(json.dumps({'mode':mode,'client_inherits_lease':False,'lease_retained':True,'reaped':True}))
finally:
    release.write_text('finish')
    if controller.poll() is None: controller.kill();controller.wait()
    for pid in (child,supervisor):
        if pid is not None:
            try: os.kill(pid,signal.SIGKILL)
            except ProcessLookupError: pass
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        try: pid,_=os.waitpid(-1,os.WNOHANG)
        except ChildProcessError: break
        if not pid: time.sleep(0.01)
"""


@pytest.mark.parametrize('mode', ['release', 'timeout'])
def test_supervisor_keeps_lease_after_controller_death_even_if_client_closes_fds(tmp_path, mode):
    completed = subprocess.run([sys.executable, '-I', '-B', '-c', HARNESS,
        str(tmp_path), str(ROOT/'host/lifecycle/service_client.py'), mode],
        capture_output=True, text=True, timeout=15)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert '"client_inherits_lease": false' in completed.stdout
    assert '"lease_retained": true' in completed.stdout
    assert '"reaped": true' in completed.stdout

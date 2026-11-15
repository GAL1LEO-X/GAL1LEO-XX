"""Each WhatsApp entry point rejects another product's cached installation module."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / 'plugins/whatsapp/scripts'
ENTRY_POINTS = (
    'admin_handoff.py', 'admin_host.py', 'admin_manifest.py', 'backup_runtime.py',
    'backup_validation.py', 'build_admin_bundle.py', 'fresh_admin.py', 'github_release.py',
    'github_release_common.py', 'host_integration.py', 'installation_command.py',
    'provision_host.py', 'release_admin.py', 'release_backup.py', 'release_build.py',
    'release_runtime.py', 'release_transaction.py', 'runtime_lifecycle.py',
    'state_enrollment.py', 'tenant_admin.py', 'wa_link.py',
)


@pytest.mark.parametrize('entry', ENTRY_POINTS)
def test_entry_point_rejects_foreign_layout_before_resolving_any_identity(entry):
    code = """import importlib.util, sys, types
foreign=types.ModuleType('installation_layout');foreign.FORMAT='box-installation-v1'
def forbidden(*args,**kwargs):raise AssertionError('Foreign installation was consulted')
foreign.active=forbidden;foreign.mapped=forbidden
sys.modules['installation_layout']=foreign
spec=importlib.util.spec_from_file_location('entry_under_test',sys.argv[1])
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module
try:spec.loader.exec_module(module)
except ImportError as error:
    assert 'cannot reuse another product installation layout' in str(error),str(error)
else:raise AssertionError('WhatsApp silently reused a BOX installation layout')
assert sys.modules['installation_layout'] is foreign
"""
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(SCRIPTS / entry)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name != 'posix', reason='WhatsApp administrative gate imports fcntl')
def test_own_cached_layout_remains_usable_by_the_read_only_admission_gate():
    code = """import importlib.util, sys
from pathlib import Path
scripts=Path(sys.argv[1])
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module
layout=load('installation_layout',scripts/'installation_layout.py')
layout.select(layout.Installation.legacy())
module=load('entry_under_test',scripts/'release_admin.py')
assert str(module.OWNER)=='/etc/develative-deploy/recovery-owners/whatsapp.json'
assert sys.modules['installation_layout'] is layout
"""
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(SCRIPTS)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr

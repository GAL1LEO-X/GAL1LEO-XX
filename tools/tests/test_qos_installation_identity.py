"""QoS imports preserve identity isolation; no kernel, service or real /etc writes."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='QoS lifecycle uses POSIX filesystem primitives')

PRELUDE = """import hashlib,importlib.util,json,os,sys
from pathlib import Path
root=Path(sys.argv[1]);fixture=Path(sys.argv[2]);sys.path.insert(0,str(root))
from host import installation as original
original_object=original

def load_qos():
    source=root/'host/qos/applicator.py'
    spec=importlib.util.spec_from_file_location('isolated_qos_identity',source)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    assert sys.modules['host.installation'] is original_object
    return module

def configured():
    return original.Installation.from_dict(json.loads((root/'plugins/whatsapp/deploy/installation.example.json').read_bytes()))

def installed(selected):
    (fixture/'etc').mkdir(mode=0o700)
    marker=fixture/original.IDENTITY.relative_to('/')
    locator=fixture/original.PROFILE.relative_to('/')
    marker.write_bytes(original.identity_bytes(selected));marker.chmod(0o600)
    if not selected.compatibility:
        locator.write_bytes(selected._encoded);locator.chmod(0o600)
    original.activate_installation(root=fixture,trusted_uid=os.getuid())
    return marker,locator
"""


def run_case(tmp_path, code):
    result = subprocess.run([sys.executable, '-I', '-B', '-c', PRELUDE + code, str(ROOT), str(tmp_path)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_box_only_qos_import_and_registry_do_not_resolve_whatsapp_identity(tmp_path):
    run_case(tmp_path, """
assert original._selected is None
qos=load_qos()
assert original._selected is None
assert qos.installation_profile.__globals__['_selected'] is None
assert not (fixture/'etc').exists()
def forbidden():raise AssertionError('BOX-only registry requested WhatsApp identity')
qos.installation_profile=forbidden
account={'uid':2001,'gid':2001,'home':'/var/lib/boxproxy'}
policy={'parameters':{'box_account':account,'essential_accounts':{}}}
registry={'format':1,'policy_sha256':'a'*64,'consumers':{'box.release':{
    'owner':'box','account':'boxproxy','unit':'box-proxy.service','status':'active',**account}}}
assert qos.validate_registry(registry,policy)==registry
""")


@pytest.mark.parametrize('mode', ['legacy', 'configured'])
def test_explicit_offline_identity_is_copied_without_replacing_canonical_module(tmp_path, mode):
    run_case(tmp_path, f"""
selected=original.Installation.legacy() if {mode!r}=='legacy' else configured()
original.select(selected)
qos=load_qos()
assert qos.installation_profile.__globals__ is not original.__dict__
assert qos.installation_profile().sha256==selected.sha256
assert original._selected is selected
assert not (fixture/'etc').exists()
""")


@pytest.mark.parametrize('mode', ['legacy', 'configured'])
def test_installed_context_retains_identity_checks_after_private_source_loading(tmp_path, mode):
    run_case(tmp_path, f"""
selected=original.Installation.legacy() if {mode!r}=='legacy' else configured()
marker,locator=installed(selected)
qos=load_qos()
assert qos.installation_profile().sha256==selected.sha256
assert qos.installation_profile.__globals__['_installed_context']==(fixture,os.getuid())
marker.unlink()
try:qos.installation_profile()
except ValueError:pass
else:raise AssertionError('QoS dropped installed identity checks after source loading')
""")


def test_explicit_source_manifest_does_not_inherit_an_offline_identity(tmp_path):
    run_case(tmp_path, """
original.select(original.Installation.legacy())
qos=load_qos()
manifest=fixture/'sources.json'
value={'format':1,'sources':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in qos.SOURCES}}
raw=qos.canonical(value);manifest.write_bytes(raw)
# Only ownership validation is replaced for the isolated manifest fixture.
# The production function still checks the exact bounded manifest and every source digest.
allowed={manifest,*(root/name for name in qos.SOURCES)}
def fixture_protected(path):
    selected=Path(path)
    assert selected in allowed and selected==selected.resolve(strict=True)
    return selected
qos.protected=fixture_protected
qos.load_sources(manifest,hashlib.sha256(raw).hexdigest())
assert qos.installation_profile.__globals__['_selected'] is None
assert qos.installation_profile.__globals__['_installed_context'] is None
assert sys.modules['host.installation'] is original_object
assert original._selected.compatibility
""")

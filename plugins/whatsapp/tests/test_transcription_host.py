import importlib.util
from pathlib import Path
import tomllib

import pytest

spec = importlib.util.spec_from_file_location('transcription_host',
    Path(__file__).parents[1] / 'scripts/transcription_host.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def test_enable_preserves_all_unrelated_configuration_and_is_idempotent():
    source = '# operator comment\n[bridge]\nprofile_name="Synthetic"\nport=1234\n[extra]\nkeep=true\n'
    enabled = host.enable_config(source, 555)
    assert host.enable_config(enabled, 555) == enabled
    before, after = tomllib.loads(source), tomllib.loads(enabled)
    assert after['bridge'].pop('transcription_socket') == '/run/whatsapp-transcriber/worker.sock'
    assert after['bridge'].pop('transcription_server_uid') == 555
    assert after == before and enabled.startswith('# operator comment\n')
    with pytest.raises(ValueError, match='reconciliation'):
        host.enable_config(enabled, 556)


def test_worker_unit_is_local_limited_and_separate_from_tenant_accounts():
    unit = host.unit('/opt/whatsapp-transcriber/releases/synthetic',
                     '/opt/whatsapp-transcriber/models/synthetic', [555, 556])
    assert '--allow-uid 555 --allow-uid 556' in unit
    for setting in ('PrivateNetwork=yes', 'RestrictAddressFamilies=AF_UNIX',
                    'MemoryMax=20G', 'CPUQuota=800%', 'LimitCORE=0', 'NoNewPrivileges=yes',
                    '--device cpu --compute-type float32', 'User=whatsapp-transcriber'):
        assert setting in unit
    assert '/var/lib/whatsapp-data' not in unit and '/etc/whatsapp' not in unit
    assert host.backend_dropin() == '[Service]\nSupplementaryGroups=whatsapp-transcription\n'


@pytest.mark.parametrize('path', ['/tmp/worker', '/opt/whatsapp-transcriber/../elsewhere',
                                  '/opt/whatsapp-transcriber/a\nExecStart=/bin/sh'])
def test_rejects_unit_path_injection(path):
    with pytest.raises(ValueError):
        host.unit(path, '/opt/whatsapp-transcriber/models/test', [555])

"""Standalone backup startup with real processes and a physical generation."""
import hashlib
import json
import os
import subprocess

import pytest

from test_backup_bytecode import backup_tree
from test_release_admin import admin, installation


def inventory(generation, owner):
    result = {}
    for path in (generation, *sorted(generation.rglob('*')), owner):
        metadata = path.lstat()
        name = 'owner' if path == owner else path.relative_to(generation).as_posix()
        result[name] = [metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_mtime_ns,
                        path.readlink().as_posix() if path.is_symlink() else
                        hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None]
    return result


def startup(installation, tmp_path, arguments, *, managed=False, corruption=None):
    generation, owner, _, project = backup_tree(installation, tmp_path)
    if managed:
        value = json.loads(owner.read_text())
        arguments = [*arguments, '--managed-child', '--admin-pin', json.dumps({
            'epoch': value['epoch'], 'path': str(generation), 'manifest': value['manifest_sha256']})]
    worker = project/'scripts/backup_runtime.py'
    source = worker.read_text()
    # Observe the real function return; do not replace imports, generation
    # admission, main(), the session/reexec or its generation-pin comparison.
    source = source.replace('recovery,release,administration,generation=recovery_helpers()',
                            'recovery,release,administration,generation=recovery_helpers()\n'
                            "    _fixture_event('helpers-loaded')")
    source = source.replace("value['bytecode_flag'] = sys.flags.dont_write_bytecode",
                            "value['bytecode_flag'] = sys.flags.dont_write_bytecode\n"
                            "    value['dont_write_bytecode'] = sys.dont_write_bytecode")
    observer = f'''
def _fixture_event(phase):
    value = {{'phase': phase, 'pid': os.getpid(), 'ppid': os.getppid(),
             'session': os.getsid(0), 'flag': sys.flags.dont_write_bytecode,
             'disabled': sys.dont_write_bytecode, 'arguments': sys.argv[1:]}}
    with Path({str(tmp_path/'startup-events.jsonl')!r}).open('a') as stream:
        stream.write(json.dumps(value)+'\\n')
_fixture_event('entry')
if __name__=='__main__': main()
'''
    assert source.count("if __name__=='__main__': main()") == 1
    worker.write_text(source.replace("if __name__=='__main__': main()", observer))
    if corruption == 'cache':
        cache = generation/'__pycache__'
        cache.mkdir()
        (cache/'existing.pyc').write_bytes(b'synthetic cache retained')
    elif corruption == 'link':
        target = generation/'release_backup.py'
        original = tmp_path/'original-release-backup.py'
        target.rename(original)
        target.symlink_to(original)
    before = inventory(generation, owner)
    environment = {name: value for name, value in os.environ.items() if not name.startswith('PYTHON')}
    process = subprocess.run([str(project/'.venv/bin/python'), str(worker), *arguments],
                             cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30)
    events = [json.loads(line) for line in (tmp_path/'startup-events.jsonl').read_text().splitlines()]
    outcome_path = tmp_path/'worker-outcome.json'
    outcome = json.loads(outcome_path.read_text()) if outcome_path.exists() else None
    try:
        admin.load_generation()
        readmission = 'passed'
    except admin.AdminError as error:
        readmission = str(error)
    after = inventory(generation, owner)
    result = {'returncode': process.returncode, 'events': events, 'worker': outcome,
              'readmission': readmission, 'generation_and_owner_unchanged': before == after,
              'created_generation_paths': sorted(set(after)-set(before)),
              'environment_bytecode_override': 'PYTHONDONTWRITEBYTECODE' in environment}
    (tmp_path/'startup-result.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    return result, process, generation


@pytest.mark.parametrize('mode', ['check-recovery', 'outer', 'managed'])
def test_backup_without_python_bytecode_flag_preserves_generation(installation, tmp_path, mode):
    arguments = ['--check-recovery'] if mode == 'check-recovery' else ['--all']
    result, process, generation = startup(installation, tmp_path, arguments, managed=mode == 'managed')
    assert process.returncode == 0, (result, process.stderr)
    assert result['environment_bytecode_override'] is False
    assert result['events'][0]['flag'] == 0
    assert all(event['disabled'] is True for event in result['events']), result
    helpers = [event for event in result['events'] if event['phase'] == 'helpers-loaded']
    assert [event['flag'] for event in helpers] == ([0, 1] if mode == 'outer' else [0]), result
    if mode == 'outer':
        outer, child = helpers
        assert child['ppid'] == outer['pid'] and child['session'] == child['pid']
        assert child['pid'] != outer['pid'] and '--managed-child' in child['arguments']
        pin = json.loads(child['arguments'][child['arguments'].index('--admin-pin')+1])
        assert pin == {'epoch': 'a'*32, 'path': str(generation),
                       'manifest': json.loads(installation[1].read_text())['manifest_sha256']}
    if mode != 'check-recovery':
        assert result['worker']['status'] == 'registry-boundary'
    else:
        assert json.loads(process.stdout)['helper'] == str(generation/'release_backup.py')
    assert result['readmission'] == 'passed', result
    assert result['generation_and_owner_unchanged'], result
    assert result['created_generation_paths'] == []


def test_backup_help_without_python_bytecode_flag(installation, tmp_path):
    result, process, _ = startup(installation, tmp_path, ['--help'])
    assert process.returncode == 0 and '--check-recovery' in process.stdout
    assert result['events'][0]['flag'] == 0 and result['events'][0]['disabled'] is True
    assert all(event['phase'] == 'entry' for event in result['events'])
    assert result['generation_and_owner_unchanged'] and result['readmission'] == 'passed'


@pytest.mark.parametrize('corruption', ['cache', 'link'])
def test_backup_startup_does_not_clean_or_admit_contaminated_generation(
        installation, tmp_path, corruption):
    result, process, _ = startup(installation, tmp_path, ['--check-recovery'], corruption=corruption)
    assert process.returncode != 0
    assert result['worker']['status'] == 'rejected' and result['worker']['type'] == 'AdminError'
    assert result['readmission'].startswith('WhatsApp administration blocked:')
    assert all(event['phase'] == 'entry' for event in result['events'])
    assert result['generation_and_owner_unchanged'] and result['created_generation_paths'] == []

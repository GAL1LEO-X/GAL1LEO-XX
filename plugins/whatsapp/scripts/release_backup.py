"""Durable WhatsApp-only backup recovery, under publication then tenant locks.

No database rollback occurs here. A completed copy and recovered services are
independent facts. The installed helper is shared by standalone and release use.
"""
import sys as _installation_sys
from pathlib import Path as _InstallationPath
import types as _installation_types
if 'installation_layout' not in _installation_sys.modules:
    _installation_source=_InstallationPath(__file__).with_name('installation_layout.py')
    _installation_module=_installation_types.ModuleType('installation_layout')
    _installation_module.__file__=str(_installation_source)
    _installation_sys.modules['installation_layout']=_installation_module
    try:
        exec(compile(_installation_source.read_bytes(),str(_installation_source),'exec'),_installation_module.__dict__)
    except BaseException:
        _installation_sys.modules.pop('installation_layout',None)
        raise
if getattr(_installation_sys.modules['installation_layout'], 'FORMAT', None) != 'whatsapp-installation-v1':
    raise ImportError('The whatsapp entry point cannot reuse another product installation layout')
from installation_layout import active as installation_profile, mapped as installation_path, gateway_port
import json
import os
from pathlib import Path
import re
import shlex
import uuid

from github_release_common import STATE, require, run, save, sha

PROTOCOL = 1
FORMAT = 'whatsapp-backup-recovery-v1'
JOURNAL = STATE/'whatsapp/backup.json'
RECOVERY_TIMER = installation_path('develative-whatsapp-recovery.timer')
RECOVERY_SERVICE = installation_path('develative-whatsapp-recovery.service')
EMPTY_AUXILIARY = ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecCondition')
MAX_TYPED_RECOVERY = 256 * 1024


def capabilities():
    return {'protocol': PROTOCOL, 'beforeStop': True, 'independentRecovery': True,
            'copyAndServicesSeparate': True, 'ownedProcessSession': True}


def read():
    if not JOURNAL.exists():
        return None
    require(not JOURNAL.is_symlink(), 'Backup recovery journal cannot be a symlink')
    plan = json.loads(JOURNAL.read_text())
    require(isinstance(plan, dict) and plan.get('format') == FORMAT
            and isinstance(plan.get('id'), str) and re.fullmatch('[0-9a-f]{32}', plan['id'])
            and plan.get('phase') in ('prepared', 'copying', 'recovering', 'recovery-failed', 'restored')
            and type(plan.get('servicesRestored')) is bool
            and isinstance(plan.get('copies'), dict) and isinstance(plan.get('components'), list)
            and (plan['phase'] == 'restored') == plan['servicesRestored'],
            'Invalid backup recovery journal; inspect before any service change')
    return plan


def serial_components(components):
    return [{key: str(value) if isinstance(value, Path) else value for key, value in item.items()}
            for item in components]


def context(root, registered):
    root = Path(root)
    paths = [root/'private/tenants.json', root/'sally_whatsapp/__init__.py']
    for item in registered:
        paths.extend([Path(item['config']), Path(item['wrapper'])])
    return {str(path): sha(path) for path in paths}


def activation_idle():
    import release_transaction as transaction
    require(not transaction.GATE.exists(), 'Backup recovery cannot cross an active release gate')
    if transaction.JOURNAL.exists():
        phase = json.loads(transaction.JOURNAL.read_text()).get('phase')
        require(phase in ('published', 'rolled-back'), 'Recover the unfinished activation before backup')


def begin(root, registered, components, version):
    activation_idle()
    old = read()
    require(old is None or old['servicesRestored'], 'An interrupted backup must be recovered first')
    require(bool(registered) and len({item['slug'] for item in registered}) == len(registered),
            'Invalid backup selection')
    expected = {item['slug']+'.'+kind for item in registered for kind in ('gateway', 'bridge')}
    require({item['name'] for item in components} == expected and len(components) == len(expected)
            and all(type(item['active']) is bool for item in components), 'Invalid prior backup activity')
    plan = {'format': FORMAT, 'id': uuid.uuid4().hex, 'root': str(root),
            'version': version, 'context': context(root, registered),
            'selected': [item['slug'] for item in registered],
            'components': serial_components(components), 'phase': 'prepared',
            'copies': {item['slug']: {'path': None, 'complete': False} for item in registered},
            'servicesRestored': False, 'failures': [], 'worker': None}
    # save() fsyncs the file and its directory before a caller can stop anything.
    save(JOURNAL, plan)
    return plan


def validate_context(plan, root, registered):
    require(plan.get('root') == str(root), 'Backup recovery project differs')
    selected = [item for item in registered if item['slug'] in plan.get('selected', [])]
    require({item['slug'] for item in selected} == set(plan.get('selected', []))
            and bool(selected) and set(plan['copies']) == {item['slug'] for item in selected},
            'Backup recovery instances changed')
    require(context(root, selected) == plan.get('context'),
            'Backup recovery configuration changed; inspect without starting services')
    # Commands come from the current trusted registry, never arbitrary journal argv.
    expected = []
    for item in selected:
        for kind, command, unit, port in [
            ('gateway', [str(item['wrapper']), 'systemctl', '--user'], 'whatsapp-waha.service', gateway_port(item['slug'],item['port'])),
            ('bridge', ['systemctl'], item['unit'], item['port'])]:
            expected.append({'name': item['slug']+'.'+kind, 'kind': kind, 'command': command,
                             'unit': unit, 'port': port, 'config': str(item['config'])})
    actual = [{key: value for key, value in item.items() if key != 'active'} for item in plan['components']]
    require(actual == expected and all(type(item.get('active')) is bool for item in plan['components']),
            'Backup recovery component identity changed')
    return selected


def require_id(operation_id):
    plan = read()
    require(plan is not None and plan['id'] == operation_id and not plan['servicesRestored'],
            'Backup recovery operation differs or is already closed')
    return plan


def process_state(path):
    # comm may contain spaces or ')'; fields after its final ')' start at state.
    fields = path.read_text().rsplit(')', 1)[1].split()
    return {'state': fields[0], 'session': int(fields[3]), 'start': fields[19]}


def attach_worker(operation_id):
    plan = require_id(operation_id)
    require(plan.get('worker') is None, 'A backup worker is already recorded')
    pid = os.getpid()
    state = process_state(Path('/proc')/str(pid)/'stat')
    require(state['session'] == pid, 'Backup worker requires its own process session')
    plan['worker'] = {'pid': pid, 'session': pid, 'start': state['start'],
                      'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    save(JOURNAL, plan)


def require_worker_quiescent(plan):
    worker = plan.get('worker')
    if worker is None:
        return  # No child attached yet; the durable prepare still precedes stop.
    require(isinstance(worker, dict) and set(worker) == {'pid','session','start','boot'}
            and type(worker['pid']) is int and worker['pid'] > 0
            and type(worker['session']) is int and worker['session'] == worker['pid']
            and isinstance(worker['start'],str) and re.fullmatch('[0-9]+',worker['start'])
            and isinstance(worker['boot'],str)
            and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',worker['boot']),
            'Invalid backup worker identity')
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != worker['boot']:
        return
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:state=process_state(path/'stat')
        except (FileNotFoundError,ProcessLookupError):continue
        pid=int(path.name)
        if pid == worker['pid']:
            require(state['start'] == worker['start'], 'Backup worker PID was reused; inspect before recovery')
        if state['session'] != worker['session'] or state['state'] in ('Z','X'):continue
        # The worker may perform its own final verification after its commands
        # have exited. Other surviving session members can still issue a late
        # stop/write even if a wrapper closed its inherited lock descriptor.
        require(pid == os.getpid() == worker['pid'],
                'Backup process session is still active; recovery deferred')


def before_stop(operation_id, slug, path, gateway, bridge):
    plan = require_id(operation_id)
    require(slug in plan['copies'], 'Backup tenant is outside the recorded operation')
    prior = {item['kind']: item['active'] for item in plan['components'] if item['name'].startswith(slug+'.')}
    require(prior == {'gateway': gateway, 'bridge': bridge}, 'Backup service activity changed before stop')
    require(plan['copies'][slug]['path'] is None, 'Backup tenant was already attempted')
    plan['copies'][slug] = {'path': str(path), 'complete': False}
    plan['phase'] = 'copying'
    save(JOURNAL, plan)


def copy_complete(operation_id, slug):
    plan = require_id(operation_id)
    require(slug in plan['copies'] and plan['copies'][slug]['path'] is not None, 'Backup was not started')
    plan['copies'][slug]['complete'] = True
    save(JOURNAL, plan)


def recover(root, registered, restore):
    plan = read()
    if plan is None or plan['servicesRestored']:
        return plan
    activation_idle()
    validate_context(plan, root, registered)
    require_worker_quiescent(plan)
    plan['phase'] = 'recovering'
    save(JOURNAL, plan)
    components = [{**item, 'config': Path(item['config'])} for item in plan['components']]
    try:
        failures = restore(components, plan['version'])
    except BaseException:
        plan['phase'] = 'recovery-failed'
        plan['failures'] = ['recovery.interrupted']
        save(JOURNAL, plan)
        raise
    plan['failures'] = failures
    plan['servicesRestored'] = not failures
    plan['phase'] = 'recovery-failed' if failures else 'restored'
    save(JOURNAL, plan)
    require(not failures, 'Backup service recovery requires administrator attention: '+', '.join(failures))
    return plan


def require_empty_auxiliary(unit, field):
    # Match the installer's typed empty-value proof without importing host
    # modules into the independently installed release helper generation.
    require(unit == RECOVERY_SERVICE and field in EMPTY_AUXILIARY,
            'Property is outside the dedicated recovery empty-value profile')
    object_name = ''.join(char if char.isascii() and char.isalnum()
                          else '_' + format(ord(char), '02x') for char in unit)
    raw = run(['/usr/bin/busctl', '--system', '--json=short', 'get-property',
               'org.freedesktop.systemd1', '/org/freedesktop/systemd1/unit/' + object_name,
               'org.freedesktop.systemd1.Service', field], timeout=5)
    require(isinstance(raw, str), 'Invalid typed recovery response')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate typed recovery response field')
            value[key] = item
        return value
    try:
        require(len(raw.encode('utf-8')) <= MAX_TYPED_RECOVERY, 'Invalid typed recovery response')
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        require(False, 'Invalid typed recovery response; raw output withheld')
    require(isinstance(value, dict) and set(value) == {'type', 'data'}
            and value['type'] == 'a(sasbttttuii)' and value['data'] == [],
            'Omitted recovery property is not proven empty: ' + field)


def unit_properties(unit, names):
    response = run(['systemctl', 'show', unit, '--no-pager', '--all',
                    '--property=' + ','.join(names)], timeout=30)
    properties = {}
    for line in response.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key in names and (key not in properties or key == 'TimersMonotonic'),
                'Cannot establish the effective WhatsApp recovery unit')
        properties[key] = (properties[key] + ' ' + value) if key in properties else value
    missing = set(names) - set(properties)
    require(not missing or unit == RECOVERY_SERVICE and missing <= set(EMPTY_AUXILIARY),
            'Incomplete effective WhatsApp recovery unit')
    for field in names:
        if field in missing:
            require_empty_auxiliary(unit, field)
            properties[field] = ''
    return properties


def trusted_unit(properties, admin):
    require(properties['LoadState'] == 'loaded' and properties['NeedDaemonReload'] == 'no',
            'The dedicated WhatsApp recovery unit is absent or not loaded coherently')
    admin.trusted_path(Path(properties['FragmentPath']))
    for path in shlex.split(properties['DropInPaths']):
        admin.trusted_path(Path(path))


def same_attestation(actual, expected):
    return (isinstance(actual, dict) and actual == expected
            and all(type(actual[key]) is type(value) for key, value in expected.items()))


def verify_prerequisites(root):
    """Read-only attestation of the dedicated installed chain before any stop.

    This deliberately does not acquire the publication lock: callers already
    hold it. Both child checks attest the same immutable generation/owner epoch.
    There is no fallback to another project's scheduler or helper tree.
    """
    from installation_layout import preflight_roots
    preflight_roots()
    import release_admin as admin
    generation = admin.require_current(__file__)
    admin.trusted_path(admin.ENTRYPOINT)
    admin.trusted_path(admin.ENTRYPOINT.parent/'release_admin.py')
    response = json.loads(run([Path(root)/'.venv/bin/python', '-B', Path(root)/'scripts/backup_runtime.py',
                               '--check-recovery'], timeout=30))
    require(same_attestation(response, {**capabilities(), 'helper': str(generation.path/'release_backup.py')}),
            'Install the dedicated WhatsApp backup/recovery generation before publication')
    common = ['LoadState', 'NeedDaemonReload', 'FragmentPath', 'DropInPaths']
    timer = unit_properties(RECOVERY_TIMER, common + ['ActiveState', 'UnitFileState', 'Unit',
                                                     'TimersMonotonic'])
    trusted_unit(timer, admin)
    require(timer['ActiveState'] == 'active' and timer['UnitFileState'] == 'enabled',
            'The dedicated WhatsApp recovery timer must be active and enabled after boot')
    require(timer['Unit'] == RECOVERY_SERVICE, 'The WhatsApp recovery timer targets another service')
    # systemctl renders monotonic bases independently of their next deadline.
    # The timer must continue after each run as well as recover after boot.
    bases = re.findall(r'\{\s*(On[A-Za-z]+USec)=([^;]+);[^}]*\}', timer['TimersMonotonic'])
    require(len(bases) == 2 and dict((key, value.strip()) for key, value in bases)
            in ({'OnBootUSec': '45s', 'OnUnitInactiveUSec': '1min'},
                {'OnBootUSec': '45s', 'OnUnitInactiveUSec': '60s'}),
            'The effective WhatsApp recovery schedule differs from the reviewed boot/periodic cadence')
    service = unit_properties(RECOVERY_SERVICE, common + ['Type', 'User', 'ExecStart', 'ExecStartPre',
                              'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecCondition', 'KillMode',
                              'RemainAfterExit', 'Restart', 'RestartForceExitStatus', 'TimeoutStartUSec'])
    trusted_unit(service, admin)
    require(service['Type'] == 'oneshot' and service['User'] == 'root'
            and service['KillMode'] == 'control-group',
            'Unexpected dedicated WhatsApp recovery execution identity or process supervision')
    require(service['RemainAfterExit'] == 'no' and service['Restart'] == 'no'
            and not service['RestartForceExitStatus']
            and service['TimeoutStartUSec'] in ('10min', '600s'),
            'Dedicated recovery must finish for periodic retry and retain its bounded execution')
    require(all(not service[name] for name in ('ExecStartPre','ExecStartPost','ExecStop',
                                              'ExecStopPost','ExecCondition')),
            'Unexpected auxiliary commands in the WhatsApp recovery unit')
    expected = '/usr/bin/python3 -I -B ' + str(admin.ENTRYPOINT) + ' recovery'
    executable = re.findall(r'\bpath=([^;]+);', service['ExecStart'])
    commands = re.findall(r'\bargv\[\]=([^;]+);', service['ExecStart'])
    require([value.strip() for value in executable] == ['/usr/bin/python3']
            and [value.strip() for value in commands] == [expected],
            'The dedicated recovery service does not use the stable WhatsApp entrypoint')
    expected_response = {**capabilities(), 'project': 'whatsapp', 'generation': str(generation.path),
                         'epoch': generation.epoch, 'manifestSha256': generation.manifest_sha256,
                         'entrypoint': str(admin.ENTRYPOINT)}
    response = json.loads(run(['/usr/bin/python3', '-I', '-B', admin.ENTRYPOINT,
                               'recovery', '--check'], timeout=30))
    require(same_attestation(response, expected_response),
            'Dedicated recovery bootstrap and backup helper disagree on generation or capability')
    admin.require_current(__file__, expected=generation)
    return capabilities()

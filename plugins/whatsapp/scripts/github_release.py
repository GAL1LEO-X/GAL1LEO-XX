#!/usr/bin/env python3
"""Publish only the WhatsApp Python backend; preserve accounts and gateway state."""
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
import ast
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from github_release_common import ReleaseError, STATE, file_map, main, normalized, require, run, save, sha, version_key
from release_build import create_build, sandbox, seal, tree_hashes
from release_database import contract as migration_contract, migrate
from release_transaction import activate, dbpath, GATE, prepare_gate_directory, tenant, snapshot_registered
from tenant_database import run_database
from backup_validation import validate_snapshot
import release_transaction as transaction
import release_backup as backup_recovery

ROOT = Path(installation_path('/srv/openai-codex/projects/whatsapp-personal'))
BACKUPS = Path('/var/backups')


def literal(path, name):
    tree = ast.parse(Path(path).read_text(encoding='utf-8-sig'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name
                                                 for target in node.targets):
            return ast.literal_eval(node.value)
    raise ReleaseError('Missing backend version or database schema declaration')


def instances(root):
    registry = json.loads((root / 'private/tenants.json').read_text())
    result = []
    for slug, row in registry['instances'].items():
        require(re.fullmatch(r'[a-z][a-z0-9-]{1,19}', slug) is not None, 'Invalid registered instance')
        require(row['spec']['slug'] == slug, 'Instance registry is inconsistent')
        port = row['spec']['bridge_port']
        profile=installation_profile()
        if profile.compatibility:
            require('installation' not in row['spec'] and type(port) is int
                    and 8820 <= port <= 8998 and port % 2 == 0, 'Invalid legacy instance layout or port')
        else:
            require(row['spec'].get('installation')==profile.as_dict()
                    and type(port) is int and port==profile.instance_ports(slug)['bridge'],
                    'Registered installation identity or service port differs')
        auth_mode=row['spec'].get('auth_mode','managed-authelia')
        require(auth_mode in ('managed-authelia','external-oidc'), 'Unknown registered authentication mode')
        base = profile.service(slug)
        result.append({'slug': slug, 'unit': base + '.service', 'base': base, 'port': port, 'auth_mode':auth_mode,
                       'config': Path(profile.instance_paths(slug)['configuration']) / 'config.toml',
                       'wrapper': root / ('scripts/as-user' if slug == 'personal'
                                          else 'private/tenants/' + slug + '/as-user')})
    require(bool(result), 'No WhatsApp instances are registered')
    require(len({item['port'] for item in result}) == len(result), 'Instance ports overlap')
    return result


def require_restore_reconciled(registered):
    """Fail closed before preview/build or activation can replace gated code.

    A previous backend may not understand the external restore marker. Never
    infer clearance from unreadable metadata, a dangling link or malformed
    content: only physical absence in the existing configuration directory
    permits an update. The publication lease excludes cooperative restores.
    """
    for instance in registered:
        parent = Path(instance['config']).parent
        try:
            require(parent.is_absolute() and parent.resolve(strict=True) == parent,
                    'Restore maintenance location is not physical')
            parent.lstat()  # A missing/inaccessible configuration is unverified.
            marker = parent / 'restore-maintenance.json'
            try:
                marker.lstat()
            except FileNotFoundError:
                continue
        except (OSError, RuntimeError):
            raise ReleaseError('Restore maintenance state cannot be verified') from None
        raise ReleaseError('Restore maintenance requires reconciliation before a backend update')


def active(unit):
    return subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                          capture_output=True, timeout=15).returncode == 0


def verify_service_access(candidate, registered, *, state_markers=None):
    """Exercise real service identities without closing the gate or restarting."""
    prepare_gate_directory()
    probe = ('from pathlib import Path\nimport sys\n'
             'try: Path(sys.argv[1]).stat()\n'
             'except FileNotFoundError: pass\n'
             '(Path(sys.argv[2])/"sally_whatsapp/__init__.py").read_bytes()\n'
             'if len(sys.argv)>3: Path(sys.argv[3]).read_bytes()')
    for instance in registered:
        account = run(['systemctl', 'show', instance['unit'], '--property=User', '--value']).strip()
        require(bool(account) and account not in ('root', '0'), 'Bridge must use an explicit unprivileged account')
        marker=[str(state_markers[instance['slug']])] if state_markers else []
        run(['runuser', '-u', account, '--', str(candidate / '.venv/bin/python'),
             '-I', '-c', probe, str(GATE), str(candidate), *marker])


def verify_state_identity(instance, database_copy):
    """Registered 0.5.0 deployments require an external marker, checked on a copy.

    The conventional marker leaves the old 0.4.9 configuration loadable during
    the pre-activation backup/restart. Never query the live DB for this check.
    """
    config_path=Path(instance['config'])
    config=tomllib.loads(config_path.read_text())['bridge']
    marker=Path(config.get('state_identity_file') or config_path.parent/'technical-state.json')
    require(marker.is_absolute() and marker.is_file() and not marker.is_symlink()
            and not marker.resolve().is_relative_to(Path(config['database']).parent.resolve()),
            'Registered state identity marker must exist outside the database directory')
    info=marker.stat()
    require(info.st_uid==0 and not info.st_mode & 0o022 and info.st_size<=1024,
            'Registered state identity marker must be administrator-owned and protected')
    value=json.loads(marker.read_text())
    tenant=hashlib.sha256(json.dumps([config['owner_subject'],config['public_url'],config.get('session','default')],
                                   separators=(',',':')).encode()).hexdigest()
    require(isinstance(value,dict) and set(value)=={'protocol','id','tenant'}
            and type(value['protocol']) is int and value['protocol']==1 and isinstance(value['id'],str)
            and re.fullmatch('[0-9a-f]{32}',value['id']) and value['tenant']==tenant,
            'Registered state identity marker differs from the configured tenant')
    with closing(sqlite3.connect(Path(database_copy).as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
        row=db.execute('SELECT value FROM state WHERE key=?',('private:technical_state_identity:v1',)).fetchone()
    stored=json.loads(row[0]) if row is not None else None
    require(isinstance(stored,dict) and type(stored.get('protocol')) is int and stored==value,
            'Register and verify technical-state identity before deploying this candidate')
    return marker


def get_json(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return json.load(response)
    except (urllib.error.URLError, ValueError):
        raise ReleaseError('WhatsApp readiness check did not succeed') from None


def health(instance, version, maintenance=False, require_ready=False):
    require(active(instance['unit']), 'An expected WhatsApp bridge is not active')
    origin = 'http://127.0.0.1:' + str(instance['port'])
    result = get_json(origin + '/healthz')
    require(isinstance(result, dict) and result.get('process') == 'running' and result.get('version') == version,
            'WhatsApp backend version or process readiness does not match')
    if require_ready:
        readiness = result.get('readiness')
        require(isinstance(readiness, dict) and readiness.get('state') == 'ready'
                and readiness.get('ready') is True, 'WhatsApp application readiness has not succeeded')
        workers = readiness.get('workers')
        require(isinstance(workers, dict)
                and all(workers.get(name) is True for name in ('events', 'transfers', 'history', 'actions'))
                and ('portal' not in workers or workers['portal'] is True),
                'WhatsApp required workers are not ready')
    config_file = Path(instance['config'])
    config = tomllib.loads(config_file.read_text())['bridge']
    public_url = config['public_url']
    endpoint = urllib.parse.urlsplit(public_url)
    require(endpoint.scheme == 'https' and bool(endpoint.hostname)
            and endpoint.netloc == endpoint.hostname and not endpoint.path
            and not endpoint.query and not endpoint.fragment
            and not any(c.isspace() or ord(c)<32 or ord(c)==127 for c in public_url)
            and '\\' not in public_url,
            'Unexpected WhatsApp configured public endpoint')
    metadata = get_json(public_url + '/.well-known/oauth-protected-resource')
    require(metadata.get('resource') == public_url and metadata.get('authorization_servers') == [config['issuer']],
            'WhatsApp OAuth resource metadata changed')
    try:
        urllib.request.urlopen(urllib.request.Request(public_url + '/mcp',
                               headers={'Accept': 'text/event-stream'}), timeout=8)
    except urllib.error.HTTPError as response:
        require(response.code == (503 if maintenance else 401), 'Unexpected MCP maintenance or authentication status')
    else:
        raise ReleaseError('Anonymous MCP access unexpectedly succeeded')
    key = (config_file.parent / 'waha.key').read_text().strip()
    session_name = config.get('session', 'default')
    require(isinstance(session_name, str) and bool(session_name) and len(session_name) <= 200
            and not any(ord(char) < 32 or ord(char) == 127 for char in session_name),
            'Invalid configured WhatsApp session identity')
    session = get_json('http://127.0.0.1:' + str(gateway_port(instance['slug'],instance['port'])) +
                       '/api/sessions/' + urllib.parse.quote(session_name, safe=''),
                       {'X-Api-Key': key})
    require(isinstance(session, dict) and session.get('name', session_name) == session_name
            and session.get('status') in ('WORKING', 'STOPPED', 'STARTING', 'SCAN_QR_CODE', 'FAILED'),
            'Unexpected WhatsApp gateway session status')
    return session['status']


def queues_idle(selected):
    for instance in selected:
        try:
            run_database(tenant(instance),'idle')
        except subprocess.CalledProcessError:
            raise ReleaseError('WhatsApp has work in flight or its database safety check failed') from None


def wait_health(selected, version, previous, maintenance=False, require_ready=False):
    for attempt in range(30):
        try:
            result = {item['slug']: health(item, version, maintenance=maintenance,
                                         require_ready=require_ready) for item in selected}
            require(all(result[slug] == state for slug, state in previous.items()),
                    'A WhatsApp session changed status during publication')
            return result
        except ReleaseError:
            if attempt == 29:
                raise
            time.sleep(2)


def verify_backups(output, expected, *, auth_modes=None):
    if auth_modes is None: auth_modes={slug:'managed-authelia' for slug in expected}
    require(isinstance(auth_modes,dict) and set(auth_modes)==set(expected)
            and all(mode in ('managed-authelia','external-oidc') for mode in auth_modes.values()),
            'Invalid expected backup authentication modes')
    rows = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
    require(bool(expected) and len(expected) == len(set(expected)) and len(rows) == len(expected)
            and all(isinstance(row, dict) for row in rows)
            and {row.get('user') for row in rows} == set(expected),
            'Not all instances have exactly one completed backup')
    profile = installation_profile()
    if not profile.compatibility:
        require(set(expected) <= set(profile.accounts()),
                'Backup instance is absent from the installation profile')
    paths = []
    for row in rows:
        require(row.get('complete') is True, 'A runtime backup is incomplete')
        directory = Path(row['backup'])
        if profile.compatibility:
            require(not directory.is_symlink() and directory.resolve().is_relative_to(BACKUPS.resolve()),
                    'Unexpected backup directory')
        else:
            # Match the configured backup writer's per-tenant destination.
            # Resolving a symlink must not adopt another tenant or a new root.
            snapshots = Path(profile.path('backup')) / row['user'] / 'snapshots'
            require(directory.is_absolute() and directory == directory.resolve()
                    and snapshots == snapshots.resolve() and directory.parent == snapshots,
                    'Unexpected configured backup directory')
        directory = directory.resolve()
        require(str(directory) not in paths, 'Backup directory reused for multiple instances')
        try:
            mode=auth_modes[row['user']]
            validate_snapshot(directory, row['user'], **({'auth_mode':mode} if mode=='external-oidc' else {}))
        except (ValueError, OSError, sqlite3.Error):
            raise ReleaseError('Runtime backup validation failed; inspect the private snapshot') from None
        paths.append(str(directory))
    return paths


def backup_components(registered):
    """Snapshot activity while holding the same lock as suspension/provisioning."""
    components = []
    for item in registered:
        for kind, command, unit, port in [
            ('gateway', [str(item['wrapper']), 'systemctl', '--user'], 'whatsapp-waha.service', gateway_port(item['slug'],item['port'])),
            ('bridge', ['systemctl'], item['unit'], item['port']),
        ]:
            state = subprocess.run([*command, 'is-active', '--quiet', unit], capture_output=True, timeout=15)
            require(state.returncode in (0, 3, 4), 'Cannot establish backup service activity')
            components.append({'name': item['slug'] + '.' + kind, 'kind': kind, 'command': command,
                               'unit': unit, 'port': port, 'config': item['config'],
                               'active': state.returncode == 0})
    return components


def run_backup_process(command, root, lock_fd, *, timeout=900, grace=60):
    """Terminate the whole backup group, allowing its finally a bounded grace."""
    process = subprocess.Popen(list(map(str, command)), cwd=root, pass_fds=(lock_fd,),
                               start_new_session=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        output, _ = process.communicate(timeout=timeout)
        require(process.returncode == 0, 'The runtime backup failed')
        return output
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=grace)
        except subprocess.TimeoutExpired:
            pass
        finally:
            # Also terminate descendants whose leader exited and closed its
            # pipes already. They must not outlive the held administration lock.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=15)
        raise ReleaseError('The runtime backup failed or was interrupted') from None


def restore_backup_components(components, version, *, lock_fd=None):
    """Independent starts and readiness checks; never enable a stopped account."""
    failures = []
    running = [item for item in components if item['active']]
    for item in running:
        try:
            run([*item['command'], 'start', item['unit']], timeout=60,
                **({'pass_fds': (lock_fd,)} if lock_fd is not None else {}))
        except Exception:
            failures.append(item['name'] + '.start')
    for item in running:
        try:
            for attempt in range(30):
                try:
                    state = subprocess.run([*item['command'], 'is-active', '--quiet', item['unit']],
                                           capture_output=True, timeout=15,
                                           **({'pass_fds': (lock_fd,)} if lock_fd is not None else {}))
                    require(state.returncode == 0, 'Service has not recovered')
                    gateway = item['kind'] == 'gateway'
                    headers = {'X-Api-Key': (item['config'].parent / 'waha.key').read_text().strip()} if gateway else None
                    data = get_json('http://127.0.0.1:' + str(item['port']) +
                                    ('/api/version' if gateway else '/healthz'), headers)
                    require(isinstance(data, dict) and (gateway or
                            (data.get('process') == 'running' and data.get('version') == version)),
                            'Service readiness has not recovered')
                    if not gateway and version_key(version) >= version_key('0.4.0'):
                        readiness=data.get('readiness',{})
                        require(readiness.get('state') == 'ready' and readiness.get('ready') is True
                                and all(readiness.get('workers',{}).get(name) is True
                                        for name in ('events','transfers','history','actions'))
                                and ('portal' not in readiness.get('workers',{})
                                     or readiness['workers']['portal'] is True),
                                'Backup service workers have not recovered')
                    break
                except Exception:
                    if attempt == 29:
                        raise
                    time.sleep(1)
        except Exception:
            failures.append(item['name'] + '.readiness')
    return failures


def runtime_backups(root, registered, lock_fd, version):
    import release_admin as administration
    generation = administration.require_current(__file__)
    backup_recovery.verify_prerequisites(root)
    components = backup_components(registered)
    plan = backup_recovery.begin(root, registered, components, version)
    try:
        pin = {'epoch': generation.epoch, 'path': str(generation.path), 'manifest': generation.manifest_sha256}
        output = run_backup_process([root / '.venv/bin/python', '-B', root / 'scripts/backup_runtime.py',
                                     '--all', '--lock-fd', str(lock_fd), '--recovery-id', plan['id'],
                                     '--admin-pin', json.dumps(pin, separators=(',', ':'))], root, lock_fd)
        paths = verify_backups(output, [item['slug'] for item in registered],
                               auth_modes={item['slug']:item.get('auth_mode','managed-authelia') for item in registered})
        recovered = backup_recovery.recover(root, registered,
                    lambda parts, old_version: restore_backup_components(parts, old_version, lock_fd=lock_fd))
        require(recovered is not None and recovered['id'] == plan['id']
                and recovered['servicesRestored']
                and all(item['complete'] for item in recovered['copies'].values()),
                'Backup completion or service recovery was not durably confirmed')
        return paths
    except BaseException:
        backup_recovery.recover(root, registered,
                    lambda parts, old_version: restore_backup_components(parts, old_version, lock_fd=lock_fd))
        raise ReleaseError('Backup failed; previously active components restored and verified') from None


def pending_publication(root, target, candidate_hashes, current_hashes):
    path = STATE / 'whatsapp/pending.json'
    if not path.exists():
        return None
    pending = json.loads(path.read_text())
    require(pending.get('commit') == target['commit'] and pending.get('filesSha256') == candidate_hashes,
            'An unfinished publication must be reconciled using its original release')
    record = Path(pending['previousCode'])
    require(record.resolve().parent == (root / 'work').resolve() and record.is_dir(),
            'Invalid unfinished publication record')
    if current_hashes == pending['previousHashes']:
        # No activation, or a completed code rollback: retry from fresh backups.
        path.unlink()
        return None
    require(current_hashes == candidate_hashes, 'Unfinished publication has inconsistent active files; inspect recovery')
    return record


def record_publication(target, candidate_hashes, record_dir=None):
    """The durable pending record survives any failure in final bookkeeping."""
    try:
        if record_dir is not None:
            save(record_dir / 'result.json', {'status': 'published', 'sourceCommit': target['commit']})
        current = STATE / 'whatsapp/current.json'
        try:
            previous = json.loads(current.read_text()) if current.exists() else {}
        except (ValueError, UnicodeError):
            previous = {}
        if not isinstance(previous, dict) or previous.get('filesSha256') != candidate_hashes:
            previous = {}
        save(current, {**target, 'filesSha256': candidate_hashes,
                       'previousCode': str(record_dir) if record_dir else previous.get('previousCode'),
                       'version': target['version']})
        (STATE / 'whatsapp/pending.json').unlink(missing_ok=True)
    except Exception:
        raise ReleaseError('Backend is active but publication records are incomplete; retry the same release to reconcile') from None


def build_backend(source):
    """Install a fresh venv in its final path; a venv must never be relocated."""
    migration_contract(source)
    package = tomllib.loads((source/'pyproject.toml').read_text())
    pinned = re.compile(r'[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+')
    runtime = [line.split(';', 1)[0].strip() for line in (source/'requirements.lock').read_text().splitlines()
               if line.strip() and not line.lstrip().startswith('#')]
    require(all(pinned.fullmatch(line) for line in runtime), 'Python dependencies must be pinned package versions')
    build_requirements = package['build-system']['requires']
    require(all(pinned.fullmatch(line) for line in build_requirements), 'Python build dependencies must be pinned')
    def distribution(requirement):
        match = re.match(r'[A-Za-z0-9_.-]+(?=\[|[<>=!~; @]|$)', requirement.strip())
        require(match is not None, 'Invalid declared Python dependency')
        return re.sub(r'[-_.]+', '-', match.group()).lower()
    build_names = {distribution(item) for item in build_requirements}
    require(build_names == {'setuptools'}, 'Only the reviewed setuptools build tool may be removed from the runtime')
    runtime_names = {distribution(item) for item in [*runtime, *package['project'].get('dependencies', [])]}
    require(build_names.isdisjoint(runtime_names), 'Build tools must not also be declared runtime dependencies')
    directory = create_build('whatsapp', source, ['sally_whatsapp','pyproject.toml','requirements.lock','deploy'])
    sandbox(directory, ['/usr/bin/python3','-m','venv','--copies',str(directory/'.venv')], timeout=90)
    python = directory/'.venv/bin/python'
    pip = [str(python),'-m','pip','--isolated','--disable-pip-version-check']
    sandbox(directory, [*pip,'install','--no-cache-dir','--no-deps','-r',str(directory/'requirements.lock'),*build_requirements], network=True, timeout=480)
    sandbox(directory, [*pip,'install','--no-cache-dir','--no-deps','--no-build-isolation',str(directory)], network=True, timeout=180)
    # setuptools is required only to build the installed package. Its executable
    # distutils .pth is incompatible with the administrative import admission.
    # Remove only this declared build tool; never reconcile/delete lock entries.
    sandbox(directory, [*pip,'uninstall','--yes','setuptools'], timeout=90)
    sandbox(directory, [*pip,'check'], timeout=90)
    return directory


def probe_databases(candidate, databases):
    import pwd
    import uuid
    import release_admin as administration
    generation=administration.require_current(__file__)
    helpers={}
    for name in ('release_probe.py','release_runtime.py','installation_layout.py'):
        source=Path(__file__).with_name(name)
        administration.require_current(source,expected=generation)
        content=source.read_bytes()
        require(hashlib.sha256(content).hexdigest()==generation.files[name],
                'Admitted database probe helper changed during capture')
        helpers[name]=content
    administration.require_current(__file__,expected=generation)
    account=pwd.getpwnam(installation_path('develative-release-build'))
    checks=candidate/('.database-check-'+uuid.uuid4().hex)
    checks.mkdir(mode=0o700)
    copies=[]
    try:
        os.chown(checks,account.pw_uid,account.pw_gid)
        for name,content in helpers.items():
            target=checks/name
            target.write_bytes(content);target.chmod(0o600)
            os.chown(target,account.pw_uid,account.pw_gid)
        for index,database in enumerate(databases):
            copy=checks/(str(index)+'.sqlite')
            shutil.copyfile(database,copy);copy.chmod(0o600)
            os.chown(copy,account.pw_uid,account.pw_gid);copies.append(copy)
        # The build namespace hides arbitrary host administration roots. Only
        # these captured admitted bytes accompany the private database copies.
        probe=checks/'release_probe.py'
        result=json.loads(sandbox(candidate,[str(candidate/'.venv/bin/python'),'-B',str(probe),*map(str,copies)],timeout=120).splitlines()[-1])
        require(result.get('passed') is True and result.get('workersGated') is True,'Candidate maintenance and database probe failed')
        return result
    finally:
        # These contain private database copies: remove before sealing/public read permissions.
        shutil.rmtree(checks)


def publish(checkout, target, config):
    import fcntl
    root = ROOT
    registered = instances(root)
    require_restore_reconciled(registered)
    source = checkout / 'plugins/whatsapp'
    version = literal(source / 'sally_whatsapp/__init__.py', '__version__')
    package = tomllib.loads((source / 'pyproject.toml').read_text())
    require(version == package['project']['version'] == target['version'], 'Tag and WhatsApp backend version do not match')
    old_version = literal(root / 'sally_whatsapp/__init__.py', '__version__')
    candidate_hashes, previous_hashes = file_map(source / 'sally_whatsapp'), file_map(root / 'sally_whatsapp')
    same = (candidate_hashes == previous_hashes
            and normalized(source/'requirements.lock') == normalized(root/'requirements.lock')
            and normalized(source/'pyproject.toml') == normalized(root/'pyproject.toml'))
    version_eligible = same or version_key(version) > version_key(old_version)
    require(target['dryRun'] or version_eligible,
            'A changed WhatsApp backend must use a version newer than the active one')
    selected = [item for item in registered if active(item['unit'])]
    require(bool(selected), 'No active WhatsApp bridge can be verified')
    reconciling = same and not target['dryRun'] and (STATE/'whatsapp/pending.json').exists()
    # A committed candidate can legitimately return MCP 503 until readiness.
    # Reconciliation uses its durable pre-activation gateway snapshot below,
    # instead of requiring ordinary admission before recovery can run.
    before = {} if reconciling else {item['slug']: health(item, old_version) for item in selected}
    registry_hash = sha(root / 'private/tenants.json')
    configuration_hashes = {str(item['config']): sha(item['config']) for item in registered}
    candidate=build_backend(source)
    migrations=[]; copies=[]; state_markers={}
    with tempfile.TemporaryDirectory(prefix='database-preview-',dir=checkout.parent) as temporary:
        preview=Path(temporary)
        for item in registered:
            copy=preview/(item['slug']+'.sqlite')
            snapshot_registered(item,copy)
            migrations.append(migrate(copy,source)); copies.append(copy)
            if version_key(version)>=version_key('0.5.0'):
                marker=verify_state_identity(item,copy)
                state_markers[item['slug']]=marker
                configuration_hashes[str(marker)]=sha(marker)
        runtime_probe=probe_databases(candidate,copies)
    sealed=seal(candidate)
    save(STATE/'whatsapp/builds'/(candidate.name+'.json'),{'files':sealed,'sourceCommit':target['commit']})
    require(file_map(source/'sally_whatsapp')==file_map(candidate/'sally_whatsapp'),'Build changed backend source')
    if state_markers:verify_service_access(candidate,registered,state_markers=state_markers)
    else:verify_service_access(candidate,registered)
    result = {'status': 'verified', 'activeVersion': old_version, 'instances': len(registered),
              'activeInstances': len(selected), 'alreadyActive': same, 'activationPerformed': False,
              'versionEligible': version_eligible,
              'buildDirectory':str(candidate),'buildFiles':len(sealed),'migrations':migrations,'runtimeValidation':runtime_probe,
              'checks': ['CI', 'new pinned dependency installation', 'pip check', 'database migration on copies', 'maintenance and worker gate', 'service account filesystem access', 'process', 'OAuth metadata', 'anonymous MCP challenge', 'gateway session status']}
    if target['dryRun']:
        return result
    with (root / 'private/tenant-admin.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require_restore_reconciled(registered)
        require(sha(root / 'private/tenants.json') == registry_hash, 'Instance registry changed during preparation')
        require(all(sha(path) == digest for path, digest in configuration_hashes.items()),
                'Instance configuration changed during preparation')
        require(file_map(root / 'sally_whatsapp') == previous_hashes, 'Backend changed during preparation')
        require([item['unit'] for item in registered if active(item['unit'])] == [item['unit'] for item in selected],
                'Instance activity changed during preparation')
        pending = pending_publication(root, target, candidate_hashes, previous_hashes)
        if same:
            if pending is not None:
                require(transaction.JOURNAL.exists(), 'Unfinished activation journal is missing; inspect recovery')
                plan = json.loads(transaction.JOURNAL.read_text())
                require(plan.get('phase') in transaction.COMMITTED_PHASES
                        and plan.get('sourceCommit') == target['commit']
                        and plan.get('version') == version
                        and Path(plan.get('root', '')).resolve() == root.resolve()
                        and Path(plan.get('record', '')).resolve() == (pending/'transaction').resolve()
                        and set(plan.get('activeUnits', [])) == {item['unit'] for item in selected},
                        'Unfinished activation journal does not match; inspect recovery')
                transaction.recover(plan, wait_health, lock_fd=lock.fileno())
            else:
                # An unchanged legacy release may predate the readiness contract.
                if not before:
                    before = {item['slug']: health(item, old_version) for item in selected}
                wait_health(selected, old_version, before)
            record_publication(target, candidate_hashes, pending)
            return {**result, 'status': 'already-active', 'recordsReconciled': True}
        # Undo records need this receiver-only directory after backup/recovery.
        # Prepare it under the admitted generation and tenant lock first, so a
        # missing or unsafe parent cannot cause an unnecessary service cycle.
        import release_admin as administration
        administration.require_current(__file__)
        work = administration.trusted_path(root, directory=True) / 'work'
        try:
            work.mkdir(mode=0o700)
        except FileExistsError:
            pass
        administration.trusted_path(work, directory=True)
        wait_health(selected, old_version, before)
        queues_idle(selected)
        backups = runtime_backups(root, registered, lock.fileno(), old_version)
        wait_health(selected, old_version, before)
        queues_idle(selected)
        require(tree_hashes(candidate)==sealed,'Prepared backend or dependency files changed')
        record_dir = work / ('github-release-' + str(time.time_ns()))
        record_dir.mkdir(mode=0o700)
        save(record_dir / 'plan.json', {'sourceCommit': target['commit'], 'version': version,
             'previousVersion': old_version, 'previousHashes': previous_hashes,
             'candidateHashes': candidate_hashes, 'backups': backups,
             'activeUnits': [item['unit'] for item in selected]})
        save(STATE / 'whatsapp/pending.json', {**target, 'filesSha256': candidate_hashes,
             'previousHashes': previous_hashes, 'previousCode': str(record_dir), 'status': 'activation-pending'})
        transaction_dir=record_dir/'transaction'
        activate(root,candidate,registered,selected,before,old_version,version,transaction_dir,
                 wait_health,queues_idle,lambda copies:probe_databases(candidate,copies),
                 source_commit=target['commit'],lock_fd=lock.fileno())
        record_publication(target, candidate_hashes, record_dir)
    return {**result, 'status': 'published', 'activeVersion': version,
            'activationPerformed': True, 'backupCount': len(backups)}


def receive():
    # main admits the owner and validates the request before inspecting
    # tenant paths, then repeats this gate under the publication lease.
    main('whatsapp', publish,
         preflight=lambda: require_restore_reconciled(instances(ROOT)))


if __name__ == '__main__':
    receive()

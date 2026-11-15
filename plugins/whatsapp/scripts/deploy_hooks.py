#!/usr/bin/env python3
"""WhatsApp-only hooks for the new deploy engine, installed outside app packages.

Only ordinary schema-8 backend changes are admitted. A separately reviewed
host profile and cutover are required; this file never provisions an account,
changes a grant, migrates the installed layout, or repairs an unknown state.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

CONFIG = Path('/etc/whatsapp/deploy-hooks.json')
PHASES = {'prepare', 'maintenance', 'backup', 'migrate', 'activate', 'health', 'restore', 'reopen'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def http_open(request):
    # A local gateway key must never follow a redirect or an ambient HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    return opener.open(request, timeout=8)


def require(value, code):
    if not value:
        raise ValueError(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def save(path, value, mode=0o600):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + os.urandom(8).hex() + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded(value)); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); fsync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def protected(path, *, file=True):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'invalid_protected_path')
    for parent in [*reversed(path.parents), path]:
        item = parent.lstat()
        require(not stat.S_ISLNK(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o022,
                'unprotected_administrative_path')
    if file:
        item = path.stat()
        require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1, 'invalid_administrative_file')
    return path


def command(args, *, uid=None, gid=None, input=None):
    options = {'cwd': '/', 'env': {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                                   'PIP_CONFIG_FILE': '/dev/null', 'PIP_DISABLE_PIP_VERSION_CHECK': '1'},
               'check': True, 'capture_output': True, 'text': True, 'timeout': 180, 'input': input}
    if uid is not None:
        require(uid > 0 and gid > 0, 'application_identity_must_be_unprivileged')
        options.update(user=uid, group=gid, extra_groups=[])
    return subprocess.run(list(map(str, args)), **options)


def validate_config(config):
    require(config.get('format') == 'whatsapp-deploy-profile-v1' and config.get('cutover_verified') is True,
            'reviewed_cutover_profile_required')
    require(config.get('app') == 'whatsapp' and config.get('target_id') == 'gal1leo-server-01', 'wrong_target')
    require(config.get('schema') == 8, 'only_reviewed_schema_8_is_supported')
    require(re.fullmatch('[0-9a-f]{64}', config.get('provider_policy_sha256', '')), 'provider_policy_pin_required')
    for name in ('engine_root', 'gate', 'current', 'runtime_entrypoint', 'tenant_helper', 'python'):
        require(isinstance(config.get(name), str) and re.fullmatch('/[A-Za-z0-9_./-]+', config[name])
                and '..' not in Path(config[name]).parts, 'literal_host_path_required')
    require(Path(config['current']).parent == Path(config['engine_root']), 'current_must_belong_to_deploy_root')
    require(config['python'] == '/usr/bin/python3.13', 'reviewed_system_python_required')
    require(type(config.get('build_uid')) is int and config['build_uid'] > 0
            and type(config.get('build_gid')) is int and config['build_gid'] > 0, 'build_identity_required')
    instances = config.get('instances')
    require(isinstance(instances, list) and len(instances) >= 2, 'all_registered_instances_required')
    for item in instances:
        require(set(item) == {'slug', 'user', 'uid', 'gid', 'unit', 'config', 'database', 'port', 'gateway_port', 'provider_state'},
                'invalid_instance_fields')
        require(re.fullmatch('[a-z][a-z0-9-]{1,19}', item['slug'])
                and re.fullmatch('[a-z][a-z0-9_-]{0,30}', item['user'])
                and re.fullmatch(r'[a-z][a-z0-9-]{1,63}\.service', item['unit']), 'invalid_instance_identity')
        require(type(item['uid']) is int and item['uid'] > 0 and type(item['gid']) is int and item['gid'] > 0,
                'invalid_instance_uid')
        require(all(type(item[key]) is int and 1024 <= item[key] <= 65535 for key in ('port', 'gateway_port')),
                'invalid_instance_port')
        for key in ('config', 'database', 'provider_state'):
            require(re.fullmatch('/[A-Za-z0-9_./-]+', item[key]) and '..' not in Path(item[key]).parts,
                    'invalid_instance_path')
        require(Path(item['database']).name == 'archive.sqlite', 'unexpected_database_name')
    for field in ('slug', 'uid', 'gid', 'unit', 'config', 'database', 'provider_state'):
        require(len({item[field] for item in instances}) == len(instances), 'instance_identity_overlap')
    require(config['build_uid'] not in {item['uid'] for item in instances}, 'build_identity_is_a_tenant')
    require(config['build_gid'] not in {item['gid'] for item in instances}, 'build_group_is_a_tenant')
    return config


def seal_runtime(root):
    """Seal descriptors, never chown a symlink or an attacker-selected ancestor.

The preceding transient systemd service must have stopped its entire cgroup.
Files with extra hard links are not promoted into the administrative runtime.
"""
    def walk(descriptor):
        os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o755)
        for name in os.listdir(descriptor):
            item = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(item.st_mode):
                # venv --copies needs only its conventional lib64 -> lib link.
                require(name == 'lib64' and os.readlink(name, dir_fd=descriptor) == 'lib', 'unexpected_runtime_symlink')
                os.chown(name, 0, 0, dir_fd=descriptor, follow_symlinks=False)
                continue
            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0)
            if stat.S_ISDIR(item.st_mode): flags |= os.O_DIRECTORY
            child = os.open(name, flags, dir_fd=descriptor)
            try:
                pinned = os.fstat(child)
                require((pinned.st_dev, pinned.st_ino) == (item.st_dev, item.st_ino), 'runtime_changed_during_seal')
                if stat.S_ISDIR(pinned.st_mode):
                    walk(child)
                else:
                    require(stat.S_ISREG(pinned.st_mode) and pinned.st_nlink == 1, 'runtime_contains_special_or_linked_file')
                    os.fchown(child, 0, 0); os.fchmod(child, 0o755 if pinned.st_mode & 0o111 else 0o644); os.fsync(child)
            finally:
                os.close(child)
        os.fsync(descriptor)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: walk(fd)
    finally: os.close(fd)


def require_build_idle(uid, proc=Path('/proc')):
    # Check every kernel UID (real/effective/saved/filesystem), rather than a
    # single procfs owner. Never inspect argv/environment before sealing output.
    for path in proc.iterdir():
        if path.name.isdecimal():
            try:
                with (path / 'status').open('rb') as stream:
                    fields = next((line.split()[1:] for line in stream if line.startswith(b'Uid:')), None)
            except (FileNotFoundError, ProcessLookupError):
                if not path.exists(): continue  # The process exited during observation.
                raise ValueError('build_identity_process_inspection_incomplete') from None
            except OSError:
                raise ValueError('build_identity_process_inspection_incomplete') from None
            require(fields is not None and len(fields) == 4 and all(value.isdigit() for value in fields),
                    'build_identity_process_inspection_incomplete')
            require(uid not in {int(value) for value in fields}, 'build_identity_has_surviving_processes')


def runtime_inventory(root, *, trusted_uid=0):
    root = Path(root)
    records = []
    for path in [root, *sorted(root.rglob('*'))]:
        relative = path.relative_to(root).as_posix()
        if relative == 'qualified.json': continue
        item = path.lstat()
        require(item.st_uid == trusted_uid and (stat.S_ISLNK(item.st_mode) or not item.st_mode & 0o022),
                'runtime_is_not_sealed')
        if stat.S_ISLNK(item.st_mode):
            require(relative == 'venv/lib64' and os.readlink(path) == 'lib', 'unexpected_runtime_symlink')
            records.append({'path': relative, 'link': 'lib'})
        elif stat.S_ISDIR(item.st_mode):
            records.append({'path': relative, 'directory': True, 'mode': stat.S_IMODE(item.st_mode)})
        else:
            require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1, 'invalid_runtime_file')
            records.append({'path': relative, 'size': item.st_size, 'mode': stat.S_IMODE(item.st_mode), 'sha256': sha(path)})
    return records


def qualified_runtime(path, release):
    path = Path(path)
    proof = json.loads(protected(path / 'qualified.json').read_bytes())
    require(set(proof) == {'commit', 'package_sha256', 'files'}
            and proof['commit'] == release['commit'] and proof['package_sha256'] == release['package_sha256'],
            'runtime_qualification_identity_mismatch')
    require(proof['files'] == runtime_inventory(path), 'qualified_runtime_changed')
    return True


def verify_snapshot(source, expected, uid, gid, python):
    """Read an admitted snapshot under the tenant UID without exposing its path.

The child receives only a read-only descriptor, validates a private copy and
prints nothing. It never queries the possibly corrupted live database.
"""
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'invalid_snapshot_descriptor')
        script = ('import os,json,sqlite3,tempfile,shutil\nfrom pathlib import Path\n'
                  'from contextlib import closing\n'
                  'with tempfile.TemporaryDirectory(prefix="whatsapp-snapshot-") as temporary:\n'
                  ' path=Path(temporary)/"archive.sqlite"\n'
                  ' with os.fdopen(' + str(fd) + ',"rb") as source,path.open("wb") as target: shutil.copyfileobj(source,target)\n'
                  ' with closing(sqlite3.connect(path.as_uri()+"?mode=ro&immutable=1",uri=True)) as db:\n'
                  '  assert db.execute("PRAGMA integrity_check").fetchall()==[("ok",)]\n'
                  '  assert not db.execute("PRAGMA foreign_key_check").fetchall()\n'
                  '  assert db.execute("PRAGMA user_version").fetchone()[0]==8\n'
                  '  value=db.execute("SELECT value FROM state WHERE key=?",("private:technical_state_identity:v1",)).fetchone()\n'
                  '  assert value is not None and json.loads(value[0])==' + repr(expected) + '\n')
        require(uid > 0 and gid > 0, 'snapshot_validation_identity_must_be_unprivileged')
        subprocess.run([python, '-I', '-B', '-'], input=script.encode(), pass_fds=(fd,),
                       user=uid, group=gid, extra_groups=[], env={}, cwd='/',
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=90)
    finally:
        os.close(fd)


class Adapter:
    def __init__(self, config, context, *, host=True):
        self.config, self.context, self.host = validate_config(config), context, host
        require(context.get('app') == 'whatsapp' and context.get('target_id') == config['target_id'], 'context_target_mismatch')
        require(context.get('format') == 'deploy-context-v1', 'context_format_mismatch')
        require(re.fullmatch('[a-f0-9]{32,64}', context.get('operation_id', '')), 'invalid_operation_id')
        require(context.get('phase') in PHASES and type(context.get('committed')) is bool, 'invalid_context_phase')
        require(context.get('schema_after') == 8 and context.get('schema_before') == 8,
                'schema_change_requires_separate_reviewed_migration')
        self.root = Path(config['engine_root'])
        self.operation = self.root / 'operations' / context['operation_id']
        require(Path(context['operation_dir']) == self.operation, 'operation_directory_mismatch')
        self.release = context['release']
        self.release_path = Path(self.release['path'])
        require(self.release_path.parent == self.root / 'releases'
                and self.release_path.name == self.release['id'] and re.fullmatch('[a-f0-9]{64}', self.release['id']),
                'release_directory_mismatch')
        require(self.release['manifest']['app'] == 'whatsapp' and self.release['manifest']['data'] == {'schema': 8, 'readable_schemas': [8]},
                'release_contract_mismatch')
        require(self.release['commit'] == self.release['manifest']['commit']
                and re.fullmatch('[a-f0-9]{40}', self.release['commit'])
                and self.release['package_sha256'] == self.release['id'], 'release_identity_mismatch')
        self.gate, self.current = Path(config['gate']), Path(config['current'])
        self.instances = config['instances']
        self.state_path = self.operation / 'whatsapp-hooks.json'
        if host:
            require(os.geteuid() == 0, 'administrative_entrypoint_requires_root')
            protected(self.root, file=False); protected(self.operation, file=False)
            protected(self.release_path, file=False)
            protected(config['runtime_entrypoint']); protected(config['tenant_helper']); protected(config['python'])
            if self.state_path.exists(): protected(self.state_path)
        self.state = json.loads(self.state_path.read_bytes()) if self.state_path.exists() else {
            'operation_id': context['operation_id'], 'config_sha256': hashlib.sha256(encoded(config)).hexdigest(), 'steps': {}}
        require(self.state['operation_id'] == context['operation_id']
                and self.state['config_sha256'] == hashlib.sha256(encoded(config)).hexdigest(), 'hook_profile_drift')

    def tenant_helper(self):
        spec = importlib.util.spec_from_file_location('whatsapp_deploy_tenant', self.config['tenant_helper'])
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def tenant(self, helper, item):
        import pwd
        account = pwd.getpwnam(item['user'])
        require((account.pw_uid, account.pw_gid) == (item['uid'], item['gid']), 'tenant_uid_drift')
        require(command(['systemctl', 'show', item['unit'], '--property=User', '--value']).stdout.strip() == item['user'],
                'unit_identity_drift')
        parent = Path(item['config']).parent
        require(not (parent / 'restore-maintenance.json').exists(), 'existing_restore_requires_reconciliation')
        return helper.registered_tenant(item['config'], item['database'], item['user'])

    def config_identity(self):
        result = {}
        helper = self.tenant_helper()
        for item in self.instances:
            tenant = self.tenant(helper, item)
            helper.run_database(tenant, 'verify')
            result[item['slug']] = self.configuration_files(item)
        return result

    def configuration_files(self, item):
        path = protected(item['config'])
        config = tomllib.loads(path.read_text())['bridge']
        marker = Path(config.get('state_identity_file') or path.parent / 'technical-state.json')
        return {'configuration': sha(path), 'identity': sha(protected(marker))}

    def verify_identity(self):
        if 'identity' in self.state:
            require(self.config_identity() == self.state['identity'], 'tenant_configuration_changed')

    def active(self, item):
        result = subprocess.run(['systemctl', 'is-active', '--quiet', item['unit']], capture_output=True, timeout=15)
        return result.returncode == 0

    def gate_on(self):
        protected(self.gate.parent, file=False)
        save(self.gate, {'operation_id': self.context['operation_id']}, 0o644)

    def all_stopped(self):
        return all(not self.active(item) for item in self.instances)

    def prepare(self):
        provider = json.loads((self.release_path / 'payload/provider-reference.json').read_bytes())
        require(provider['policy_sha256'] == self.config['provider_policy_sha256'], 'provider_change_requires_separate_operation')
        self.state['identity'] = self.config_identity()
        self.state['active'] = [item['unit'] for item in self.instances if self.active(item)]
        require(len(self.state['active']) == len(self.instances), 'all_instances_must_be_healthy_before_ordinary_update')
        self.state['sessions'] = {item['slug']: self.session(item) for item in self.instances}
        save(self.state_path, self.state)
        runtime = self.release_path / 'runtime'; runtime.mkdir(exist_ok=True, mode=0o755)
        require(not runtime.is_symlink(), 'runtime_must_be_physical')
        if any(runtime.iterdir()):
            qualified_runtime(runtime, self.release)
            return  # Retained package after rollback: reuse, never erase/reinstall.
        require_build_idle(self.config['build_uid'])
        os.chown(runtime, self.config['build_uid'], self.config['build_gid'])
        venv = runtime / 'venv'; payload = self.release_path / 'payload'
        self.build_command('venv', [self.config['python'], '-I', '-m', 'venv', '--copies', venv], runtime)
        python = venv / 'bin/python'
        self.build_command('install', [python, '-I', '-m', 'pip', 'install', '--no-index', '--only-binary=:all:', '--require-hashes',
                           '--find-links', payload / 'wheelhouse', '--requirement', payload / 'requirements.lock'], runtime)
        self.build_command('check', [python, '-I', '-m', 'pip', 'check'], runtime)
        self.build_command('import', [python, '-I', '-c', 'import sally_whatsapp, sally_whatsapp.server; assert sally_whatsapp.__version__ == '
                           + repr(self.release['manifest']['version'])], runtime)
        # Once qualified, neither build UID nor tenants may replace runtime bytes.
        require_build_idle(self.config['build_uid'])
        seal_runtime(runtime)
        save(runtime / 'qualified.json', {'commit': self.release['commit'], 'package_sha256': self.release['package_sha256'],
                                        'files': runtime_inventory(runtime)}, 0o644)

    def build_command(self, stage, args, runtime):
        # All application/.pth execution runs in a transient unprivileged cgroup.
        # KillMode removes any surviving children before root seals their output.
        unit = 'whatsapp-deploy-' + self.context['operation_id'] + '-' + stage
        properties = {'User': self.config['build_uid'], 'Group': self.config['build_gid'],
                      'SupplementaryGroups': '', 'PrivateNetwork': 'yes', 'ProtectSystem': 'strict',
                      'ProtectHome': 'yes', 'PrivateTmp': 'yes', 'PrivateDevices': 'yes',
                      'NoNewPrivileges': 'yes', 'RestrictSUIDSGID': 'yes', 'CapabilityBoundingSet': '',
                      'AmbientCapabilities': '', 'KillMode': 'control-group', 'RuntimeMaxSec': '150',
                      'WorkingDirectory': runtime, 'ReadWritePaths': runtime, 'UMask': '0022'}
        command(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + unit,
                 *['--property=' + key + '=' + str(value) for key, value in properties.items()],
                 '--setenv=PIP_CONFIG_FILE=/dev/null', '--setenv=PIP_NO_INDEX=1', '--', *args])

    def maintenance(self):
        self.verify_identity()
        # A rollback has no prepare phase; capture its current instances first.
        if 'active' not in self.state:
            self.state['identity'] = self.config_identity()
            self.state['active'] = [item['unit'] for item in self.instances if self.active(item)]
            require(len(self.state['active']) == len(self.instances), 'all_instances_must_be_active')
            self.state['sessions'] = {item['slug']: self.session(item) for item in self.instances}
            save(self.state_path, self.state)
        self.gate_on()
        command(['systemctl', 'stop', *[item['unit'] for item in self.instances]])
        require(self.all_stopped(), 'instances_not_stopped')
        helper = self.tenant_helper()
        for item in self.instances:
            helper.run_database(self.tenant(helper, item), 'idle')
        self.migrate()  # Read-only schema verification also covers explicit rollback.

    def backup(self):
        require(self.gate.exists() and self.all_stopped(), 'backup_requires_stopped_gated_instances')
        self.verify_identity(); helper = self.tenant_helper(); snapshots = []
        for item in self.instances:
            path = self.operation / (item['slug'] + '-before.sqlite')
            helper.snapshot_tenant_database(self.tenant(helper, item), path)
            snapshots.append({'slug': item['slug'], 'path': str(path), 'sha256': sha(path)})
        self.state['snapshots'] = snapshots; save(self.state_path, self.state)

    def migrate(self):
        # Deliberately ordinary updates only. A schema transition needs its own
        # qualified migration adapter, backup/restore proof and approved window.
        require(self.context['schema_before'] == self.context['schema_after'] == 8, 'migration_not_qualified')
        require(self.gate.exists() and self.all_stopped(), 'schema_check_requires_maintenance')
        self.verify_identity()
        code = ('import sqlite3,sys; from contextlib import closing; '
                'db=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True); '
                'assert db.execute("PRAGMA user_version").fetchone()[0]==8; '
                'assert db.execute("PRAGMA quick_check").fetchall()==[("ok",)]; db.close()')
        for item in self.instances:
            command([self.config['python'], '-I', '-B', '-c', code, item['database']], uid=item['uid'], gid=item['gid'])

    def point_release(self):
        protected(self.current.parent, file=False)
        require(not self.current.exists() or self.current.is_symlink(), 'current_is_not_a_reviewed_symlink')
        temporary = self.current.with_name(self.current.name + '.' + os.urandom(8).hex())
        temporary.symlink_to(self.release_path, target_is_directory=True)
        os.replace(temporary, self.current); fsync_dir(self.current.parent)

    def activate(self):
        require(self.gate.exists(), 'activation_requires_barrier')
        self.verify_identity()
        qualified_runtime(self.release_path / 'runtime', self.release)
        if self.context.get('kind') == 'recovery':
            # A failed rollback may already have started its target. start on an
            # active unit is a no-op, so stop before selecting the prior code.
            command(['systemctl', 'stop', *[item['unit'] for item in self.instances]])
        require(self.all_stopped(), 'activation_requires_stopped_instances')
        self.point_release()
        # Unit definitions are converted once at cutover and point to current;
        # this hook never edits unit files, users, grants or provider state.
        command(['systemctl', 'start', *self.state['active']])

    def session(self, item):
        cfg = tomllib.loads(protected(item['config']).read_text())['bridge']
        name = cfg.get('session', 'default')
        require(isinstance(name, str) and 0 < len(name) <= 200, 'invalid_session_name')
        key = protected(Path(item['config']).parent / 'waha.key').read_text().strip()
        request = urllib.request.Request('http://127.0.0.1:' + str(item['gateway_port'])
                                         + '/api/sessions/' + urllib.parse.quote(name, safe=''), headers={'X-Api-Key': key})
        with http_open(request) as response:
            value = json.load(response)
        require(value.get('name', name) == name and value.get('status') == 'WORKING', 'session_not_working')
        return value['status']

    def health_once(self, ready=False):
        self.verify_identity()
        require(self.current.is_symlink() and self.current.resolve() == self.release_path, 'current_release_mismatch')
        for item in self.instances:
            require(self.active(item), 'instance_not_active')
            pid = command(['systemctl', 'show', item['unit'], '--property=MainPID', '--value']).stdout.strip()
            require(pid.isdecimal() and int(pid) > 1, 'invalid_service_pid')
            require(Path('/proc/' + pid + '/cwd').resolve(strict=True) == self.release_path
                    and Path('/proc/' + pid + '/exe').resolve(strict=True) == (self.release_path / 'runtime/venv/bin/python').resolve(strict=True),
                    'running_process_does_not_belong_to_release')
            with http_open('http://127.0.0.1:' + str(item['port']) + '/healthz') as response:
                require(response.headers.get('X-WhatsApp-Release-Commit') == self.release['commit'], 'running_commit_mismatch')
                value = json.load(response)
            require(value.get('process') == 'running' and value.get('version') == self.release['manifest']['version'],
                    'running_version_mismatch')
            if ready:
                readiness = value.get('readiness', {})
                require(readiness.get('state') == 'ready' and readiness.get('ready') is True
                        and all(readiness.get('workers', {}).get(name) is True for name in ('events', 'transfers', 'history', 'actions', 'portal')),
                        'application_not_ready')
            require(self.session(item) == self.state['sessions'][item['slug']], 'provider_session_changed')
            cfg = tomllib.loads(protected(item['config']).read_text())['bridge']
            public = cfg['public_url']
            endpoint = urllib.parse.urlsplit(public)
            require(re.fullmatch(r'https://[A-Za-z0-9.-]+', public) and endpoint.scheme == 'https'
                    and endpoint.netloc == endpoint.hostname and not endpoint.path and not endpoint.query and not endpoint.fragment,
                    'unexpected_public_endpoint')
            with http_open(public + '/.well-known/oauth-protected-resource') as response:
                metadata = json.load(response)
            require(metadata.get('resource') == public and metadata.get('authorization_servers') == [cfg['issuer']],
                    'oauth_resource_changed')
            try:
                with http_open(urllib.request.Request(public + '/mcp', headers={'Accept': 'text/event-stream'})):
                    pass
            except urllib.error.HTTPError as response:
                require(response.code == (401 if ready else 503), 'anonymous_mcp_admission_changed')
            else:
                raise ValueError('anonymous_mcp_access_succeeded')

    def health(self, ready=False):
        # A committed recovery can resume directly at health/reopen without
        # activate or restore; validate the selected runtime once per call.
        qualified_runtime(self.release_path / 'runtime', self.release)
        for attempt in range(30):
            try:
                self.health_once(ready); return
            except (ValueError, OSError):
                if attempt == 29: raise
                time.sleep(1)

    def replace_snapshot(self, snapshot, item):
        # Only root-created frozen snapshots; no SQLite code executes as root.
        source = protected(snapshot['path'])
        require(source.parent == self.operation and sha(source) == snapshot['sha256'], 'frozen_backup_changed')
        helper = self.tenant_helper()
        require(self.configuration_files(item) == self.state['identity'][item['slug']], 'tenant_configuration_changed')
        identity = helper.tenant_context(self.tenant(helper, item))
        verify_snapshot(source, identity['expected'], item['uid'], item['gid'], self.config['python'])
        target = Path(item['database'])
        with helper.physical_directory(target.parent) as directory:
            before = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == item['uid'], 'database_identity_changed')
            name = target.name + '.deploy-' + os.urandom(16).hex()
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                with source.open('rb') as incoming, os.fdopen(os.dup(fd), 'wb') as outgoing:
                    shutil.copyfileobj(incoming, outgoing); outgoing.flush()
                os.fchown(fd, item['uid'], item['gid']); os.fchmod(fd, before.st_mode & 0o777); os.fsync(fd)
                current = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
                require((before.st_dev, before.st_ino) == (current.st_dev, current.st_ino), 'database_replaced_during_restore')
                for suffix in ('-wal', '-shm'):
                    try: os.unlink(target.name + suffix, dir_fd=directory)
                    except FileNotFoundError: pass
                os.replace(name, target.name, src_dir_fd=directory, dst_dir_fd=directory); os.fsync(directory)
            finally:
                os.close(fd)

    def restore(self):
        require(not self.context['committed'], 'post_commit_data_restore_forbidden')
        require(self.gate.exists(), 'restore_requires_barrier')
        qualified_runtime(self.release_path / 'runtime', self.release)
        command(['systemctl', 'stop', *[item['unit'] for item in self.instances]])
        require(self.all_stopped(), 'restore_requires_stopped_instances')
        snapshots = {item['slug']: item for item in self.state.get('snapshots', [])}
        require(set(snapshots) == {item['slug'] for item in self.instances}, 'complete_backup_required')
        for item in self.instances:
            self.replace_snapshot(snapshots[item['slug']], item)
        self.point_release(); command(['systemctl', 'start', *self.state['active']])

    def reopen(self):
        require(self.context['committed'], 'durable_commit_required_before_reopening')
        self.health()
        self.gate.unlink(missing_ok=True); fsync_dir(self.gate.parent)
        self.health(ready=True)

    def execute(self, phase, mode):
        require(phase == self.context['phase'] and phase in PHASES and mode in ('run', 'reconcile'), 'hook_invocation_mismatch')
        require(not (phase == 'restore' and self.context['committed']), 'post_commit_data_restore_forbidden')
        if phase == 'health':
            self.health(); return 'done'
        # Recovery contexts select the previous release but retain the operation;
        # distinguish their receipts by the selected release and committed flag.
        key = phase + ':' + self.release['id']
        step = self.state['steps'].get(key)
        if mode == 'reconcile':
            if step == 'done': return 'done'
            if step is None: return 'not_started'
            if phase == 'reopen' and self.context['committed'] and not self.gate.exists():
                self.health(ready=True); return 'done'
            # No replay of partial backup, runtime build, activation or restore.
            # The stopped/gated state is retained for explicit diagnosis.
            return 'unknown'
        require(step is None, 'phase_already_started_requires_reconciliation')
        self.state['steps'][key] = 'started'; save(self.state_path, self.state)
        getattr(self, phase)()
        self.state['steps'][key] = 'done'; save(self.state_path, self.state)
        return 'done'


def main():
    try:
        require(len(sys.argv) == 4, 'usage_phase_mode_context')
        phase, mode, path = sys.argv[1:]
        protected(CONFIG); protected(path)
        config, context = json.loads(CONFIG.read_bytes()), json.loads(Path(path).read_bytes())
        adapter = Adapter(config, context)
        require(Path(path).parent == adapter.operation, 'context_outside_operation')
        status = adapter.execute(phase, mode)
        print(json.dumps({'format': 'deploy-hook-v1', 'operation_id': context['operation_id'], 'phase': phase, 'status': status}))
        return 0
    except Exception:
        # No config, session, key, HTTP body or database diagnostics on either stream.
        print('WhatsApp hook blocked; inspect the protected operation state with the approved administrative path.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

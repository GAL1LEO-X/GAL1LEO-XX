#!/usr/bin/env python3
"""Restore one suspended tenant's data from an independently approved snapshot.

Only the selected runtime units can be quiesced; an optional bridge restart
is restricted to maintenance. No configuration, executable, identity-provider
state or authority is installed from a backup. Interrupted swaps resume forward under the same plan;
preimages are retained in the protected journal directory, never auto-deleted.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import ast
from contextlib import contextmanager
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import tarfile
import time
import tomllib
import types
from types import SimpleNamespace

FORMAT = 'whatsapp-tenant-data-restore-v1'
DEPLOY_FORMAT = 'whatsapp-tenant-data-restore-v2'
MAX_JSON = 1024 * 1024
MAX_FILES = 100000
MAX_BYTES = 64 * 1024 ** 3
_TRUST_ROOT = Path('/')  # fixture seam; never accepted from CLI or a plan
_TRUST_UID = 0
_CGROUP_ROOT = Path('/sys/fs/cgroup')
# These pins attest the pre-SQLite restoration fence independently of a mutable
# installation or the backup's advertised version. Backend changes require a
# review of this admission contract and an explicit update of these hashes.
RESTORE_GATE_SOURCES = {
    '__init__.py': '6e6074d7f9c39207ad584ac1420ada36ee15bfaac7044f615527283cfe448a1b',
    'server.py': '9b79f04f1980524ae100498071a54c8203e3962789f9e278a6687fa716d25afc',
    'restore_maintenance.py': 'ff190ba36d864ccd1dc4395d65d0750ed6bc46799a5822569cd2ccf5d5afe7db',
    'config.py': '0ac870da54721970ced393c9af998022feed2adab830fa07c606048534eedfea',
    'cli.py': '30de1782d8ba5c38a30dc83ee36433b61b51fb4fba1d741809733949ee808f90',
}
RELEASE_LAUNCHER_SHA256 = 'd3cb0690df8140b1d38e37da5641d82bd0adadb6dc264525d4ca82bf7d134d4b'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def hexid(value, length=64):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value) is not None


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate restore field')
        value[key] = item
    return value


def decode(raw):
    require(len(raw) <= MAX_JSON, 'Restore metadata exceeds its bound')
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite restore value')))


def physical(path, *, protected=False, directory=False):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(strict=True), 'Physical restore path required')
    relative = path.relative_to(_TRUST_ROOT)
    current = _TRUST_ROOT
    for index, part in enumerate(('', *relative.parts)):
        if part:
            current = current / part
        info = current.lstat()
        kind = stat.S_ISDIR if directory or index < len(relative.parts) else stat.S_ISREG
        require(kind(info.st_mode), 'Restore path type differs')
        if protected:
            require(info.st_uid == _TRUST_UID and not info.st_mode & 0o022,
                    'Restore authority path is not protected')
    return path


def protected_read(path):
    path = physical(path, protected=True)
    with path.open('rb') as stream:
        require(os.fstat(stream.fileno()).st_nlink == 1, 'Linked restore metadata')
        content = stream.read(MAX_JSON + 1)
    require(len(content) <= MAX_JSON, 'Restore metadata exceeds its bound')
    return content


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    """Private atomic journal write; a stale temporary file is never overwritten."""
    content = encoded(value)
    temporary = path.with_suffix('.pending')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def validate(plan):
    require(isinstance(plan, dict), 'Exact restore plan required')
    runtime_fields = {'runtime'} if plan.get('format') == DEPLOY_FORMAT else set()
    require(set(plan) == {
        'format', 'id', 'instance', 'installation_sha256', 'registry_sha256',
        'snapshot', 'current_sha256', 'owner', 'preimage_policy', 'quiesce',
        'restore_service_state', 'service_definitions', 'account'} | runtime_fields, 'Exact restore plan required')
    require(plan['format'] in (FORMAT, DEPLOY_FORMAT) and hexid(plan['id'], 32)
            and isinstance(plan['instance'], str)
            and re.fullmatch('[a-z][a-z0-9-]{1,19}', plan['instance'])
            and '--' not in plan['instance']
            and all(hexid(plan[name]) for name in ('installation_sha256', 'registry_sha256')),
            'Invalid restore identity')
    require(plan['preimage_policy'] in ('exact_digest', 'preserve_all_current')
            and ((plan['preimage_policy'] == 'exact_digest' and hexid(plan['current_sha256']))
                 or (plan['preimage_policy'] == 'preserve_all_current' and plan['current_sha256'] is None))
            and plan['quiesce'] in ('already_stopped', 'stop')
            and plan['restore_service_state'] in ('remain_stopped', 'maintenance'),
            'Invalid explicit restore/preimage/service policy')
    definitions = plan['service_definitions']
    require((definitions is None and plan['quiesce'] == 'already_stopped'
             and plan['restore_service_state'] == 'remain_stopped')
            or (isinstance(definitions, dict) and set(definitions) == {'bridge', 'gateway'}
                and all(hexid(value) for value in definitions.values())),
            'Reviewed service definitions are required for service transitions')
    account = plan['account']
    require(isinstance(account, dict) and set(account) == {'name', 'uid', 'gid', 'home', 'shell', 'group'}
            and all(isinstance(account[key], str) and re.fullmatch('[a-z][a-z0-9_-]{0,30}', account[key])
                    for key in ('name', 'group'))
            and all(type(account[key]) is int and account[key] > 0 for key in ('uid', 'gid'))
            and isinstance(account['home'], str) and Path(account['home']).is_absolute()
            and str(Path(account['home'])) == account['home'] and '..' not in Path(account['home']).parts
            and account['shell'] == '/usr/sbin/nologin', 'Exact unprivileged restore account binding required')
    snapshot = plan['snapshot']
    require(isinstance(snapshot, dict) and set(snapshot) == {'path', 'manifest_sha256'}
            and isinstance(snapshot['path'], str) and Path(snapshot['path']).is_absolute()
            and str(Path(snapshot['path'])) == snapshot['path'] and '..' not in Path(snapshot['path']).parts
            and hexid(snapshot['manifest_sha256']), 'Invalid approved snapshot')
    owner = plan['owner']
    require(isinstance(owner, dict) and set(owner) == {
        'protocol', 'epoch', 'state', 'generation', 'manifest_sha256'}
        and type(owner['protocol']) is int and owner['protocol'] == 1
        and owner['state'] == 'dedicated' and hexid(owner['epoch'], 32)
        and hexid(owner['manifest_sha256']) and isinstance(owner['generation'], str),
        'Invalid restore administrative owner')
    if runtime_fields:
        from admin_deployment import validate_binding
        runtime = plan['runtime']
        require(isinstance(runtime, dict) and set(runtime) == {'deployment', 'start_context_sha256'}
                and hexid(runtime['start_context_sha256']), 'Exact approved deployment start context required')
        validate_binding(runtime['deployment'])
    return plan


def owner_record(generation):
    return {'protocol': 1, 'epoch': generation.epoch, 'state': generation.state,
            'generation': str(generation.path), 'manifest_sha256': generation.manifest_sha256}


def configured_authority(config, instance):
    """The runtime gate and restore helper must name the same authority files."""
    require(all(config.get(field) == str(instance.config_dir / name) for field, name in (
        ('encryption_key_file', 'encryption.key'), ('webhook_secret_file', 'webhook.key'),
        ('waha_key_file', 'waha.key'))),
        'Restore requires canonical instance key paths and maintenance fence')


def account_binding(instance, profile, plan):
    account = pwd.getpwnam(instance.service_user)
    group = grp.getgrgid(account.pw_gid)
    actual = {'name': account.pw_name, 'uid': account.pw_uid, 'gid': account.pw_gid,
              'home': account.pw_dir, 'shell': account.pw_shell, 'group': group.gr_name}
    require(actual == plan['account'] and account.pw_name == instance.service_user
            and account.pw_dir == str(instance.gateway_home) and account.pw_shell == '/usr/sbin/nologin'
            and account.pw_uid > 0 and account.pw_gid > 0
            and (profile.compatibility or group.gr_name == instance.service_user),
            'Restore account numeric identity, home, shell or group changed')
    return account


def context(plan, administration):
    from installation_layout import active
    from sally_whatsapp.tenancy import Instance
    profile = active()
    require(profile.sha256 == plan['installation_sha256'], 'Restore installation differs')
    project = Path(profile.path('project'))
    raw = protected_read(project / 'private/tenants.json')
    require(sha(raw) == plan['registry_sha256'], 'Restore registry changed')
    registry = decode(raw)
    require(set(registry) == {'format', 'instances'} and registry['format'] == 1,
            'Invalid current tenant registry')
    row = registry['instances'].get(plan['instance'])
    require(isinstance(row, dict) and type(row.get('enabled')) is bool
            and (plan['quiesce'] == 'stop' or row['enabled'] is False)
            and row.get('phase') in ('ready', 'existing'), 'Restore requires an existing instance and explicit quiescence')
    instance = Instance(**row['spec'])
    require(instance.slug == plan['instance'] and instance._installation_identity.sha256 == profile.sha256,
            'Restore instance identity differs')
    account = account_binding(instance, profile, plan)
    config = tomllib.loads(protected_read(instance.config_dir / 'config.toml').decode())['bridge']
    configured_authority(config, instance)
    if plan['restore_service_state'] == 'maintenance':
        from sally_whatsapp.config import Settings
        require(Settings.load(str(instance.config_dir / 'config.toml')).admin_enabled is True,
                'Maintenance restart requires a valid enabled owner administration portal')
    require(config['database'] == str(instance.state_dir / 'archive.sqlite')
            and config['owner_subject'] == instance.subject and config['public_url'] == instance.public_url,
            'Current configuration differs from the registered instance')
    marker = Path(config.get('state_identity_file', str(instance.config_dir / 'technical-state.json')))
    from tenant_database import identity
    technical = identity(decode(protected_read(marker)))
    tenant = sha(json.dumps([instance.subject, instance.public_url, config.get('session', 'default')], separators=(',', ':')).encode())
    require(technical['tenant'] == tenant, 'Technical identity belongs to another tenant')
    require(not marker.is_relative_to(instance.state_dir), 'Restore needs an external technical identity')
    from admin_deployment import load
    deployment = load(profile, instance.slug)
    if deployment is None:
        require(plan['format'] == FORMAT, 'A deploy-v1 plan cannot select a legacy runtime')
    else:
        require(plan['format'] == DEPLOY_FORMAT and plan['runtime']['deployment'] == deployment.binding,
                'Restore requires the exact approved deploy-v1 release')
        require(deployment.instance['uid'] == account.pw_uid and deployment.instance['gid'] == account.pw_gid
                and (project / '.venv').resolve(strict=True) == deployment.venv,
                'Administrative interpreter differs from the admitted deployment')
    return SimpleNamespace(instance=instance, profile=profile, uid=account.pw_uid, gid=account.pw_gid,
                           project=project, marker=marker, technical=technical,
                           deployment=deployment,
                           start_context_sha256=plan.get('runtime', {}).get('start_context_sha256'),
                           state=Path(profile.mapped('/var/lib/develative-deploy/whatsapp')) / 'restores')


def targets(ctx):
    return {'state': ctx.instance.state_dir,
            'sessions': ctx.instance.gateway_home / 'sessions',
            'media': ctx.instance.gateway_home / 'media'}


def inventory(path):
    """Digest the complete preimage, including WAL and unrecognized files.

    Descriptors avoid following tenant links. Mutable metadata is compared both
    before and after reading; special files, hardlinks and mounts are refused.
    """
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return None
    physical(path, directory=True)
    entries = {}
    total = 0
    root_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    device = os.fstat(root_fd).st_dev

    def scan(fd, name):
        nonlocal total
        before = os.fstat(fd)
        require(before.st_dev == device, 'Restore tree crosses a filesystem')
        require(len(entries) < MAX_FILES, 'Restore inventory exceeds its bound')
        item = {'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid, 'gid': before.st_gid}
        if stat.S_ISREG(before.st_mode):
            require(before.st_nlink == 1, 'Restore tree contains hardlinks')
            total += before.st_size
            require(total <= MAX_BYTES, 'Restore data exceeds its bound')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                item.update(sha256=hashlib.file_digest(stream, 'sha256').hexdigest(), bytes=before.st_size)
        else:
            require(stat.S_ISDIR(before.st_mode), 'Restore tree contains a special file')
            item['directory'] = True
            for child in sorted(os.listdir(fd)):
                descriptor = os.open(child, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    scan(descriptor, name + '/' + child)
                    after_name = os.stat(child, dir_fd=fd, follow_symlinks=False)
                    opened = os.fstat(descriptor)
                    require((after_name.st_dev, after_name.st_ino) == (opened.st_dev, opened.st_ino), 'Restore file replaced during inspection')
                finally:
                    os.close(descriptor)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'Restore tree changed during inspection')
        entries[name] = item

    try:
        scan(root_fd, '.')
        info = os.fstat(root_fd)
        require((path.stat().st_dev, path.stat().st_ino) == (info.st_dev, info.st_ino), 'Restore root replaced')
        return {'sha256': sha(encoded(entries)), 'device': info.st_dev, 'inode': info.st_ino}
    finally:
        os.close(root_fd)


def current_digest(ctx):
    return sha(encoded({key: inventory(path) for key, path in targets(ctx).items()}))


@contextmanager
def target_parent(ctx, target):
    """Anchor swaps without traversing mutable tenant-owned path components."""
    parent = target.parent
    gateway = ctx.instance.gateway_home
    if parent == gateway:
        physical(parent.parent, protected=True, directory=True)
        physical(parent, directory=True)
        expected_uid = ctx.uid
    else:
        physical(parent, protected=True, directory=True)
        expected_uid = _TRUST_UID
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(info.st_uid == expected_uid and not info.st_mode & 0o022,
                'Restore destination parent ownership or protection differs')
        actual = parent.lstat()
        require((actual.st_dev, actual.st_ino) == (info.st_dev, info.st_ino),
                'Restore destination parent changed')
        yield fd
    finally:
        os.close(fd)


def swap(ctx, source, destination, target):
    """Use the pinned live parent and protected transaction dirfds for rename."""
    live_is_source = source == target
    stored = destination if live_is_source else source
    physical(stored.parent, protected=True, directory=True)
    with target_parent(ctx, target) as live_fd:
        stored_fd = os.open(stored.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.rename(source.name, destination.name,
                      src_dir_fd=live_fd if live_is_source else stored_fd,
                      dst_dir_fd=stored_fd if live_is_source else live_fd)
            os.fsync(live_fd)
            os.fsync(stored_fd)
        finally:
            os.close(stored_fd)


def lease_fds(*descriptors):
    from host_integration import command_options
    return command_options({'pass_fds': descriptors})['pass_fds']


def quiescent(ctx, lock_fd):
    """Observe only finite named units; never start/stop through this helper."""
    wrapper = physical(ctx.instance.wrapper, protected=True)
    properties = ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlPID', 'Job', 'UnitFileState', 'ControlGroup')
    for prefix, unit in ((['/usr/bin/systemctl'], ctx.instance.base + '.service'),
                         ([str(wrapper), '/usr/bin/systemctl', '--user'], 'whatsapp-waha.service')):
        result = subprocess.run([*prefix, 'show', unit, '--property=' + ','.join(properties)],
                                capture_output=True, check=True, timeout=20, pass_fds=lease_fds(lock_fd), env={})
        require(len(result.stdout) <= 8192, 'Unbounded restore service observation')
        value = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        require(set(value) == set(properties) and value['LoadState'] in ('masked', 'loaded')
                and (unit != 'whatsapp-waha.service' or value['LoadState'] == 'masked')
                and value['ActiveState'] == 'inactive' and value['SubState'] == 'dead'
                and value['MainPID'] == value['ControlPID'] == '0' and value['Job'] in ('', '0'),
                'Restore requires masked, inactive runtime units without pending jobs')
        group = value['ControlGroup']
        if group:
            require(group.startswith('/') and '..' not in PurePosixPath(group).parts,
                    'Invalid runtime control group')
            path = _CGROUP_ROOT / group.lstrip('/')
            require(path == path.resolve(strict=True), 'Runtime control group is not physical')
            events = dict(line.split() for line in (path / 'cgroup.events').read_text().splitlines())
            require(events.get('populated') == '0', 'Runtime control group still contains processes')


# This worker runs under the dedicated UID with no supplementary groups. It
# reads an inherited read-only snapshot FD, never host paths or application code.
SANITIZE = r'''
import hashlib,json,os,shutil,sqlite3,sys,tempfile
expected=json.loads(sys.argv[2])
role,action=sys.argv[3:5]
contract=sys.argv[5]
with tempfile.TemporaryDirectory(prefix='whatsapp-restore-db-') as work:
    path=os.path.join(work,'archive.sqlite')
    with os.fdopen(int(sys.argv[1]),'rb') as source,open(path,'xb') as target:
        shutil.copyfileobj(source,target)
    db=sqlite3.connect(path)
    try:
        db.execute('PRAGMA trusted_schema=OFF')
        assert db.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
        if role=='archive':
            assert db.execute('PRAGMA user_version').fetchone()==(8,)
            reference=sqlite3.connect(':memory:')
            try:
                reference.executescript(contract)
                assert schema(db)==schema(reference)
            finally: reference.close()
            row=db.execute("SELECT value FROM state WHERE key='private:technical_state_identity:v1'").fetchone()
            assert row and json.loads(row[0])==expected
        else:
            tables_found=[row for row in db.execute('PRAGMA table_list') if row[0]=='main' and row[1]=='user_opaque_identifier']
            assert len(tables_found)==1 and tables_found[0][2]=='table'
            columns={row[1] for row in db.execute('PRAGMA table_info(user_opaque_identifier)')}
            assert {'service','sector_id','username','identifier'} <= columns
        with db:
            if action=='sanitize':
                db.execute('DELETE FROM link_sessions')
                db.execute('DELETE FROM link_login_states')
                db.execute('UPDATE subscriptions SET active=0')
                db.execute("UPDATE deliveries SET state='cancelled' WHERE state IN ('collecting','pending','sending')")
                db.execute("UPDATE sends SET state='uncertain' WHERE state='queued'")
                db.execute("UPDATE sends SET state='uncertain' WHERE state='sending'")
                db.execute("UPDATE history_jobs SET state='cancelled' WHERE state IN ('running','paused','failed')")
                db.execute("UPDATE media_jobs SET state='cancelled',source=X'',error='Cancelled by approved data restore' WHERE state IN ('queued','downloading')")
        assert db.execute('PRAGMA journal_mode=DELETE').fetchone()==('delete',)
        assert db.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
    finally: db.close()
    if action=='sanitize':
        with open(path,'rb') as stream: shutil.copyfileobj(stream,sys.stdout.buffer)
'''


def database_worker(source, ctx, lock_fd, *, target=None, role='archive'):
    # Select only pure schema functions from the already admitted helper source.
    # No code is read from a snapshot or executed with administrative privileges.
    source_module = Path(__file__).with_name('release_database.py')
    tree = ast.parse(source_module.read_text())
    wanted = {'quote', 'tables', 'ascii_fold', 'declaration', 'schema'}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    require({node.name for node in functions} == wanted, 'Installed schema validator is incomplete')
    header = "import re\ndef require(condition, message):\n    if not condition: raise ValueError(message)\n"
    code = header + ast.unparse(ast.Module(body=functions, type_ignores=[])) + '\n' + SANITIZE
    options = {'cwd': '/', 'env': {}, 'input': code.encode(), 'stderr': subprocess.DEVNULL,
               'check': True, 'timeout': 120, 'close_fds': True}
    if os.geteuid() == 0:
        options.update(user=ctx.uid, group=ctx.gid, extra_groups=[])
    else:
        require(os.geteuid() == ctx.uid and os.getegid() == ctx.gid,
                'Restore worker requires the dedicated tenant credentials')
    output = target.open('xb') if target else open(os.devnull, 'wb')
    contract = Path(__file__).with_name('backup_schemas').joinpath('8.sql').read_text()
    with source.open('rb') as stream, output:
        subprocess.run([sys.executable, '-I', '-B', '-', str(stream.fileno()), json.dumps(ctx.technical),
                        role, 'sanitize' if target else 'validate', contract],
                       pass_fds=lease_fds(stream.fileno(), lock_fd), stdout=output, **options)
        output.flush()
        if target:
            os.fsync(output.fileno())
    if target:
        os.chmod(target, 0o600)
        os.chown(target, ctx.uid, ctx.gid)


def snapshot_admission(plan, ctx, lock_fd):
    # A private module namespace keeps the existing structural/hash validator,
    # while database parsing runs in a separate process under the tenant UID.
    path = Path(__file__).with_name('backup_validation.py')
    validator = types.ModuleType('_restore_backup_validation')
    validator.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), validator.__dict__)
    validator.installation_profile = lambda: ctx.profile
    validator.validate_database = lambda path, role: database_worker(path, ctx, lock_fd, role=role)
    snapshot = physical(plan['snapshot']['path'], protected=True, directory=True)
    expected_parent = (Path('/var/backups') / ctx.instance.base if ctx.profile.compatibility
                       else Path(ctx.profile.path('backup')) / ctx.instance.slug) / 'snapshots'
    if _TRUST_ROOT != Path('/'):
        expected_parent = _TRUST_ROOT / str(expected_parent).lstrip('/')
    require(snapshot.parent == expected_parent, 'Snapshot is outside the selected tenant backup namespace')
    raw = protected_read(snapshot / 'manifest.json')
    require(sha(raw) == plan['snapshot']['manifest_sha256'], 'Approved snapshot manifest changed')
    for path in snapshot.iterdir():
        physical(path, protected=True)
        require(path.stat().st_nlink == 1, 'Snapshot contains hardlinks')
    manifest = validator.validate_snapshot(snapshot, ctx.instance.slug, runtime_prefix=_TRUST_ROOT,
                                 auth_mode=ctx.instance.auth_mode)
    require(manifest['format'] in ('whatsapp-isolated-backup-v5', 'whatsapp-isolated-backup-v6'),
            'Restore requires an installation-bound backup')
    return snapshot


def stage(plan, ctx, directory, lock_fd):
    snapshot = snapshot_admission(plan, ctx, lock_fd)
    current = targets(ctx)
    pending = directory / 'new'
    pending.mkdir(mode=0o700)
    for key in current:
        (pending / key).mkdir(mode=0o700)
    # Archived authority is never restored. Compare only identity/keys that
    # bind the restored data; current configuration (including broker policy)
    # remains current and may legitimately differ from the old backup.
    protected_names = [ctx.instance.config_dir / name for name in ('encryption.key', 'webhook.key', 'waha.key')]
    protected_names.append(ctx.marker)
    required = {str(path).lstrip('/'): path for path in protected_names}
    found = set()
    payload_roots = {
        str(ctx.instance.state_dir / 'media-cache').lstrip('/'): ('state', 'media-cache'),
        str(ctx.instance.state_dir / 'diagnostics').lstrip('/'): ('state', 'diagnostics'),
        str(ctx.instance.state_dir / 'archive.sqlite.identity.json').lstrip('/'): ('state', 'archive.sqlite.identity.json'),
        str(current['sessions']).lstrip('/'): ('sessions', ''),
        str(current['media']).lstrip('/'): ('media', ''),
    }
    total = 0
    with tarfile.open(snapshot / 'private-runtime.tar.gz', 'r:gz') as archive:
        members = archive.getmembers()
        require(len(members) <= MAX_FILES, 'Restore archive exceeds its bound')
        for member in members:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts
                    and (member.isdir() or member.isfile()), 'Unsafe restore archive member')
            if member.name in required:
                require(member.isfile() and member.size <= 131072, 'Invalid archived data identity')
                with archive.extractfile(member) as source:
                    require(source.read() == protected_read(required[member.name]), 'Archived data keys or identity differ')
                found.add(member.name)
            selected = next(((prefix, values) for prefix, values in payload_roots.items()
                             if member.name == prefix or member.name.startswith(prefix + '/')), None)
            if selected is None:
                continue
            prefix, (key, prefix_relative) = selected
            suffix = member.name[len(prefix):].lstrip('/')
            relative = Path(prefix_relative) / suffix if prefix_relative else Path(suffix)
            destination = pending / key / relative
            total += member.size
            require(total <= MAX_BYTES and not member.mode & 0o7000, 'Invalid restore payload size or mode')
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.extractfile(member) as source, destination.open('xb') as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(destination, 0o600)
    require(found == set(required), 'Backup is missing the current data keys or technical identity')
    database_worker(snapshot / 'archive.sqlite', ctx, lock_fd, target=pending / 'state/archive.sqlite')
    for path in sorted(pending.rglob('*'), key=lambda p: len(p.parts), reverse=True):
        os.chown(path, ctx.uid, ctx.gid)
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
        if path.is_dir():
            sync_directory(path)
    sync_directory(pending)
    # An archive altered between validation/extraction never becomes published.
    snapshot_admission(plan, ctx, lock_fd)
    return {key: inventory(pending / key) for key in current}


def _fault(point):
    """Test-only crash injection seam, not an input or operational option."""


def _recover_pending(journal_path, plan_digest):
    temporary = journal_path.with_suffix('.pending')
    if temporary.exists():
        value = decode(protected_read(temporary))
        require(value.get('plan_sha256') == plan_digest, 'Pending restore journal belongs to another plan')
        if not journal_path.exists():
            os.rename(temporary, journal_path)
        else:
            # Both journals belong to the same immutable plan. The newer
            # write is authoritative; swap state is independently re-attested.
            old = decode(protected_read(journal_path))
            require(old.get('plan_sha256') == plan_digest, 'Restore journal plan differs')
            os.replace(temporary, journal_path)
        sync_directory(journal_path.parent)


def unfinished(ctx, identifier):
    """A durable incomplete restore fences later attempts for this instance."""
    for path in ctx.state.iterdir():
        require(path.is_dir() and not path.is_symlink() and hexid(path.name, 32),
                'Unexpected restore journal inventory')
        if path.name == identifier:
            continue
        journal = path / 'journal.json'
        # A crash creating a journal directory is conservatively global: there
        # is not yet evidence identifying which instance owns that directory.
        require(journal.exists(), 'An unclassified restore attempt requires reconciliation')
        row = decode(protected_read(journal))
        require(row.get('instance') != ctx.instance.slug or row.get('phase') == 'completed',
                'An earlier restore for this instance is unfinished')


def maintenance_marker(ctx, plan, *, phase='restoring'):
    require(phase in ('restoring', 'maintenance'), 'Invalid restore fence phase')
    path = ctx.instance.config_dir / 'restore-maintenance.json'
    physical(path.parent, protected=True, directory=True)
    base = {'format': 'whatsapp-restore-maintenance-v1', 'id': plan['id'],
            'plan_sha256': sha(encoded(plan)), 'instance': plan['instance']}
    value = {**base, 'phase': phase}
    def owned(previous):
        return isinstance(previous, dict) and set(previous) == set(value) and all(
            previous[key] == item for key, item in base.items()) and previous['phase'] in ('restoring', 'maintenance')
    if path.exists():
        previous = decode(protected_read(path))
        require(owned(previous), 'Another restore maintenance fence is active')
        if previous == value:
            return
    temporary = path.with_suffix('.pending')
    if temporary.exists():
        require(owned(decode(protected_read(temporary))), 'Unrecognized pending restore fence')
        temporary.unlink()
        sync_directory(path.parent)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fchmod(stream.fileno(), 0o644)
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def service_tenant(ctx):
    from runtime_lifecycle import layout
    value = layout(ctx.instance.slug)
    require(value['account'] == ctx.profile.account(ctx.instance.slug)
            and value['wrapper'] == str(ctx.instance.wrapper), 'Restore service layout differs')
    value.update(slug=ctx.instance.slug, uid=ctx.uid, gid=ctx.gid,
                 bridge_cgroup='/system.slice/' + ctx.instance.base + '.service',
                 gateway_cgroup='/user.slice/user-' + str(ctx.uid) + '.slice/user@' + str(ctx.uid)
                 + '.service/app.slice/whatsapp-waha.service')
    # Even the privileged runuser wrapper must be the finite reviewed template.
    expected = ('#!/bin/sh\nset -eu\ncd ' + value['home'] + '\nexec runuser -u ' +
                value['account'] + ' -- env HOME=' + value['home'] + ' XDG_RUNTIME_DIR=/run/user/' +
                str(ctx.uid) + ' DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(ctx.uid) + '/bus "$@"\n')
    require(protected_read(ctx.instance.wrapper) == expected.encode(), 'Restore gateway wrapper is not source-finite')
    return value


def service_observation(ctx, component, lock_fd):
    from runtime_lifecycle import read_unit
    def reader(argv):
        answer = subprocess.run(argv, capture_output=True, timeout=20, check=True,
                                pass_fds=lease_fds(lock_fd), env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        require(len(answer.stdout) + len(answer.stderr) <= 256 * 1024, 'Unbounded service observation')
        return answer.stdout
    return read_unit(service_tenant(ctx), component, reader)


def service_command(ctx, component, operation, lock_fd):
    require(component in ('bridge', 'gateway') and operation in ('stop', 'mask', 'unmask', 'start'),
            'Unknown restore service operation')
    require((component, operation) in (('bridge', 'stop'), ('bridge', 'unmask'), ('bridge', 'start'),
                                      ('gateway', 'stop'), ('gateway', 'mask')),
            'Restore service operation exceeds its scope')
    prefix = ['/usr/bin/systemctl'] if component == 'bridge' else [str(ctx.instance.wrapper), '/usr/bin/systemctl', '--user']
    unit = ctx.instance.base + '.service' if component == 'bridge' else 'whatsapp-waha.service'
    args = ['--runtime'] if operation in ('mask', 'unmask') else []
    subprocess.run([*prefix, *args, operation, '--', unit], check=True, timeout=30,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   pass_fds=lease_fds(lock_fd), env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})


def verify_definition(ctx, component, observation, plan):
    from runtime_lifecycle import validate_unit_effects, unit_definition
    deployment = getattr(ctx, 'deployment', None)
    if deployment is None:
        validate_unit_effects(service_tenant(ctx), component, observation)
    else:
        validate_unit_effects(service_tenant(ctx), component, observation, deployment=deployment)
    require(sha(encoded(unit_definition(observation))) == plan['service_definitions'][component],
            'Effective runtime service definition differs from the approved plan')


def close_services(ctx, plan, record, journal_path, lock_fd):
    if plan['quiesce'] == 'already_stopped':
        quiescent(ctx, lock_fd)
        return
    for component in ('bridge', 'gateway'):
        value = service_observation(ctx, component, lock_fd)
        require(value['Job'] in ('', '0'), 'Service job outcome is still pending')
        if value['LoadState'] != 'masked':
            verify_definition(ctx, component, value, plan)
        else:
            require(value['ActiveState'] == 'inactive' and value['MainPID'] == value['ControlPID'] == '0',
                    'A masked service is unexpectedly active')
        if value['ActiveState'] != 'inactive':
            require(value['ActiveState'] == 'active', 'Runtime service state is uncertain')
            require(record.get('service_intent') != component + ':stop',
                    'Previous service stop has an uncertain outcome; inspect without replay')
            record['service_intent'] = component + ':stop'
            save(journal_path, record)
            service_command(ctx, component, 'stop', lock_fd)
            _fault(component + ':stopped')
        if component == 'gateway' and value['LoadState'] != 'masked':
            record['service_intent'] = component + ':mask'
            save(journal_path, record)
            service_command(ctx, component, 'mask', lock_fd)
    quiescent(ctx, lock_fd)
    record['service_intent'] = None
    save(journal_path, record)


def maintenance_health(ctx):
    expected_version = verify_gate_sources(ctx)
    deadline = time.monotonic() + 15
    while True:
        connection = http.client.HTTPConnection('127.0.0.1', ctx.instance.bridge_port, timeout=2)
        try:
            connection.request('GET', '/healthz')
            answer = connection.getresponse()
            body = answer.read(65537)
            require(len(body) <= 65536, 'Unbounded restore health response')
            if answer.status in (200, 503):
                value = decode(body)
                if (isinstance(value, dict) and value.get('restore_maintenance') is True
                        and isinstance(value.get('readiness'), dict)
                        and value['readiness'].get('ready') is True
                        and value.get('version') == expected_version):
                    return
        except (OSError, ValueError, RecursionError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        require(time.monotonic() < deadline, 'Bridge maintenance startup is not verified')
        time.sleep(.1)


START_CONTEXT = ('WorkingDirectory', 'Environment', 'EnvironmentFiles', 'PassEnvironment',
                 'RootDirectory', 'RootImage', 'BindPaths', 'BindReadOnlyPaths', 'TemporaryFileSystem',
                 'User', 'Group', 'DynamicUser', 'SupplementaryGroups', 'NoNewPrivileges')


def validate_start_context(value, ctx, plan):
    deployment = getattr(ctx, 'deployment', None)
    working_directory, groups = str(ctx.project), ('',)
    if deployment is not None:
        deployment.check_current()
        working_directory = str(deployment.current)
        groups = ('', ctx.profile.as_dict()['services']['prefix'] + '-transcription')
        require(sha(encoded(value)) == ctx.start_context_sha256,
                'Deployment startup context differs from the approved plan')
    require(set(value) == set(START_CONTEXT)
            and value['WorkingDirectory'] == working_directory
            and value['User'] == plan['account']['name'] and value['Group'] == plan['account']['group']
            and value['DynamicUser'] == 'no' and value['NoNewPrivileges'] == 'yes'
            and value['SupplementaryGroups'] in groups
            and all(value[key] == '' for key in ('Environment', 'EnvironmentFiles', 'PassEnvironment',
                'RootDirectory', 'RootImage', 'BindPaths', 'BindReadOnlyPaths', 'TemporaryFileSystem')),
            'Maintenance start import context is not source-finite')


def validate_start_ex(raw, expected):
    """Legacy ExecStart omits the '+'/'!' privilege prefixes; require typed flags.

    ExecStartEx is the systemd D-Bus a(sasasttttuii) property. Older managers
    without it cannot authorize this restore path. No command flags are allowed.
    """
    value = decode(raw)
    require(isinstance(value, dict) and set(value) == {'type', 'data'}
            and value['type'] == 'a(sasasttttuii)' and isinstance(value['data'], list)
            and len(value['data']) == 1, 'Complete typed ExecStartEx identity is required')
    row = value['data'][0]
    require(isinstance(row, list) and len(row) == 10 and isinstance(row[0], str)
            and isinstance(row[1], list) and row[2] == []
            and all(type(item) is int for item in row[3:])
            and expected == [{'path': row[0], 'argv': row[1], 'ignore_errors': False}],
            'Maintenance startup flags or executable identity are not permitted')


def verify_gate_sources(ctx):
    """Attest both packages and return their reviewed literal version, without imports."""
    source = (ctx.project / 'sally_whatsapp').resolve(strict=True)
    packages = list((ctx.project / '.venv/lib').glob('python*/site-packages/sally_whatsapp'))
    require(len(packages) == 1, 'One installed bridge package is required for startup admission')
    versions = []
    for root in (source, packages[0].resolve(strict=True)):
        physical(root, protected=True, directory=True)
        version_source = None
        for name, digest in RESTORE_GATE_SOURCES.items():
            raw = protected_read(root / name)
            require(sha(raw) == digest,
                    'Installed backend does not match the reviewed restoration fence')
            if name == '__init__.py':
                version_source = raw
        require(version_source is not None, 'Reviewed version source is required')
        try:
            tree = ast.parse(version_source)
        except (SyntaxError, ValueError, RecursionError):
            raise ValueError('Reviewed version must be a single literal') from None
        statement = tree.body[0] if len(tree.body) == 1 else None
        require(isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name) and statement.targets[0].id == '__version__'
                and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str)
                and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', statement.value.value),
                'Reviewed version must be a single literal')
        versions.append(statement.value.value)
    require(versions[0] == versions[1], 'Installed and source versions differ')
    deployment = getattr(ctx, 'deployment', None)
    if deployment is not None:
        require(versions[0] == deployment.version, 'Deployment metadata differs from the reviewed source version')
    return versions[0]


def validate_manager_environment(raw):
    require(isinstance(raw, bytes) and len(raw) <= 256 * 1024, 'Unbounded service manager environment')
    for line in raw.decode().splitlines():
        key, delimiter, _ = line.partition('=')
        require(delimiter and not key.startswith(('PYTHON', 'LD_')),
                'Service manager environment can override the reviewed Python runtime')


def verify_start_context(ctx, plan, lock_fd):
    from runtime_lifecycle import command
    observation = service_observation(ctx, 'bridge', lock_fd)
    verify_definition(ctx, 'bridge', observation, plan)
    argv = command(service_tenant(ctx), 'bridge', 'ExecStart')
    argv[-1] = 'ExecStartEx'
    flags = subprocess.run(argv, capture_output=True, timeout=20, check=True, pass_fds=lease_fds(lock_fd),
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(len(flags.stdout) <= MAX_JSON, 'Unbounded typed start context')
    validate_start_ex(flags.stdout, observation['ExecStart'])
    from admin_deployment import read_start_context
    def read_start(argv):
        result = subprocess.run(argv, capture_output=True, timeout=20, check=True,
                                pass_fds=lease_fds(lock_fd),
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        require(len(result.stdout) <= 65536, 'Unbounded maintenance start context')
        return result.stdout
    validate_start_context(read_start_context(ctx.instance.base + '.service', read_start), ctx, plan)
    environment = subprocess.run(['/usr/bin/systemctl', 'show-environment'],
                                 capture_output=True, timeout=20, check=True, pass_fds=lease_fds(lock_fd),
                                 env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    validate_manager_environment(environment.stdout)
    # The finite argv is insufficient if Python can import a tenant-controlled
    # module from the current directory, venv, .pth or sitecustomize path.
    physical(ctx.project, protected=True, directory=True)
    venv = (ctx.project / '.venv').resolve(strict=True)
    configuration = {}
    for line in protected_read(venv / 'pyvenv.cfg').decode().splitlines():
        key, delimiter, value = line.partition('=')
        require(delimiter and key.strip() not in configuration, 'Ambiguous Python virtual environment')
        configuration[key.strip()] = value.strip()
    require(configuration.get('include-system-site-packages') == 'false',
            'Restore requires a virtual environment without global or user site packages')
    verify_gate_sources(ctx)
    start = observation['ExecStart'][0]['argv']
    deployment = getattr(ctx, 'deployment', None)
    if deployment is not None:
        require(venv == deployment.venv and start == deployment.command(),
                'Deployment interpreter or startup identity differs')
    elif start[1] != '-m':
        require(sha(protected_read(start[1])) == RELEASE_LAUNCHER_SHA256,
                'Release launcher differs from the reviewed restoration entry point')
    # The non-isolated bridge also imports from its working directory. Include
    # the complete project tree: namespace packages, bytecode and extensions
    # cannot be safely covered by checking only top-level .py files. Operational
    # tenant data lives outside the project; any mutable node here is rejected.
    # The admitted deploy-v1 argv uses Python -I: neither cwd nor the script
    # directory/project backup trees enter sys.path. Keep historical recovery
    # copies intact; attest the complete sealed venv actually imported instead.
    roots = ((venv,) if deployment is not None else
             tuple(dict.fromkeys((ctx.project, venv, (ctx.project / 'sally_whatsapp').resolve(strict=True)))))
    roots = tuple(root for root in roots if not any(root != other and root.is_relative_to(other) for other in roots))
    count = 0
    for root in roots:
        physical(root, protected=True, directory=True)
        for path in root.rglob('*'):
            count += 1
            require(count <= MAX_FILES, 'Runtime import tree exceeds its bound')
            resolved = path.resolve(strict=True)
            if resolved.is_dir():
                # rglob does not descend into symlink directories. Admit only
                # aliases of directories covered by another attested tree too;
                # release installations use a project/.venv directory symlink.
                require(any(resolved.is_relative_to(admitted) for admitted in roots),
                        'Runtime import directory escapes its attested root')
            physical(resolved, protected=True, directory=resolved.is_dir())
            if path.suffix == '.pth':
                content = protected_read(resolved).decode()
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    require(not line.startswith(('import ', 'import\t')),
                            'Executable Python path hooks need separate review before maintenance start')
                    location = Path(line)
                    location = location if location.is_absolute() else path.parent / location
                    location = location.resolve(strict=True)
                    # A protected directory alone does not attest its children:
                    # sitecustomize or a dependency there could be tenant-writable.
                    require(location.is_relative_to(venv),
                            'Python path hook escapes the attested virtual environment')
                    physical(location, protected=True, directory=True)


def startup_admission(ctx, plan, lock_fd):
    """Close imports/privilege drift before any marker, stop or data mutation."""
    if plan['quiesce'] == 'stop':
        value = service_observation(ctx, 'bridge', lock_fd)
        if value['LoadState'] != 'masked':
            verify_start_context(ctx, plan, lock_fd)
        else:
            require(plan['restore_service_state'] == 'remain_stopped',
                    'Masked bridge cannot establish the approved maintenance startup contract')
    else:
        # An already-stopped plan with no reviewed startup definition is only
        # safe when neither named unit can be started during the directory swap.
        for component in ('bridge', 'gateway'):
            value = service_observation(ctx, component, lock_fd)
            require(value['LoadState'] == 'masked' and value['ActiveState'] == 'inactive',
                    'Already-stopped restore requires both named units masked and inactive')


def finish_services(ctx, plan, record, journal_path, lock_fd):
    if plan['restore_service_state'] == 'remain_stopped':
        quiescent(ctx, lock_fd)
        return
    value = service_observation(ctx, 'bridge', lock_fd)
    require(value['Job'] in ('', '0'), 'Maintenance startup outcome is still pending')
    if value['LoadState'] == 'masked':
        require(value['UnitFileState'] == 'masked-runtime', 'Persistent bridge mask requires separate authorization')
        service_command(ctx, 'bridge', 'unmask', lock_fd)
        value = service_observation(ctx, 'bridge', lock_fd)
    verify_definition(ctx, 'bridge', value, plan)
    verify_start_context(ctx, plan, lock_fd)
    if value['ActiveState'] != 'active':
        require(value['ActiveState'] == 'inactive' and not record.get('restart_intent'),
                'Previous maintenance startup has an uncertain outcome; inspect without replay')
        record['restart_intent'] = True
        save(journal_path, record)
        service_command(ctx, 'bridge', 'start', lock_fd)
    maintenance_health(ctx)


def apply(plan, *, administration=None):
    """Apply/resume a protected plan; all mutable destinations are derived."""
    validate(plan)
    from host_integration import load_administration, runtime_admission
    from installation_layout import active
    administration = load_administration() if administration is None else administration
    initial = administration.load_generation(states=('dedicated',))
    require(owner_record(initial) == plan['owner'], 'Restore owner/generation changed')
    with runtime_admission(active().path('project'), administration=administration) as lock_fd:
        current_owner = administration.load_generation(states=('dedicated',))
        require(owner_record(current_owner) == plan['owner'], 'Restore owner changed under lease')
        ctx = context(plan, administration)
        for target in targets(ctx).values():
            with target_parent(ctx, target):
                pass
        physical(ctx.state.parent, protected=True, directory=True)
        if not ctx.state.exists():
            ctx.state.mkdir(mode=0o700)
            sync_directory(ctx.state.parent)
        physical(ctx.state, protected=True, directory=True)
        unfinished(ctx, plan['id'])
        directory = ctx.state / plan['id']
        digest = sha(encoded(plan))
        journal_path = directory / 'journal.json'
        if not directory.exists():
            # Establish snapshot validity before downtime or any live mutation.
            snapshot_admission(plan, ctx, lock_fd)
            if plan['preimage_policy'] == 'exact_digest':
                require(current_digest(ctx) == plan['current_sha256'], 'Current data changed after restore approval')
            directory.mkdir(mode=0o700)
            sync_directory(ctx.state)
            record = {'format': FORMAT, 'id': plan['id'], 'instance': plan['instance'],
                      'plan_sha256': digest, 'phase': 'closing', 'before': None,
                      'after': None, 'service_intent': None, 'restart_intent': False}
            save(journal_path, record)
        physical(directory, protected=True, directory=True)
        _recover_pending(journal_path, digest)
        record = decode(protected_read(journal_path))
        require(record.get('plan_sha256') == digest and record.get('instance') == ctx.instance.slug,
                'Restore identifier already belongs to another plan')
        def receipt():
            return {'id': plan['id'], 'state': 'completed', 'instance': ctx.instance.slug,
                    'data_restored': True, 'services_started': plan['restore_service_state'] == 'maintenance',
                    'maintenance_active': True, 'gateway_started': False, 'preimages_retained': True}
        if record['phase'] == 'completed':
            return receipt()
        startup_admission(ctx, plan, lock_fd)
        maintenance_marker(ctx, plan)
        if record['phase'] == 'closing':
            close_services(ctx, plan, record, journal_path, lock_fd)
            if plan['preimage_policy'] == 'exact_digest':
                require(current_digest(ctx) == plan['current_sha256'], 'Current data changed while quiescing')
            record['before'] = {key: inventory(path) for key, path in targets(ctx).items()}
            record['phase'] = 'staging'
            save(journal_path, record)
        if record['phase'] == 'staging':
            quiescent(ctx, lock_fd)
            require({key: inventory(path) for key, path in targets(ctx).items()} == record['before'],
                    'Current data changed while staging')
            if (directory / 'new').exists():
                attempt = next((index for index in range(8)
                                if not (directory / ('incomplete-' + str(index))).exists()), None)
                require(attempt is not None, 'Too many retained staging attempts; reconciliation required')
                os.rename(directory / 'new', directory / ('incomplete-' + str(attempt)))
                sync_directory(directory)
            record['after'] = stage(plan, ctx, directory, lock_fd)
            record['phase'] = 'prepared'
            save(journal_path, record)
            _fault('prepared')
        if record['phase'] in ('prepared', 'swapping'):
            current = targets(ctx)
            require(set(record['before']) == set(record['after']) == set(current), 'Restore journal destinations differ')
            old = directory / 'old'
            if not old.exists():
                old.mkdir(mode=0o700)
                sync_directory(directory)
            record['phase'] = 'swapping'
            save(journal_path, record)
            for key, target in current.items():
                quiescent(ctx, lock_fd)
                require(owner_record(administration.load_generation(states=('dedicated',))) == plan['owner'],
                        'Restore owner changed during the transaction')
                physical(target.parent, directory=True)
                require(target.parent.stat().st_dev == directory.stat().st_dev, 'Restore needs atomic same-filesystem swaps')
                previous, staged = old / key, directory / 'new' / key
                actual, saved, pending = inventory(target), inventory(previous), inventory(staged)
                before, after = record['before'][key], record['after'][key]
                if actual == after and pending is None and saved == before:
                    continue
                require(pending == after and saved in (None, before), 'Restore staged or retained data changed')
                if saved is None and before is not None:
                    require(actual == before, 'Restore current data changed before quarantine')
                    swap(ctx, target, previous, target)
                    _fault(key + ':quarantined')
                    actual = None
                require(actual is None, 'Restore destination is occupied by unrecognized data')
                swap(ctx, staged, target, target)
                _fault(key + ':published')
                require(inventory(target) == after and inventory(previous) == before, 'Restore swap verification failed')
            record['phase'] = 'data_restored'
            save(journal_path, record)
        require(record['phase'] == 'data_restored', 'Unknown restore phase')
        maintenance_marker(ctx, plan, phase='maintenance')
        finish_services(ctx, plan, record, journal_path, lock_fd)
        record['phase'] = 'completed'
        save(journal_path, record)
        return receipt()


def inspect_runtime(instance, *, reader=None):
    """Read-only qualification and binding material; never prepare/apply a restore."""
    from installation_layout import active
    from admin_deployment import leases, load, read_start_context
    profile = active()
    with leases(profile) as descriptors:
        deployment = load(profile, instance)
        require(deployment is not None, 'This inspection requires an installed deploy-v1 profile')
        project = Path(profile.path('project'))
        require((project / '.venv').resolve(strict=True) == deployment.venv,
                'Administrative interpreter differs from the admitted deployment')
        if reader is None:
            def reader(argv):
                answer = subprocess.run(argv, capture_output=True, timeout=20, check=True,
                                        pass_fds=descriptors, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
                require(len(answer.stdout) <= 65536, 'Unbounded deployment inspection')
                return answer.stdout
        values = read_start_context(deployment.instance['unit'], reader)
        start_digest = sha(encoded(values))
        ctx = SimpleNamespace(project=project, profile=profile, deployment=deployment, start_context_sha256=start_digest)
        account = pwd.getpwnam(deployment.instance['user'])
        require(account.pw_uid == deployment.instance['uid'] and account.pw_gid == deployment.instance['gid'],
                'Deployment account numeric identity differs')
        validate_start_context(values, ctx, {'account': {'name': account.pw_name,
                                                      'group': grp.getgrgid(account.pw_gid).gr_name}})
        from runtime_lifecycle import layout, unit_definition
        service = layout(instance)
        ctx.uid, ctx.gid = account.pw_uid, account.pw_gid
        ctx.instance = SimpleNamespace(slug=instance, base=deployment.instance['unit'][:-8],
                                       wrapper=Path(service['wrapper']))
        observation = service_observation(ctx, 'bridge', descriptors[-1])
        approved = {'account': {'name': account.pw_name, 'group': grp.getgrgid(account.pw_gid).gr_name},
                    'service_definitions': {'bridge': sha(encoded(unit_definition(observation)))}}
        verify_start_context(ctx, approved, descriptors[-1])
        version = verify_gate_sources(ctx)
        deployment.check_current()
        return {'action': 'inspect-runtime', 'instance': instance, 'version': version,
                'runtime': {'deployment': deployment.binding, 'start_context_sha256': start_digest},
                'source_gate_verified': True, 'runtime_seal_verified': True,
                'startup_contract_verified': True,
                'restore_executed': False, 'services_changed': False, 'data_opened': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['apply', 'inspect-runtime'])
    parser.add_argument('--plan')
    parser.add_argument('--sha256')
    parser.add_argument('--instance')
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, 'Restore entry point requires the admitted administrative account')
    if args.action == 'inspect-runtime':
        require(args.instance and args.plan is None and args.sha256 is None,
                'Inspection needs one instance and cannot accept a restore plan')
        print(json.dumps(inspect_runtime(args.instance), sort_keys=True))
        return
    require(args.plan and args.instance is None, 'Apply needs the approved plan and no instance override')
    require(hexid(args.sha256), 'An exact approved plan digest is required')
    content = protected_read(args.plan)
    require(sha(content) == args.sha256, 'Restore plan differs from approval')
    print(json.dumps(apply(decode(content)), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Restore not completed; retain journals and inspect the approved operation') from None

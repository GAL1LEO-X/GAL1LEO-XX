"""Durable, opt-in provisioning of a new configured instance.

Only the admitted administrator invokes this module. A tenant never supplies paths,
commands, UID values or cleanup manifests. Unknown/changed resources are retained.
External host publications are recovered by their existing pinned protocols, never
rolled back by retiring the installation's other consumers.
"""
from contextlib import contextmanager
from dataclasses import replace
import argparse
import ctypes
import errno
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess

FORMAT = 'whatsapp-provisioning-attempt-v1'
TERMINAL = ('prepared', 'cancelled')
SUBORDINATE_REGISTRIES = ('/etc/subuid', '/etc/subgid')


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def physical(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Physical absolute path required')
    for ancestor in reversed(path.parents):
        require(not ancestor.is_symlink(), 'Symlink ancestor refused')
    require(not path.is_symlink(), 'Symlink resource refused')
    return path


def identity(path):
    path = physical(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'Unexpected resource type')
    result = {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
              'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
              'kind': 'directory' if stat.S_ISDIR(info.st_mode) else 'file'}
    if result['kind'] == 'file':
        require(info.st_nlink == 1, 'Hardlinked resource refused')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            require((info.st_dev, info.st_ino) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino), 'Resource replaced')
            hasher = hashlib.sha256()
            while block := os.read(fd, 1024 * 1024):
                hasher.update(block)
            result['sha256'] = hasher.hexdigest()
        finally:
            os.close(fd)
    return result


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_private(path):
    record = identity(path)
    require(record is not None and record['kind'] == 'file' and record['uid'] == os.geteuid()
            and record['mode'] == 0o600, 'Protected administrative receipt required')
    return json.loads(Path(path).read_bytes())


def save_private(path, value):
    path = physical(path)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(encoded(value)); stream.flush(); os.fsync(fd)
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        os.close(fd)
        temporary.unlink(missing_ok=True)


def rename_exclusive(source, target):
    """Linux atomic no-clobber publication for both directories and files."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(target), 1):
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(target))
    sync_directory(Path(target).parent)


def root_for(instance):
    return instance.project_root / 'private' / 'provisioning-attempts'


def gate_path(instance):
    return root_for(instance) / ('gate-' + instance.slug + '.json')


def guard_activation(instance):
    marker = instance.config_dir / 'restore-maintenance.json'
    require(not (marker.exists() or marker.is_symlink()),
            'Restore maintenance requires explicit reconciliation before activation/resume')
    path = gate_path(instance)
    if path.exists() or path.is_symlink():
        gate = read_private(path)
        require(gate.get('state') == 'prepared',
                'Provisioning is incomplete, uncertain or cancelling; activation/resume is fenced')


def account_identity(name):
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        return None
    try:
        group = grp.getgrgid(account.pw_gid)
    except KeyError:
        raise ValueError('Runtime primary group missing') from None
    return {'name': account.pw_name, 'uid': account.pw_uid, 'gid': account.pw_gid,
            'home': account.pw_dir, 'shell': account.pw_shell, 'marker': account.pw_gecos,
            'group': group.gr_name, 'members': sorted(group.gr_mem)}


def subordinate_rows(path):
    """Read the complete registry before deciding what an account command owns."""
    rows = [row for row in Path(path).read_text().splitlines() if row]
    for row in rows:
        parts = row.split(':')
        require(len(parts) == 3 and parts[0] and not any(char.isspace() for char in parts[0])
                and not parts[0].startswith('+') and re.fullmatch(r'[0-9]+', parts[1])
                and re.fullmatch(r'[0-9]+', parts[2]) and int(parts[2]) > 0,
                'Subordinate registry is not completely attributable')
    return rows


def account_subordinates(rows, name, account=None):
    """Shadow accepts names and numeric UIDs (including equivalent aliases).

    Treat zero-padded numeric IDs conservatively as aliases too. Rows written
    using any representation other than our exact recorded name are never
    adopted or passed to usermod/userdel for removal.
    """
    uid = None if account is None else account['uid']
    names = {name}
    if uid is not None:
        names.update(row.pw_name for row in pwd.getpwall() if row.pw_uid == uid)
    return [row for row in rows if row.split(':')[0] in names or
            uid is not None and re.fullmatch(r'[0-9]+', row.split(':')[0])
            and int(row.split(':')[0]) == uid]


def verify_subordinates(name, account, effects, *, empty=False):
    """All matching rows in both registries need exact attempt provenance.

    userdel removes subordinate ranges implicitly. Its admission therefore
    requires both registries empty for this identity, even when no subordinate
    effect was ever recorded or an earlier removal was already checkpointed.
    """
    for path in SUBORDINATE_REGISTRIES:
        rows = account_subordinates(subordinate_rows(path), name, account)
        effect = next((row for key, row in effects.items() if key.startswith('subid:')
                       and Path(key.split(':', 1)[1]) == Path(path)), None)
        expected = None if empty or not effect or effect['state'] == 'compensated' else effect['entry']
        require(not rows or expected is not None and rows == [expected]
                and expected.split(':')[0] == name,
                'Subordinate allocations lack exact attempt provenance: ' + path)


def verify_account_memberships(name, account=None):
    # useradd/initgroups would activate stale supplementary grants; userdel
    # would subsequently remove them without any attempt attribution.
    require(not any(name in group.gr_mem for group in grp.getgrall()),
            'Supplementary group membership has no attempt provenance')
    if account is not None:
        require(not any(row.pw_uid == account['uid'] and row.pw_name != name for row in pwd.getpwall()),
                'Another account shares the runtime UID')


class Attempt:
    """One immutable instance/plan binding, with a durable per-instance fence.

    The caller holds runtime_admission (owner/generation plus global tenant lease).
    This additional lock excludes direct concurrent use of the same journal. All
    public methods are synchronous and all checkpoint boundaries are injectable.
    """
    def __init__(self, instance, host, attempt_id, *, fault=None, create=True):
        require(isinstance(attempt_id, str) and re.fullmatch('[a-f0-9]{32}', attempt_id), 'Invalid attempt ID')
        require(instance.auth_mode == 'external-oidc' and not instance._installation_identity.compatibility,
                'Tracked provisioning requires a configured external-OIDC installation')
        self.instance, self.host, self.id = instance, host, attempt_id
        self.fault = fault or (lambda _: None)
        self.root = root_for(instance)
        self.path = self.root / (attempt_id + '.json')
        self.binding = {'format': FORMAT, 'id': attempt_id, 'instance': instance.record(),
                        'installation_sha256': instance._installation_identity.sha256,
                        'allocation_sha256': instance._installation_identity.roster_sha256,
                        'host_plan_sha256': host.plan_digest,
                        'host_operation_id': host.plan['operation_id']}
        self.create = create
        self.fd = None

    def __enter__(self):
        physical(self.root.parent)
        parent = identity(self.root.parent)
        require(parent and parent['kind'] == 'directory' and parent['uid'] == os.geteuid()
                and not parent['mode'] & 0o077, 'Protected private project root is required')
        if self.create:
            self.root.mkdir(mode=0o700, exist_ok=True)
        container = physical(self.instance.private_dir.parent)
        if self.create:
            container.mkdir(mode=0o700, exist_ok=True)
        parent_info = identity(container)
        require(parent_info and parent_info['kind'] == 'directory' and parent_info['uid'] == os.geteuid()
                and parent_info['mode'] == 0o700, 'Tenant private container is not protected')
        info = identity(self.root)
        require(info and info['kind'] == 'directory' and info['uid'] == os.geteuid()
                and info['mode'] == 0o700, 'Provisioning journal root is not protected')
        lock = self.root / 'lease'
        self.fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(self.fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'Invalid provisioning lease')
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require((lock.lstat().st_dev, lock.lstat().st_ino) == (info.st_dev, info.st_ino), 'Lease replaced')
            if self.path.exists() or self.path.is_symlink():
                self.data = read_private(self.path)
                require(self.data.get('binding') == self.binding, 'Attempt belongs to different inputs or generation')
            else:
                require(self.create, 'Attempt receipt is missing; historical provisioning cannot be adopted')
                require(not gate_path(self.instance).exists(), 'Instance already has a provisioning attempt')
                registry_path = self.instance.project_root / 'private/tenants.json'
                if registry_path.exists():
                    require(self.instance.slug not in read_private(registry_path).get('instances', {}),
                            'Historical provisioning cannot be adopted by a new attempt')
                if hasattr(self.host, 'resumes_runtime'):
                    require(not self.host.resumes_runtime(), 'Historical host effects need their original recovery')
                paths = self.resource_roots()
                require(all(identity(path) is None for path in paths), 'Preexisting runtime resources cannot be adopted')
                require(account_identity(self.instance.service_user) is None, 'Preexisting account cannot be adopted')
                try:
                    grp.getgrnam(self.instance.service_user)
                except KeyError:
                    pass
                else:
                    raise ValueError('Preexisting group cannot be adopted')
                self.data = {'binding': self.binding, 'state': 'preparing', 'resources': [], 'effects': {},
                             'account': None, 'residuals': []}
                self.save('intent')
            gate = gate_path(self.instance)
            if gate.exists():
                old = read_private(gate)
                require(old['attempt_id'] == self.id and old['host_plan_sha256'] == self.host.plan_digest,
                        'Instance gate belongs to another attempt')
            self.save('admitted')
            return self
        except BaseException:
            os.close(self.fd); self.fd = None
            raise

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd); self.fd = None

    def resource_roots(self):
        return [self.instance.config_dir, self.instance.state_dir, self.instance.gateway_home,
                self.instance.private_dir, Path('/etc/systemd/system') / (self.instance.base + '.service')]

    def save(self, boundary):
        save_private(self.path, self.data)
        save_private(gate_path(self.instance), {'attempt_id': self.id, 'host_plan_sha256': self.host.plan_digest,
                                               'state': self.data['state']})
        self.fault(boundary)

    def status(self):
        return {'attempt_id': self.id, 'target': self.instance.slug, 'state': self.data['state'],
                'host_plan_sha256': self.host.plan_digest,
                'allocation_released': False, 'instance_reusable': False,
                'administrative_records_retained': True,
                'resources': [{'path': row['path'], 'state': row['state'], 'kind': row['identity']['kind']}
                              for row in self.data['resources']],
                'effects': {name: row['state'] for name, row in self.data['effects'].items()},
                'residuals': list(self.data['residuals'])}

    def _allowed(self, path):
        path = physical(path)
        require(any(path == root or path.is_relative_to(root) for root in self.resource_roots()),
                'Resource is outside this instance')
        require(path.parent.is_dir(), 'Resource parent is missing')
        return path

    def publish(self, path, *, content=None, mode=0o700, uid=0, gid=0):
        """Stage -> persist inode/hash -> no-replace rename -> persist published.

        A crash after rename is attributable through the already durable inode.
        An unrecorded staging orphan is never adopted or deleted automatically.
        """
        require(self.data['state'] in ('preparing', 'recovery_required'), 'Attempt cannot create resources in this state')
        path = self._allowed(path)
        prior = next((row for row in self.data['resources'] if row['path'] == str(path)), None)
        if prior is not None:
            expected = prior['identity']
            actual = identity(path)
            if actual is None and prior['state'] == 'staged':
                stage = Path(prior['staging'])
                require(identity(stage) == expected, 'Staged resource changed; preserve it')
                rename_exclusive(stage, path)
                self.fault('published:' + str(path))
                actual = identity(path)
            require(actual == expected and prior['state'] != 'removed', 'Attempt resource changed or was removed')
            prior['state'] = 'published'; self.save('recorded:' + str(path))
            return
        require(identity(path) is None, 'Refusing to overwrite a preexisting resource')
        stage = path.with_name('.wa-' + self.id + '-' + digest(str(path).encode())[:12])
        require(identity(stage) is None, 'Unrecorded staging resource requires reconciliation')
        if content is None:
            stage.mkdir(mode=0o700)
        else:
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, 'wb', closefd=False) as stream:
                    stream.write(content); stream.flush(); os.fsync(fd)
            finally:
                os.close(fd)
        os.chown(stage, uid, gid, follow_symlinks=False)
        os.chmod(stage, mode, follow_symlinks=False)
        sync_directory(stage.parent)
        record = {'path': str(path), 'staging': str(stage), 'identity': identity(stage), 'state': 'staged'}
        self.data['resources'].append(record)
        self.save('staged:' + str(path))
        require(identity(stage) == record['identity'], 'Staged resource changed before publication')
        rename_exclusive(stage, path)
        self.fault('published:' + str(path))
        require(identity(path) == record['identity'], 'Published resource changed before receipt')
        record['state'] = 'published'
        self.save('recorded:' + str(path))

    def effect(self, name, action, *, recoverable=False):
        """External adapters must supply their own exact idempotent admission.

        Non-idempotent effects are not reissued after a lost result. Their public
        state remains recovery_required, with named residuals and the gate held.
        """
        require(self.data['state'] in ('preparing', 'recovery_required'), 'Attempt is fenced against further preparation')
        row = self.data['effects'].get(name)
        if row and row['state'] == 'completed' and name not in self.data['residuals']:
            return
        if row and not recoverable:
            self.data['state'] = 'recovery_required'
            self.data['residuals'] = sorted(set(self.data['residuals']) | {name})
            self.save('uncertain:' + name)
            raise ValueError('Outcome requires reconciliation before retry: ' + name)
        self.data['effects'][name] = {'state': 'pending', 'recoverable': recoverable}
        self.save('before:' + name)
        action()
        self.fault('after:' + name)
        self.data['effects'][name]['state'] = 'completed'
        self.data['residuals'] = [item for item in self.data['residuals'] if item != name]
        self.save('done:' + name)

    def create_account(self, run):
        marker = 'wa-attempt-' + self.id + '-' + self.host.plan_digest[:16]
        actual = account_identity(self.instance.service_user)
        stored = self.data['account']
        if stored is not None:
            require(actual == stored, 'Service UID or account identity changed')
            require(self.check_account_dependencies(), 'Subordinate allocations require reconciliation')
            return pwd.getpwnam(self.instance.service_user)
        pending = self.data['effects'].get('account')
        if actual is None:
            require(not pending or pending['state'] == 'pending', 'Account disappeared after provisioning')
            # A group without the marked account is not attributed to this attempt.
            try:
                grp.getgrnam(self.instance.service_user)
            except KeyError:
                pass
            else:
                raise ValueError('Unattributed group after account creation; preserve it')
            require(self.check_account_dependencies(empty=True), 'Preexisting subordinate allocations require reconciliation')
            self.data['effects']['account'] = {'state': 'pending', 'recoverable': True}
            self.save('before:account')
            require(self.check_account_dependencies(empty=True), 'Subordinate allocations changed before account creation')
            run(['useradd', '--system', '--user-group', '--no-create-home', '--comment', marker,
                 '--home-dir', str(self.instance.gateway_home), '--shell', '/usr/sbin/nologin', self.instance.service_user])
            self.fault('after:account')
            actual = account_identity(self.instance.service_user)
        require(actual and actual['marker'] == marker and actual['home'] == str(self.instance.gateway_home)
                and actual['shell'] == '/usr/sbin/nologin' and actual['group'] == self.instance.service_user
                and actual['uid'] > 0 and actual['gid'] > 0 and actual['members'] == [],
                'Account creation has no exact attempt provenance')
        self.data['account'] = actual
        self.data['effects']['account'] = {'state': 'completed', 'recoverable': True}
        self.save('done:account')
        require(self.check_account_dependencies(), 'Assigned UID has subordinate allocations requiring reconciliation')
        return pwd.getpwnam(self.instance.service_user)

    def check_account_dependencies(self, *, empty=False):
        try:
            verify_subordinates(self.instance.service_user, self.data['account'], self.data['effects'], empty=empty)
            verify_account_memberships(self.instance.service_user, self.data['account'])
        except (OSError, ValueError):
            self.data['state'] = 'recovery_required'
            self.data['residuals'] = sorted(set(self.data['residuals']) | {'account-dependencies'})
            self.save('account-dependencies-recovery-required')
            return False
        self.data['residuals'] = [item for item in self.data['residuals'] if item != 'account-dependencies']
        return True

    def subordinate(self, path, flag, run):
        name = 'subid:' + str(path)
        account = self.data['account']
        require(account is not None and account_identity(self.instance.service_user) == account,
                'Exact account identity required before subordinate allocation')
        rows = subordinate_rows(path)
        selected = account_subordinates(rows, self.instance.service_user, account)
        effect = self.data['effects'].get(name)
        if effect:
            expected = effect['entry']
            if selected == [expected]:
                self.check_subordinate_overlap(rows, expected)
                require(self.check_account_dependencies(), 'Account dependencies require reconciliation')
                effect['state'] = 'completed'; self.save('done:' + name); return
            require(not selected and effect['state'] == 'pending', 'Subordinate identity changed')
        else:
            require(not selected, 'Preexisting subordinate ranges cannot be adopted')
            start = max([100000] + [int(line.split(':')[1]) + int(line.split(':')[2]) for line in rows if line])
            expected = f'{self.instance.service_user}:{start}:65536'
            effect = {'state': 'pending', 'entry': expected, 'recoverable': True}
            self.data['effects'][name] = effect; self.save('before:' + name)
        start, count = map(int, expected.split(':')[1:])
        rows = subordinate_rows(path)
        require(not account_subordinates(rows, self.instance.service_user, account),
                'Subordinate account entry appeared before allocation')
        # Recheck conflicts immediately before effect, retaining unrelated rows.
        for line in rows:
            if line and line.split(':')[0] != self.instance.service_user:
                begin, length = map(int, line.split(':')[1:])
                require(start + count <= begin or begin + length <= start, 'Subordinate range acquired by another account')
        require(self.check_account_dependencies(), 'Account dependencies changed before subordinate allocation')
        run(['usermod', flag, f'{start}-{start + count - 1}', self.instance.service_user])
        self.fault('after:' + name)
        verified = subordinate_rows(path)
        require(account_subordinates(verified, self.instance.service_user, account) == [expected],
                'Subordinate allocation was not verified')
        self.check_subordinate_overlap(verified, expected)
        require(self.check_account_dependencies(), 'Account dependencies changed during subordinate allocation')
        effect['state'] = 'completed'; self.save('done:' + name)

    @staticmethod
    def check_subordinate_overlap(rows, expected):
        owner, lower, count = expected.split(':')
        lower, count = int(lower), int(count)
        for line in rows:
            if line and line.split(':')[0] != owner:
                begin, length = map(int, line.split(':')[1:])
                require(lower + count <= begin or begin + length <= lower,
                        'Subordinate range overlaps another account; preserve and reconcile')

    def finish(self):
        require(all(row['state'] == 'completed' for row in self.data['effects'].values()), 'Incomplete external effects')
        require(self.check_account_dependencies(), 'Account dependencies require reconciliation')
        require(not self.data['residuals'], 'Unreconciled provisioning resources')
        self.data['state'] = 'prepared'; self.save('prepared')

    def cancel(self, system):
        """Compensate only exact resources, preserving unknown additions/changes.

        No recursion, userdel -r, shared-owner retirement or broad ACL reset.
        The system adapter verifies account provenance, processes and mounts.
        """
        require(self.data['state'] != 'prepared', 'Completed instances use explicit suspension/retirement')
        if self.data['state'] == 'cancelled':
            return self.status()
        self.data['state'] = 'cancelling'; self.save('cancelling')
        # Account loss/reuse must block even file cleanup. A new user with the same
        # UID is not evidence that the old attempt still owns its former files.
        actual = account_identity(self.instance.service_user)
        if self.data['account'] is None and actual is not None:
            self.create_account_for_cancel(actual)
        removal = self.data['effects'].get('account', {}).get('state')
        removing = removal in ('removing_user', 'user_removed', 'removing_group', 'compensated')
        require(actual == self.data['account'] or removing and actual is None
                and all(row['state'] == 'removed' for row in self.data['resources']),
                'Account identity changed; cancellation stopped')
        if not self.check_account_dependencies():
            return self.status()
        residuals = []
        external = [name for name, row in self.data['effects'].items()
                    if name != 'account' and not name.startswith('subid:')]
        if external:
            # Host/QoS/certificates and user-manager effects carry independent
            # journals. Their exact resume is supported; blind inverse is not.
            self.data['state'] = 'recovery_required'
            self.data['residuals'] = sorted(external)
            self.save('external-recovery-required')
            return self.status()
        if not removing:
            system.quiescent(self.data['account'], self.resource_roots())
            if not self.check_account_dependencies():
                return self.status()
        # Preflight the entire manifest before deleting anything. Unknown children
        # and modified files are preserved; no early parent removal is possible.
        known = {Path(row[key]) for row in self.data['resources'] if row['state'] != 'removed'
                 for key in ('path', 'staging')}
        for row in self.data['resources']:
            if row['state'] == 'removed':
                continue
            path, stage = Path(row['path']), Path(row['staging'])
            actual = identity(path)
            candidate = path if actual is not None else stage
            observed = actual if actual is not None else identity(stage)
            if observed is None and row['state'] == 'removing':
                row['state'] = 'removed'; continue
            if observed != row['identity']:
                residuals.append(str(path)); continue
            if observed['kind'] == 'directory' and any(child not in known for child in candidate.iterdir()):
                residuals.append(str(path))
        if residuals:
            self.data['state'] = 'recovery_required'; self.data['residuals'] = sorted(residuals)
            self.save('resources-changed'); return self.status()
        for row in reversed(self.data['resources']):
            if row['state'] == 'removed':
                continue
            path = Path(row['path'])
            if identity(path) is None:
                path = Path(row['staging'])
            system.quiescent(self.data['account'], self.resource_roots())
            require(identity(path) == row['identity'], 'Resource changed immediately before compensation')
            row['state'] = 'removing'; self.save('before-remove:' + row['path'])
            system.quiescent(self.data['account'], self.resource_roots())
            if not self.check_account_dependencies():
                return self.status()
            require(identity(path) == row['identity'], 'Resource changed after compensation intent')
            if row['identity']['kind'] == 'directory':
                path.rmdir()
            else:
                path.unlink()
            sync_directory(path.parent)
            self.fault('after-remove:' + row['path'])
            row['state'] = 'removed'; self.save('removed:' + row['path'])
        for name, row in reversed(list(self.data['effects'].items())):
            if name.startswith('subid:') and row['state'] != 'compensated':
                if not self.check_account_dependencies():
                    return self.status()
                try:
                    system.remove_subordinate(self.data['account'], name.split(':', 1)[1], row['entry'])
                except (OSError, ValueError):
                    if not self.check_account_dependencies():
                        return self.status()
                    raise
                row['state'] = 'compensated'; self.save('removed:' + name)
        if self.data['account'] is not None:
            account = self.data['account']
            row = self.data['effects']['account']
            if row['state'] not in ('user_removed', 'removing_group', 'compensated'):
                if not self.check_account_dependencies(empty=True):
                    return self.status()
                row['state'] = 'removing_user'; self.save('before-remove:user')
                if not self.check_account_dependencies(empty=True):
                    return self.status()
                try:
                    system.remove_user(account)
                except (OSError, ValueError):
                    if not self.check_account_dependencies(empty=True):
                        return self.status()
                    raise
                self.fault('after-remove:user')
                row['state'] = 'user_removed'; self.save('removed:user')
            if row['state'] != 'compensated':
                row['state'] = 'removing_group'; self.save('before-remove:group')
                system.remove_group(account)
                self.fault('after-remove:group')
                row['state'] = 'compensated'; self.save('removed:group')
            self.data['retired_account'] = account
            self.data['account'] = None; self.save('removed:account')
        self.data['state'] = 'cancelled'; self.data['residuals'] = []; self.save('cancelled')
        return self.status()

    def create_account_for_cancel(self, actual):
        pending = self.data['effects'].get('account')
        marker = 'wa-attempt-' + self.id + '-' + self.host.plan_digest[:16]
        require(pending and pending['state'] == 'pending' and actual['marker'] == marker
                and actual['group'] == self.instance.service_user and actual['members'] == []
                and actual['home'] == str(self.instance.gateway_home) and actual['shell'] == '/usr/sbin/nologin'
                and actual['uid'] > 0 and actual['gid'] > 0, 'Unattributed account cannot be removed')
        self.data['account'] = actual; pending['state'] = 'completed'; self.save('reconciled:account')


class System:
    def __init__(self, runner=None):
        self.runner = runner or subprocess.run
        self.production = runner is None

    def run(self, args, **kwargs):
        options = {'check': True, 'capture_output': True,
                   'env': {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, **kwargs}
        if self.production:
            from host_integration import command_options
            options = command_options(options)
        return self.runner(args, **options)

    def quiescent(self, account, roots):
        if account is None:
            return
        require(account_identity(account['name']) == account, 'Runtime account changed')
        uid = account['uid']
        for item in Path('/proc').iterdir():
            if item.name.isdigit():
                try:
                    lines = (item / 'status').read_text().splitlines()
                except FileNotFoundError:
                    continue
                ids = next((line.split()[1:] for line in lines if line.startswith('Uid:')), [])
                require(str(uid) not in ids, 'Runtime processes still exist; no resource removal is allowed')
        mount_data = Path('/proc/self/mountinfo').read_text().splitlines()
        for line in mount_data:
            mounted = Path(line.split()[4].replace('\\040', ' ').replace('\\134', '\\'))
            require(not any(mounted == root or mounted.is_relative_to(root) for root in roots),
                    'Runtime mount remains; no resource removal is allowed')
        linger = Path('/var/lib/systemd/linger') / account['name']
        require(not linger.exists(), 'Linger remains enabled; recover the exact service step first')

    def remove_subordinate(self, account, path, entry):
        require(account_identity(account['name']) == account, 'Account changed before subordinate compensation')
        require(path in ('/etc/subuid', '/etc/subgid'), 'Unsupported subordinate registry')
        rows = subordinate_rows(path)
        own = account_subordinates(rows, account['name'], account)
        if not own:
            return
        require(own == [entry], 'Subordinate ranges changed')
        verify_account_memberships(account['name'], account)
        begin, count = map(int, entry.split(':')[1:])
        self.run(['usermod', '--del-subuids' if path.endswith('subuid') else '--del-subgids',
                  f'{begin}-{begin + count - 1}', account['name']])
        require(not account_subordinates(subordinate_rows(path), account['name'], account),
                'Subordinate compensation was not verified')

    def remove_user(self, account):
        current = account_identity(account['name'])
        if current is None:
            return  # Only called after durable removing_user intent.
        self.quiescent(account, [Path(account['home'])])
        require(not any(row.pw_gid == account['gid'] and row.pw_name != account['name'] for row in pwd.getpwall()),
                'Another account uses the primary group')
        verify_subordinates(account['name'], account, {}, empty=True)
        verify_account_memberships(account['name'], account)
        self.run(['userdel', account['name']])
        require(account_identity(account['name']) is None, 'Account removal was not verified')
        verify_subordinates(account['name'], account, {}, empty=True)
        verify_account_memberships(account['name'], account)

    def remove_group(self, account):
        require(account_identity(account['name']) is None, 'Account reappeared before group compensation')
        require(not any(row.pw_gid == account['gid'] for row in pwd.getpwall()),
                'Another account uses the primary group')
        try:
            group = grp.getgrnam(account['group'])
        except KeyError:
            return
        require(group.gr_gid == account['gid'] and not group.gr_mem,
                'Primary group changed during account compensation')
        self.run(['groupdel', account['group']])



def guard_preparation(instance, attempt_id=None):
    path = gate_path(instance)
    if path.exists() or path.is_symlink():
        gate = read_private(path)
        require(attempt_id == gate['attempt_id'] and gate['state'] in ('preparing', 'recovery_required', 'prepared'),
                'This instance is bound to its existing provisioning attempt; no new or legacy retry is admitted')


def prepare(instance, artifacts, config, host, attempt, *, run, command):
    """Actual new-instance path; no live bridge or WhatsApp session is started.

    Initial SQLite and marker bytes are constructed in private staging before
    either is published. Retry never bootstraps a partially published database.
    Host provider phases retain their independent admission and recovery gates.
    """
    from cryptography.fernet import Fernet
    from sally_whatsapp.config import Settings
    from sally_whatsapp.state_initialization import initialize_new
    from sally_whatsapp.state_continuity import StateContinuity
    import tenant_admin
    if attempt.data['state'] == 'prepared':
        return attempt.status()
    require(attempt.data['state'] in ('preparing', 'recovery_required'), 'Attempt cannot be prepared after cancellation')
    account = attempt.create_account(run)
    uid, gid = account.pw_uid, account.pw_gid
    for path, flag in (('/etc/subuid', '--add-subuids'), ('/etc/subgid', '--add-subgids')):
        attempt.subordinate(path, flag, run)
    for path, owner, mode in (
            (instance.private_dir, 0, 0o700), (instance.config_dir, 0, 0o750),
            (instance.state_dir, uid, 0o700), (instance.gateway_home, uid, 0o700),
            (instance.gateway_home / 'sessions', uid, 0o700),
            (instance.gateway_home / 'media', uid, 0o700),
            (instance.gateway_home / '.config', uid, 0o700),
            (instance.gateway_home / '.config/containers', uid, 0o700),
            (instance.gateway_home / '.config/containers/systemd', uid, 0o700)):
        attempt.publish(path, uid=owner, gid=gid, mode=mode)
    for name in ('webhook.key', 'encryption.key', 'waha.key'):
        path = instance.config_dir / name
        recorded = next((row for row in attempt.data['resources'] if row['path'] == str(path)), None)
        content = b'' if recorded else Fernet.generate_key() if name == 'encryption.key' else secrets.token_hex(32).encode()
        attempt.publish(path, content=content, mode=0o640, gid=gid)
    seed = attempt.data.get('database_seed')
    if seed is None:
        # Scratch remains private evidence if interrupted. A new seed is allowed
        # only before any seed has been recorded/published; no live DB is reset.
        scratch = attempt.root / (attempt.id + '-seed-' + secrets.token_hex(8))
        scratch.mkdir(mode=0o700)
        (scratch / 'data').mkdir(mode=0o700)
        (scratch / 'identity').mkdir(mode=0o700)
        cfg = scratch / 'config.toml'
        cfg.write_text(config); os.chmod(cfg, 0o600)
        settings = Settings.load(cfg)
        staged = replace(settings, database=scratch / 'data/archive.sqlite',
                         state_identity_file=scratch / 'identity/technical-state.json')
        initialize_new(staged, 0, 0)
        seed = {'database': str(staged.database), 'marker': str(staged.state_identity_file),
                'database_identity': identity(staged.database), 'marker_identity': identity(staged.state_identity_file)}
        attempt.data['database_seed'] = seed; attempt.save('database-seed')
    for key, destination, owner, mode in (
            ('database', instance.state_dir / 'archive.sqlite', uid, 0o600),
            ('marker', instance.config_dir / 'technical-state.json', 0, 0o640)):
        source = Path(seed[key])
        require(identity(source) == seed[key + '_identity'], 'Database seed changed; no bootstrap or repair is permitted')
        attempt.publish(destination, content=source.read_bytes(), mode=mode, uid=owner, gid=gid)
    cfgpath = instance.config_dir / 'config.toml'
    attempt.publish(cfgpath, content=config.encode(), mode=0o640, gid=gid)
    StateContinuity(Settings.load(cfgpath), allow_bootstrap=False)
    wrapper = (f'#!/bin/sh\nset -eu\ncd {instance.gateway_home}\nexec runuser -u {instance.service_user} -- env '
               f'HOME={instance.gateway_home} XDG_RUNTIME_DIR=/run/user/{uid} '
               f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "$@"\n')
    attempt.publish(instance.wrapper, content=wrapper.encode(), mode=0o700)
    attempt.publish(Path('/etc/systemd/system') / (instance.base + '.service'),
                    content=artifacts['bridge'].encode(), mode=0o644)
    attempt.publish(instance.gateway_home / '.config/containers/systemd/whatsapp-waha.container',
                    content=artifacts['gateway'].encode(), mode=0o600, uid=uid, gid=gid)
    # These adapters are finite and repeatable, with host side admission retained.
    # Their residual effects require this same-plan recovery, never broad rollback.
    attempt.effect('project-acl', lambda: tenant_admin.grant_project_access(instance), recoverable=True)
    attempt.effect('runtime-acl', lambda: tenant_admin.grant_runtime_access(instance), recoverable=True)
    attempt.effect('host-begin', host.begin_runtime, recoverable=True)
    attempt.effect('host-enrollment', lambda: host.enroll_runtime(account), recoverable=True)
    attempt.effect('linger', lambda: run(['loginctl', 'enable-linger', instance.service_user]), recoverable=True)
    attempt.effect('user-manager', lambda: run(['systemctl', 'start', f'user@{uid}.service']), recoverable=True)
    for name, source in (('whatsapp-waha-api-key', instance.config_dir / 'waha.key'),
                         ('whatsapp-waha-disabled-ui-key', None)):
        label = 'secret:' + name
        def ensure_secret(name=name, source=source):
            inspected = command([instance.wrapper, 'podman', 'secret', 'inspect', name], capture_output=True)
            if inspected.returncode == 0:
                values = json.loads(inspected.stdout)
                require(isinstance(values, list) and len(values) == 1
                        and values[0].get('Spec', {}).get('Labels', {}).get('wa.attempt') == attempt.id,
                        'Existing secret has no exact attempt provenance')
                return
            require(inspected.returncode == 1, 'Secret observation is uncertain')
            body = source.read_bytes() if source else secrets.token_hex(32).encode()
            run([instance.wrapper, 'podman', 'secret', 'create', '--label', 'wa.attempt=' + attempt.id, name, '-'], input=body)
            verified = command([instance.wrapper, 'podman', 'secret', 'inspect', name], capture_output=True)
            require(verified.returncode == 0, 'Secret creation result not verified')
            values = json.loads(verified.stdout)
            require(isinstance(values, list) and len(values) == 1
                    and values[0].get('Spec', {}).get('Labels', {}).get('wa.attempt') == attempt.id,
                    'Secret provenance not verified')
        attempt.effect(label, ensure_secret, recoverable=True)
    attempt.effect('system-reload', lambda: run(['systemctl', 'daemon-reload']), recoverable=True)
    attempt.effect('user-reload', lambda: run([instance.wrapper, 'systemctl', '--user', 'daemon-reload']), recoverable=True)
    attempt.effect('host-https', lambda: host.ensure_https(artifacts['apache']), recoverable=True)
    attempt.finish()
    return attempt.status()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'cancel'))
    parser.add_argument('--user', required=True)
    parser.add_argument('--attempt-id', required=True)
    parser.add_argument('--host-plan', required=True)
    parser.add_argument('--host-plan-sha256', required=True)
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, 'Authorized administrator required')
    import tenant_admin
    from host_integration import runtime_admission
    with runtime_admission(tenant_admin.ROOT):
        data = tenant_admin.registry()
        from sally_whatsapp.tenancy import Instance
        require(args.user in data['instances'], 'Registered attempted instance required')
        instance = Instance(**data['instances'][args.user]['spec'])
        host = tenant_admin.load_host_context(instance, args.host_plan, args.host_plan_sha256)
        try:
            if args.action == 'status':
                attempt = Attempt(instance, host, args.attempt_id, create=False)
                attempt.data = read_private(attempt.path)
                require(attempt.data.get('binding') == attempt.binding, 'Attempt binding changed')
                print(json.dumps(attempt.status()))
            else:
                with Attempt(instance, host, args.attempt_id, create=False) as attempt:
                    result = attempt.cancel(System())
                    print(json.dumps(result))
                    if result['state'] != 'cancelled':
                        raise SystemExit(2)
        finally:
            host.close()


if __name__ == '__main__':
    main()

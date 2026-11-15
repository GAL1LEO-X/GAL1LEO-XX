#!/usr/bin/env python3
"""Real root-to-tenant SQLite integration, only on an ephemeral CI runner.

No application dependencies, operational accounts, network, or mocked privilege
boundaries. Run only the dedicated job in checks.yml; never on a service host.
The companion strace artifact records actual credential syscalls in each child.
"""
import argparse
import ast
from contextlib import closing
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(source, expected_head, report_path):
    require(os.geteuid() == 0, 'This isolated integration requires a root parent')
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
            'Only the disposable GitHub-hosted test job is allowed')
    head = subprocess.check_output(['git', '-c', 'safe.directory=' + str(source),
                                   '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    require(head == expected_head, 'Checkout does not match the requested source SHA')
    names = ('wa-ci-alpha', 'wa-ci-bravo')
    uids = (21001, 21002)
    for name, uid in zip(names, uids):
        for candidate in (name, uid):
            try:
                pwd.getpwnam(candidate) if isinstance(candidate, str) else pwd.getpwuid(candidate)
            except KeyError:
                continue
            raise RuntimeError('Synthetic account or UID already exists; refusing to reuse it')

    helper_path = source / 'plugins/whatsapp/scripts/tenant_database.py'
    store_path = source / 'plugins/whatsapp/sally_whatsapp/store.py'
    module = ast.parse(store_path.read_text())
    schema = next(ast.literal_eval(node.value) for node in module.body
                  if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == 'SCHEMA' for target in node.targets))
    results = []
    report = {'source_head': head, 'synthetic_only': True,
              'helper_sha256': digest(helper_path), 'store_source_sha256': digest(store_path),
              'parent': {'uid': os.geteuid(), 'gid': os.getegid()},
              'tenants': [], 'results': results,
              'worker_proof': 'Real perform() asserts effective UID/GID and exact supplementary groups; companion strace records syscalls.'}
    original_groups = os.getgroups()
    created_users, created_groups = [], []
    # Hosted /opt can be runner-owned. Never relax production checks or chmod
    # shared ancestors: private metadata stays under root's existing home;
    # tenants reach only the separate synthetic state tree under sticky /tmp.
    temporary = Path(tempfile.mkdtemp(prefix='whatsapp-uid-ci-', dir='/root'))
    state_temporary = Path(tempfile.mkdtemp(prefix='whatsapp-uid-ci-state-', dir='/tmp'))
    state_temporary.chmod(0o755)
    try:
        for name, uid in zip(names, uids):
            subprocess.run(['groupadd', '--gid', str(uid), name], check=True)
            created_groups.append(name)
            subprocess.run(['useradd', '--no-create-home', '--no-user-group', '--uid', str(uid),
                            '--gid', str(uid), '--shell', '/usr/sbin/nologin', name], check=True)
            created_users.append(name)
            account = pwd.getpwnam(name)
            require((account.pw_uid, account.pw_gid) == (uid, uid), 'Real NSS identity mismatch')
            report['tenants'].append({'name': name, 'uid': uid, 'gid': uid})
        os.setgroups([21003])
        report['parent']['supplementary_groups'] = os.getgroups()
        require(os.getgroups() == [21003], 'Parent sentinel group was not established')
        code = temporary / 'root-only-code'
        code.mkdir(mode=0o700)
        worker = code / 'tenant_database.py'
        worker.write_bytes(helper_path.read_bytes())
        worker.chmod(0o600)
        spec = importlib.util.spec_from_file_location('tenant_database_ci', worker)
        secure = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(secure)
        require(secure._TRUST_ROOT == Path('/') and secure._TRUST_UID == 0,
                'Production trust boundary must remain intact')

        def fixtures(label):
            case = state_temporary / label
            case.mkdir(mode=0o755)
            protected_case = temporary / label
            protected_case.mkdir(mode=0o700)
            instances = []
            for index, (name, uid) in enumerate(zip(names, uids)):
                tenant = case / name
                tenant.mkdir(mode=0o755)
                configuration = protected_case / name
                configuration.mkdir(mode=0o700)
                state = tenant / 'state'
                state.mkdir(mode=0o700)
                os.chown(state, uid, uid)
                instance = SimpleNamespace(config_dir=configuration, state_dir=state,
                                           service_user=name, subject='synthetic-owner-' + name,
                                           public_url='https://' + name + '.example.invalid')
                database = state / 'archive.sqlite'
                expected = {'protocol': 1, 'id': ('a' if index == 0 else 'b') * 32,
                            'tenant': hashlib.sha256(json.dumps([instance.subject, instance.public_url, 'default'],
                                                                separators=(',', ':')).encode()).hexdigest()}
                config = {'database': str(database), 'owner_subject': instance.subject,
                          'public_url': instance.public_url, 'session': 'default'}
                (configuration / 'config.toml').write_text('[bridge]\n' + '\n'.join(
                    key + ' = ' + json.dumps(value) for key, value in config.items()))
                (configuration / 'technical-state.json').write_text(json.dumps(expected))
                for path in configuration.iterdir():
                    path.chmod(0o600)
                with closing(sqlite3.connect(database)) as db:
                    db.executescript(schema)
                    db.execute('INSERT INTO state VALUES (?,?)', (secure.KEY, json.dumps(expected)))
                    db.execute('INSERT INTO link_login_states VALUES (?,?,?,?,?)',
                               ('synthetic', 'verifier', 'nonce', 99999999999, 0))
                    db.commit()
                database.chmod(0o600)
                os.chown(database, uid, uid)
                instances.append(instance)
            return case, instances

        case, (first, second) = fixtures('positive')
        report['protected_ancestors'] = [
            {'path': str(path), 'uid': path.stat().st_uid, 'mode': oct(stat.S_IMODE(path.stat().st_mode))}
            for path in reversed((first.config_dir, *first.config_dir.parents))]
        original_b = digest(second.state_dir / 'archive.sqlite')
        for instance in (first, second):
            for action in ('verify', 'idle', 'snapshot', 'suspend'):
                destination = case / (instance.service_user + '-snapshot.sqlite')
                secure.run_database(instance, action, **({'target': destination} if action == 'snapshot' else {}))
                if action == 'snapshot':
                    info = destination.stat()
                    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                            'Administrative snapshot must be root owned, mode 0600')
                    with closing(sqlite3.connect(destination)) as db:
                        require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'Snapshot integrity')
                        require(db.execute('PRAGMA journal_mode').fetchone() == ('delete',), 'Snapshot journal')
                        secure.database_identity(db, secure.tenant_context(instance)['expected'])
                    report.setdefault('snapshots', []).append({'tenant': instance.service_user,
                                                               'sha256': digest(destination), 'uid': info.st_uid,
                                                               'mode': '0600', 'integrity': 'ok', 'journal': 'delete'})
                if action == 'suspend':
                    with closing(sqlite3.connect(instance.state_dir / 'archive.sqlite')) as db:
                        require(db.execute('SELECT COUNT(*) FROM link_login_states').fetchone() == (0,),
                                'Suspension did not apply to selected tenant')
                if instance is first:
                    require(digest(second.state_dir / 'archive.sqlite') == original_b, 'Tenant B changed during A operation')
                results.append({'case': instance.service_user + ':' + action, 'passed': True})

        damages = ('symlink', 'parent-symlink', 'hardlink', 'foreign-identity', 'missing', 'fifo',
                   'marker-symlink', 'marker-writable', 'config-writable')
        for damage in damages:
            for action in ('verify', 'idle', 'suspend', 'snapshot'):
                case, (first, second) = fixtures(damage + '-' + action)
                database = first.state_dir / 'archive.sqlite'
                other = second.state_dir / 'archive.sqlite'
                original_b = digest(other)
                if damage in ('symlink', 'hardlink', 'foreign-identity', 'missing', 'fifo'):
                    database.unlink()
                    if damage == 'symlink':
                        database.symlink_to(other)
                    elif damage == 'hardlink':
                        os.link(other, database)
                    elif damage == 'foreign-identity':
                        database.write_bytes(other.read_bytes())
                        database.chmod(0o600)
                        os.chown(database, uids[0], uids[0])
                    elif damage == 'fifo':
                        os.mkfifo(database, 0o600)
                        os.chown(database, uids[0], uids[0])
                elif damage == 'parent-symlink':
                    first.state_dir.rename(first.state_dir.with_name('preserved'))
                    first.state_dir.symlink_to(second.state_dir, target_is_directory=True)
                elif damage == 'marker-symlink':
                    marker = first.config_dir / 'technical-state.json'
                    marker.unlink()
                    marker.symlink_to(second.config_dir / 'technical-state.json')
                else:
                    (first.config_dir / ('technical-state.json' if damage == 'marker-writable'
                                         else 'config.toml')).chmod(0o666)
                destination = case / 'rejected.sqlite'
                try:
                    secure.run_database(first, action, **({'target': destination} if action == 'snapshot' else {}))
                except (OSError, RuntimeError, subprocess.CalledProcessError):
                    pass
                else:
                    raise RuntimeError('Unsafe input accepted: ' + damage + ':' + action)
                require(digest(other) == original_b, 'Negative case changed tenant B')
                require(not destination.exists(), 'Rejected snapshot left an output')
                if damage == 'missing':
                    require(not database.exists(), 'Missing database was created')
                results.append({'case': damage + ':' + action, 'passed': True, 'tenant_b_unchanged': True})

        case, (first, second) = fixtures('existing-output')
        destination = case / 'existing.sqlite'
        destination.write_bytes(b'preserve-existing-synthetic-output')
        before = digest(destination)
        try:
            secure.run_database(first, 'snapshot', target=destination)
        except FileExistsError:
            pass
        else:
            raise RuntimeError('Snapshot accepted existing destination')
        require(digest(destination) == before, 'Existing destination was changed')
        results.append({'case': 'preexisting-snapshot', 'passed': True})

        # Search-only ancestors are a valid tenant boundary: listing /var is
        # not required to open a known descendant. Exercise actual dropped
        # credentials, with production trust checks and the root-only source.
        case, (first, second) = fixtures('search-only-ancestor')
        case.chmod(0o711)
        report['search_only_ancestor'] = {'path': str(case), 'uid': case.stat().st_uid,
                                         'mode': '0711', 'tenant_access': '--x'}
        listing_probe = (
            'import os,sys\n'
            'assert os.geteuid() == int(sys.argv[2]) and os.getegid() == int(sys.argv[2])\n'
            'assert os.getgroups() == []\n'
            'try:\n'
            ' fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n'
            'except PermissionError:\n'
            ' pass\n'
            'else:\n'
            ' os.close(fd);raise AssertionError("Synthetic ancestor unexpectedly readable")\n')
        for instance, uid in zip((first, second), uids):
            subprocess.run([sys.executable, '-I', '-B', '-c', listing_probe, str(case), str(uid)],
                           user=uid, group=uid, extra_groups=[], env={}, cwd='/', close_fds=True, check=True)
            database = instance.state_dir / 'archive.sqlite'
            other = second if instance is first else first
            other_before = digest(other.state_dir / 'archive.sqlite')
            before = digest(database)
            for action in ('verify', 'idle', 'snapshot', 'suspend'):
                destination = case / (instance.service_user + '-snapshot.sqlite')
                secure.run_database(instance, action, **({'target': destination} if action == 'snapshot' else {}))
                require(stat.S_IMODE(case.stat().st_mode) == 0o711, 'Worker changed ancestor permissions')
                require(digest(other.state_dir / 'archive.sqlite') == other_before, 'Search-only case changed other tenant')
                if action == 'suspend':
                    with closing(sqlite3.connect(database)) as db:
                        require(db.execute('SELECT COUNT(*) FROM link_login_states').fetchone() == (0,),
                                'Search-only suspension did not apply')
                else:
                    require(digest(database) == before, 'Read-only work changed source database')
                if action == 'snapshot':
                    require(destination.stat().st_uid == 0 and stat.S_IMODE(destination.stat().st_mode) == 0o600,
                            'Search-only snapshot lost its administrative output boundary')
                    with closing(sqlite3.connect(destination)) as db:
                        require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'Search-only snapshot integrity')
                        secure.database_identity(db, secure.tenant_context(instance)['expected'])
                results.append({'case': 'search-only:' + instance.service_user + ':' + action, 'passed': True})

        for action in ('verify', 'idle', 'snapshot', 'suspend'):
            case, (first, second) = fixtures('no-search-ancestor-' + action)
            case.chmod(0o700)
            before = digest(first.state_dir / 'archive.sqlite')
            other_before = digest(second.state_dir / 'archive.sqlite')
            destination = case / 'rejected.sqlite'
            try:
                secure.run_database(first, action, **({'target': destination} if action == 'snapshot' else {}))
            except subprocess.CalledProcessError:
                pass
            else:
                raise RuntimeError('Worker traversed an ancestor without search permission')
            require(stat.S_IMODE(case.stat().st_mode) == 0o700, 'Worker changed denied ancestor permissions')
            require(digest(first.state_dir / 'archive.sqlite') == before
                    and digest(second.state_dir / 'archive.sqlite') == other_before, 'Denied traversal changed a tenant')
            require(not destination.exists(), 'Denied traversal left a snapshot')
            results.append({'case': 'no-search:' + action, 'passed': True})

        case, (first, second) = fixtures('search-only-busy')
        with closing(sqlite3.connect(first.state_dir / 'archive.sqlite')) as db:
            db.execute('INSERT INTO sends VALUES (?,?,?,?,?,?,?)',
                       ('synthetic-active', 'owner', 'hash', 'sending', None, 0, 0))
            db.commit()
        before = digest(first.state_dir / 'archive.sqlite')
        other_before = digest(second.state_dir / 'archive.sqlite')
        case.chmod(0o711)
        try:
            secure.run_database(first, 'idle')
        except subprocess.CalledProcessError:
            pass
        else:
            raise RuntimeError('Search-only traversal bypassed the active queue gate')
        require(stat.S_IMODE(case.stat().st_mode) == 0o711, 'Busy check changed ancestor permissions')
        require(digest(first.state_dir / 'archive.sqlite') == before
                and digest(second.state_dir / 'archive.sqlite') == other_before, 'Busy check changed a tenant')
        results.append({'case': 'search-only:busy-queue', 'passed': True})
        report['passed'] = True
    finally:
        os.setgroups(original_groups)
        shutil.rmtree(temporary)
        shutil.rmtree(state_temporary)
        for name in reversed(created_users):
            subprocess.run(['userdel', name], check=True)
        for name in reversed(created_groups):
            try:
                grp.getgrnam(name)
            except KeyError:  # userdel may remove the user's empty namesake group.
                continue
            subprocess.run(['groupdel', name], check=True)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        report_path.chmod(0o644)
    print(json.dumps({'passed': report['passed'], 'cases': len(results), 'source_head': head}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    run(args.source.resolve(), args.expected_head, args.report.resolve())

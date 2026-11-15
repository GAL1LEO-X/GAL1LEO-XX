#!/usr/bin/env python3
"""Exact 1.0.3 -> 1.0.4 patch maintenance, with schema 3 unchanged.

This is a separately qualified adapter. The historical schema-2 transition
remains pinned and unchanged. This adapter conservatively retains the qualified forward-recovery policy:
after candidate writers may have run, preserve the database and recover the
same candidate explicitly instead of restoring an older snapshot or binary.
No deployment or configuration is performed by importing this module.
"""
import argparse
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import sqlite3
import stat
import zipfile

BASE_ADAPTER_SHA256 = 'ade6c0e03d070576efa55075026af04ac2ad57142a711e63962f83e4b3833221'
PREVIOUS_STORE = 'a7759850d24cca5aaf66ce5239fc1d0b5899a6bc12618aaa0f0a57fb2e2b8a23'
CANDIDATE_FILES = {
    'src/tesla_plugin/store.py': 'a7759850d24cca5aaf66ce5239fc1d0b5899a6bc12618aaa0f0a57fb2e2b8a23',
    'src/tesla_plugin/schema_migrations.py': 'bb9139ee1eb308b6b17d0f0f8aec047015f1a486772c840a6006cfccbc865162',
    'requirements.lock': '6cbae69d16074ead0fbb8897af9e5bdbbdfcc76f6be33fb050847a1325a15cd1',
}

_base_path = Path(__file__).with_name('schema3_update.py')
if hashlib.sha256(_base_path.read_bytes()).hexdigest() != BASE_ADAPTER_SHA256:
    raise ValueError('Historical maintenance primitive changed')
_spec = importlib.util.spec_from_file_location('tesla_schema3_qualified_primitive', _base_path)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)


def backup_database(path, owner):
    """Private, self-contained SQLite backup; never replace the live archive."""
    path = Path(path).absolute()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError('Database must be a private regular file')
    destination = path.with_name(path.name + '.pre-patch-104.' + secrets.token_hex(8) + '.sqlite3')
    with closing(sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=10)) as lock:
        lock.execute('BEGIN IMMEDIATE')
        if (lock.execute("SELECT value FROM meta WHERE key='schema'").fetchall() != [('3',)]
                or lock.execute("SELECT value FROM meta WHERE key='owner'").fetchall() != [(owner,)]):
            raise ValueError('Database schema or owner changed')
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as source, closing(sqlite3.connect(destination)) as saved:
                source.backup(saved)
                saved.execute('PRAGMA journal_mode=DELETE')
                if (saved.execute('PRAGMA integrity_check').fetchall() != [('ok',)]
                        or saved.execute("SELECT value FROM meta WHERE key='schema'").fetchall() != [('3',)]
                        or saved.execute("SELECT value FROM meta WHERE key='owner'").fetchall() != [(owner,)]):
                    raise ValueError('Backup failed integrity or identity check')
            with destination.open('rb') as saved:
                os.fsync(saved.fileno())
            base.Adapter._sync_directory(path.parent)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        finally:
            lock.rollback()
    return str(destination)


class Adapter(base.Adapter):
    """Reuse strict locks, loaded D-Bus conditions and both-writer invariants."""

    def _verify_release(self):
        if self.ops.sha(self.previous / 'src/tesla_plugin/store.py') != PREVIOUS_STORE:
            raise ValueError('Previous Store differs from reviewed 1.0.3')
        for name, expected in CANDIDATE_FILES.items():
            if self.ops.sha(self.release / name) != expected:
                raise ValueError('Candidate storage or dependency fingerprint changed')
        if (self.previous.joinpath('VERSION').read_text().strip() != '1.0.3'
                or self.release.joinpath('VERSION').read_text().strip() != '1.0.4'
                or self.previous.joinpath('requirements.lock').read_bytes() != self.release.joinpath('requirements.lock').read_bytes()):
            raise ValueError('This transition requires 1.0.3 to 1.0.4 with unchanged dependencies')
        if self.ops.sha(self.p['archive_path']) != self.p['source_archive_sha256']:
            raise ValueError('Reviewed archive changed')
        with zipfile.ZipFile(self.p['archive_path']) as archive:
            manifest_bytes = archive.read('SHA256SUMS.json')
        if self.release.joinpath('SHA256SUMS.json').read_bytes() != manifest_bytes:
            raise ValueError('Staged manifest differs from reviewed archive')
        for name, expected in json.loads(manifest_bytes).items():
            path = self.release / name
            if path.is_symlink() or self.ops.sha(path) != expected:
                raise ValueError('Staged source changed')
        if self.ops.sha(self.release / 'deploy/schema3_update.py') != BASE_ADAPTER_SHA256:
            raise ValueError('Staged historical primitive changed')
        if self.ops.sha(self.release / 'deploy/patch104_update.py') != self.ops.sha(Path(__file__)):
            raise ValueError('Maintenance adapter differs from staged candidate')

    @base.exclusive
    def stage(self):
        self._check_writers(True)
        baseline = self._guard(3, self.p['expected_owner_digest'], self.old_units)
        if baseline['intent_digest'] != self.p['expected_intent_digest']:
            raise ValueError('Owner operations changed since review')
        self.baseline = baseline
        self.ops.check_personal_settings(json.loads(self.settings.read_text()), transport=True)
        if self.release.exists() or self.recovery.exists():
            raise ValueError('Already staged or attempted; inspect the original receipt')
        self.recovery.mkdir(mode=0o700)
        self.ops.write_new(self.recovery / 'profile.json', json.dumps(self.p, sort_keys=True))
        for name in base.WRITERS:
            self.ops.write_new(self.recovery / (name + '.before'), (self.unit_root / name).read_bytes())
        self.ops.extract_verified(self.p['archive_path'], self.release, self.p['source_archive_sha256'])
        self._verify_release()
        self.ops.run(['python3', '-m', 'venv', str(self.release / 'venv')], log=self.recovery / 'venv.log')
        python = str(self.release / 'venv/bin/python')
        self.ops.run([python, '-m', 'pip', 'install', '--disable-pip-version-check', '-r',
                      str(self.release / 'requirements.lock'), 'setuptools==84.0.0'], log=self.recovery / 'dependencies.log')
        self.ops.run([python, '-m', 'pip', 'install', '--disable-pip-version-check', '--no-deps',
                      '--no-build-isolation', str(self.release)], log=self.recovery / 'package.log')
        self.ops.run([python, '-m', 'pip', 'check'], log=self.recovery / 'pip-check.log')
        self.ops.release_access(self.p['release_root'], self.release, pwd.getpwnam(self.p['service_user']).pw_gid)
        self.ops.run(['runuser', '-u', self.p['service_user'], '--', str(self.release / 'venv/bin/tesla-plugin'),
                      'check-config', '--config', str(self.settings)], log=self.recovery / 'check-config.log')
        units = {}
        for name in base.WRITERS:
            candidate = self.ops.candidate_unit((self.recovery / (name + '.before')).read_text(),
                self.previous, self.release, consumer=name == base.WRITERS[1])
            path = self.recovery / (name + '.candidate')
            self.ops.write_new(path, candidate)
            units[name] = self.ops.sha(path)
        self._guard(3, baseline['owner_digest'], self.old_units)
        record = {'state': 'staged', 'baseline': baseline, 'candidate_units': units,
                  'schema_change': False, 'rollback_after_writer_start': 'forward_recovery_required'}
        self.ops.write_new(self.recovery / 'stage.json', json.dumps(record))
        return record

    def _backup(self):
        self._verify_release()
        path = self.release / 'deploy/patch104_update.py'
        with zipfile.ZipFile(self.p['archive_path']) as archive:
            expected = json.loads(archive.read('SHA256SUMS.json'))['deploy/patch104_update.py']
        script = ("import hashlib,json,pathlib,runpy,sys;path=pathlib.Path(sys.argv[1]);"
                  "None if hashlib.sha256(path.read_bytes()).hexdigest()==sys.argv[2] else sys.exit('Adapter fingerprint mismatch');"
                  "module=runpy.run_path(str(path));"
                  "print(json.dumps({'backup':module['backup_database'](sys.argv[3],sys.argv[4])}))")
        result = self._schema_process([str(self.release / 'venv/bin/python'), '-c', script,
            str(path), expected, str(self.database), json.loads(self.settings.read_text())['owner_subject']])
        backup = Path(json.loads(result)['backup'])
        if not backup.is_file() or backup.is_symlink() or backup.stat().st_mode & 0o077:
            raise ValueError('Backup was not delivered as a private file')
        return str(backup)

    def _recover(self, staged, current_units, record):
        activation = json.loads((self.recovery / 'activation.json').read_text())
        if activation.get('candidate_writers_may_have_run') is not False:
            record['candidate_writers_may_have_run'] = True
            record['forward_recovery_required'] = True
            raise ValueError('Candidate writers may have persisted new semantics; forward recovery is required')
        # No candidate process has been launched. Return units, not database,
        # to the old version. A WAL backup never replaces newer observations.
        self._stop()
        before = self._guard(3, staged['baseline']['owner_digest'], current_units)
        for name in base.WRITERS:
            self._check_files(current_units)
            self.ops.atomic(self.unit_root / name, (self.recovery / (name + '.before')).read_bytes())
            current_units[name] = self.old_units[name]
        self._system('daemon-reload')
        self._sync_directory(self.unit_root)
        after = self._guard(3, staged['baseline']['owner_digest'], self.old_units)
        if after['samples_count'] != before['samples_count']:
            raise base.IntegrityFailure('Sample count changed during stopped patch recovery')
        self._release_hold()
        self._system('start', *base.WRITERS)
        self._health('1.0.3')
        self._guard(3, staged['baseline']['owner_digest'], self.old_units)
        record.update(state='rolled_back', schema=3, database_restored=False)

    @base.exclusive
    def activate(self):
        staged = self._staged()
        self._check_writers(True)
        self._guard(3, staged['baseline']['owner_digest'], self.old_units)
        receipt = self.recovery / 'activation.json'
        record = {'state': 'started', 'source_commit': self.p['source_commit'],
                  'schema': 3, 'schema_change': False, 'candidate_writers_may_have_run': False}
        self.ops.write_new(receipt, json.dumps(record))
        self._sync_directory(self.recovery)
        current_units = dict(self.old_units)
        try:
            self._stop()
            before = self._guard(3, staged['baseline']['owner_digest'], current_units)
            record['database_backup'] = self._backup()
            record['phase'] = 'backup_verified'
            self.ops.atomic(receipt, json.dumps(record))
            self._sync_directory(self.recovery)
            after = self._guard(3, staged['baseline']['owner_digest'], current_units)
            if after['samples_count'] != before['samples_count']:
                raise base.IntegrityFailure('Sample count changed during stopped backup')
            for name in base.WRITERS:
                self._check_files(current_units)
                self.ops.atomic(self.unit_root / name, (self.recovery / (name + '.candidate')).read_bytes())
                current_units[name] = staged['candidate_units'][name]
            self._system('daemon-reload')
            self._sync_directory(self.unit_root)
            self._guard(3, staged['baseline']['owner_digest'], current_units)
            # Persist before releasing the reboot hold: a crash or an uncertain
            # start must never authorize an old binary against new semantics.
            record.update(candidate_writers_may_have_run=True, phase='candidate_start_pending')
            self.ops.atomic(receipt, json.dumps(record))
            self._sync_directory(self.recovery)
            self._release_hold()
            self._system('start', *base.WRITERS)
            self._health('1.0.4')
            self._guard(3, staged['baseline']['owner_digest'], current_units)
            record.update(state='active', phase='health_verified')
        except Exception as error:
            if isinstance(error, base.IntegrityFailure):
                record['data_integrity_failed'] = True
                self._incomplete(receipt, record)
                raise base.RecoveryIncomplete('Data integrity failed; inspect without automatic rollback') from error
            try:
                self._recover(staged, current_units, record)
            except Exception:
                self._incomplete(receipt, record)
                raise base.RecoveryIncomplete('Patch recovery incomplete; preserve data and inspect the private receipt') from error
            self._finish(receipt, record)
            raise
        return self._finish(receipt, record)

    @base.exclusive
    def rollback(self):
        # Refuse before stopping a healthy installed candidate. A separate,
        # explicitly qualified forward repair must handle its persisted state.
        self._staged()
        raise ValueError('Post-start rollback requires qualified forward recovery; no units or database changed')

    def _integrity(self):
        """Read only: an intact schema number alone is not an intact archive."""
        owner = json.loads(self.settings.read_text())['owner_subject']
        # SQLite can omit CHECK validation on a read-only handle. query_only
        # prohibits writes while retaining the complete integrity_check.
        with closing(sqlite3.connect(self.database.absolute().as_uri() + '?mode=rw', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            if (db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]
                    or db.execute("SELECT value FROM meta WHERE key='schema'").fetchall() != [('3',)]
                    or db.execute("SELECT value FROM meta WHERE key='owner'").fetchall() != [(owner,)]):
                raise base.IntegrityFailure('Archive integrity or identity is not qualified')

    def _forward_receipts(self):
        """Retain every attempt and every integrity veto, including old recovery."""
        activation = None
        attempts = []
        paths = [self.recovery / 'activation.json']
        paths += [self.recovery / name for name in ('recovery.json', 'rollback.json')
                  if (self.recovery / name).exists()]
        forward = sorted(self.recovery.glob('forward-recovery-*.json'))
        for index, path in enumerate(forward, 1):
            if path.name != f'forward-recovery-{index:06d}.json':
                raise ValueError('Forward recovery receipt sequence is incomplete')
        for path in paths + forward:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError('Recovery receipt must be a private regular file')
            value = json.loads(path.read_text())
            if (not isinstance(value, dict) or value.get('source_commit') != self.p['source_commit']
                    or value.get('state') not in ('started', 'recovery_incomplete', 'active')):
                raise ValueError('Unknown recovery receipt or candidate identity')
            if value.get('data_integrity_failed'):
                raise ValueError('Historical integrity failure requires separate operator review')
            if path.name == 'activation.json':
                activation = value
            elif path in forward:
                if (value.get('candidate_writers_may_have_run') is not True
                        or type(value.get('attempt')) is not int or value['attempt'] != len(attempts) + 1
                        or value.get('phase') not in ('qualifying', 'candidate_start_pending', 'health_verified')):
                    raise ValueError('Unknown forward recovery phase')
                if (any(item['state'] == 'active' for item in attempts)
                        or (value['state'] == 'active' and value['phase'] != 'health_verified')):
                    raise ValueError('Forward recovery terminal receipt is inconsistent')
                attempts.append(value)
        if (activation.get('candidate_writers_may_have_run') is not True
                or activation.get('schema') != 3 or activation.get('schema_change') is not False
                or activation.get('phase') != 'candidate_start_pending'):
            raise ValueError('No qualified interrupted candidate start to recover forward')
        return activation, attempts

    @base.exclusive
    def recover(self):
        # Once a forward attempt exists, the old recovery entry point must not
        # stop an already healthy candidate or erase its separate outcome.
        if list(self.recovery.glob('forward-recovery-*.json')):
            raise ValueError('A forward recovery exists; inspect it or use recover_forward')
        return base.Adapter.recover.__wrapped__(self)

    @base.exclusive
    def recover_forward(self):
        """Explicitly resume only this staged 1.0.4, preserving the current DB.

        A fresh invocation is required after each failed/uncertain attempt.
        A healthy runtime left by process death is reconciled without restarting.
        No receipt, backup or pending owner operation is silently discarded.
        """
        staged = self._staged()
        activation, attempts = self._forward_receipts()
        units = staged['candidate_units']
        self._guard(3, staged['baseline']['owner_digest'], units)
        self._integrity()
        for name in base.WRITERS:
            path = self._guard_path(name)
            if (path.parent.is_symlink() or path.is_symlink()
                    or (path.exists() and path.read_text() != self._guard_content())):
                raise ValueError('Unexpected maintenance drop-in')
        if self.hold.is_symlink() or (self.hold.exists() and self.hold.read_text() != self.p['source_commit']):
            raise ValueError('Unexpected maintenance marker')
        # Terminal replay is read-only. A later unhealthy runtime is a separate
        # incident, not permission to replay a completed maintenance operation.
        if attempts and attempts[-1]['state'] == 'active':
            if self.hold.exists():
                raise ValueError('Completed recovery has a maintenance hold; inspect separately')
            self._health('1.0.4')
            self._guard(3, staged['baseline']['owner_digest'], units)
            return attempts[-1]
        if activation['state'] == 'active':
            raise ValueError('No interrupted activation to recover')
        receipt = self.recovery / f'forward-recovery-{len(attempts) + 1:06d}.json'
        record = {'state': 'started', 'phase': 'qualifying', 'attempt': len(attempts) + 1,
                  'source_commit': self.p['source_commit'], 'schema': 3, 'schema_change': False,
                  'candidate_writers_may_have_run': True, 'database_restored': False}
        self.ops.write_new(receipt, json.dumps(record))
        self._sync_directory(self.recovery)
        try:
            running = (not self.hold.exists() and all(self._state(name, 'ActiveState') == 'active'
                                                      for name in base.WRITERS))
            if running:
                # A start result/health receipt can have been lost. Verify the
                # existing runtime before considering another start command.
                try:
                    self._health('1.0.4')
                except (OSError, ValueError):
                    running = False
            if not running:
                self._stop()
                before = self._guard(3, staged['baseline']['owner_digest'], units)
                self._integrity()
                record['database_backup'] = self._backup()
                after = self._guard(3, staged['baseline']['owner_digest'], units)
                self._integrity()
                if before['samples_count'] != after['samples_count']:
                    raise base.IntegrityFailure('Samples changed while both writers were stopped')
                self._check_writers(False)
                self._inhibit()  # Recheck the loaded, mandatory condition on BOTH writers.
                record['phase'] = 'candidate_start_pending'
                self.ops.atomic(receipt, json.dumps(record))
                self._sync_directory(self.recovery)
                self._release_hold()
                self._system('start', *base.WRITERS)
                self._health('1.0.4')
            self._guard(3, staged['baseline']['owner_digest'], units)
            self._integrity()
            record.update(state='active', phase='health_verified', reconciled_running=running)
            # Keep activation.json and all failed attempts unchanged. This
            # separately durable success is also authoritative on an explicit retry.
            return self._finish(receipt, record)
        except Exception as error:
            if isinstance(error, base.IntegrityFailure):
                record['data_integrity_failed'] = True
            self._incomplete(receipt, record)
            raise base.RecoveryIncomplete('Forward recovery incomplete; both writers are held for review') from error

    def _cleanup_basis(self, staged):
        """Find a durable runtime success, preserving all historical vetoes."""
        paths = [self.recovery / 'activation.json']
        paths += [self.recovery / name for name in ('rollback.json', 'recovery.json')
                  if (self.recovery / name).exists()]
        forwards = sorted(self.recovery.glob('forward-recovery-*.json'))
        records = []
        for path in paths + forwards:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError('Runtime receipt must be a private regular file')
            value = json.loads(path.read_text())
            if (not isinstance(value, dict) or value.get('source_commit') != self.p['source_commit']
                    or value.get('state') not in ('started', 'recovery_incomplete', 'active', 'rolled_back')):
                raise ValueError('Unknown runtime receipt or candidate identity')
            if value.get('data_integrity_failed'):
                raise ValueError('Historical integrity failure requires separate operator review')
            records.append(value)
        activation = records[0]
        if activation.get('schema') != 3 or activation.get('schema_change') is not False:
            raise ValueError('Activation schema contract is not qualified')
        if activation.get('candidate_writers_may_have_run') is True:
            if forwards:
                _, attempts = self._forward_receipts()
                success, path = attempts[-1], forwards[-1]
            else:
                success, path = records[-1], paths[-1]
                if len(paths) != 1:
                    raise ValueError('Post-start recovery has no qualified forward success')
            if success.get('state') != 'active' or success.get('phase') != 'health_verified':
                raise ValueError('No durable successful candidate runtime to clean')
            version, units = '1.0.4', staged['candidate_units']
        elif activation.get('candidate_writers_may_have_run') is False:
            success, path = records[-1], paths[-1]
            if (forwards or success.get('state') != 'rolled_back' or success.get('schema') != 3
                    or success.get('database_restored') is not False):
                raise ValueError('No durable pre-start recovery success to clean')
            version, units = '1.0.3', self.old_units
        else:
            raise ValueError('Ambiguous candidate start marker')
        return {'runtime_version': version, 'success_receipt': path.name,
                'success_receipt_sha256': self.ops.sha(path)}, units

    def _cleanup_files(self):
        """Validate both paths before deleting either; absence is resumable."""
        if self.hold.exists() or self.hold.is_symlink():
            raise ValueError('Maintenance hold must be absent before cleanup')
        for name in base.WRITERS:
            path = self._guard_path(name)
            if path.parent.is_symlink() or path.is_symlink():
                raise ValueError('Unexpected maintenance drop-in path')
            if path.exists() and (not stat.S_ISREG(path.lstat().st_mode)
                                  or path.read_text() != self._guard_content()):
                raise ValueError('Foreign or changed maintenance drop-in; preserve it')

    def _loaded_hold_absent(self, name):
        # Check absence in the loaded typed property, not its CLI rendering or
        # file contents. An unknown/malformed response is not evidence of removal.
        command = ['busctl', '--system', '--json=short', '--timeout=10']
        unit = json.loads(self.ops.run(command + ['call', 'org.freedesktop.systemd1',
            '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager', 'GetUnit', 's', name]))
        if (not isinstance(unit, dict) or unit.get('type') != 'o'
                or not isinstance(unit.get('data'), list) or len(unit['data']) != 1
                or not isinstance(unit['data'][0], str)
                or not re.fullmatch(r'/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+', unit['data'][0])):
            raise ValueError('Unexpected systemd unit object')
        value = json.loads(self.ops.run(command + ['get-property', 'org.freedesktop.systemd1',
            unit['data'][0], 'org.freedesktop.systemd1.Unit', 'Conditions']))
        if not isinstance(value, dict) or value.get('type') != 'a(sbbsi)' or not isinstance(value.get('data'), list):
            raise ValueError('Unexpected systemd conditions value')
        absent = True
        for condition in value['data']:
            if (not isinstance(condition, list) or len(condition) != 5 or not isinstance(condition[0], str)
                    or type(condition[1]) is not bool or type(condition[2]) is not bool
                    or not isinstance(condition[3], str) or type(condition[4]) is not int):
                raise ValueError('Unexpected systemd condition tuple')
            absent = absent and condition[3] != str(self.hold)
        return absent

    def _cleanup_ready(self, staged, basis, units):
        self._verify_release()
        if self.ops.sha(self.recovery / basis['success_receipt']) != basis['success_receipt_sha256']:
            raise ValueError('Successful runtime receipt changed')
        self._cleanup_files()
        self._guard(3, staged['baseline']['owner_digest'], units)
        self._integrity()
        self._health(basis['runtime_version'])
        self._check_writers(True)
        self._cleanup_files()
        self._guard(3, staged['baseline']['owner_digest'], units)

    @base.exclusive
    def complete_maintenance(self):
        """Finish only this operation's exact drop-ins, without restarting writers."""
        staged = self._staged()
        basis, units = self._cleanup_basis(staged)
        attempts = []
        for index, path in enumerate(sorted(self.recovery.glob('maintenance-cleanup-*.json')), 1):
            if path.name != f'maintenance-cleanup-{index:06d}.json':
                raise ValueError('Cleanup receipt sequence is incomplete')
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError('Cleanup receipt must be a private regular file')
            value = json.loads(path.read_text())
            if (not isinstance(value, dict) or value.get('source_commit') != self.p['source_commit']
                    or type(value.get('attempt')) is not int or value['attempt'] != index
                    or any(value.get(key) != expected for key, expected in basis.items())
                    or value.get('state') not in ('started', 'cleanup_incomplete', 'complete')
                    or value.get('phase') not in ('remove_guards', 'reload_pending', 'verified')
                    or any(item['state'] == 'complete' for item in attempts)):
                raise ValueError('Unknown cleanup receipt or runtime identity')
            if value.get('data_integrity_failed'):
                raise ValueError('Historical cleanup integrity failure requires separate review')
            if value['state'] == 'complete' and (value.get('maintenance_cleanup_complete') is not True
                                                 or value['phase'] != 'verified'):
                raise ValueError('Cleanup success is not qualified')
            attempts.append(value)
        self._cleanup_ready(staged, basis, units)
        if attempts and attempts[-1]['state'] == 'complete':
            if any(self._guard_path(name).exists() or not self._loaded_hold_absent(name) for name in base.WRITERS):
                raise ValueError('Completed maintenance has new guard drift; inspect separately')
            return attempts[-1]  # No daemon-reload or receipt mutation on terminal retry.
        receipt = self.recovery / f'maintenance-cleanup-{len(attempts) + 1:06d}.json'
        record = basis | {'state': 'started', 'phase': 'remove_guards', 'attempt': len(attempts) + 1,
                          'source_commit': self.p['source_commit'], 'runtime_state': 'active',
                          'maintenance_cleanup_complete': False}
        self.ops.write_new(receipt, json.dumps(record))
        self._sync_directory(self.recovery)
        try:
            for name in base.WRITERS:
                self._cleanup_ready(staged, basis, units)
                path = self._guard_path(name)
                if path.exists():
                    path.unlink()
                    self._sync_directory(path.parent)
            self._cleanup_ready(staged, basis, units)
            record['phase'] = 'reload_pending'
            self.ops.atomic(receipt, json.dumps(record))
            self._sync_directory(self.recovery)
            self._system('daemon-reload')
            if not all(self._loaded_hold_absent(name) for name in base.WRITERS):
                raise ValueError('Systemd still has the maintenance condition loaded')
            self._cleanup_ready(staged, basis, units)
            if any(self._guard_path(name).exists() for name in base.WRITERS):
                raise ValueError('Maintenance drop-in reappeared during cleanup')
            record.update(state='complete', phase='verified', maintenance_cleanup_complete=True)
            self.ops.atomic(receipt, json.dumps(record))
            self._sync_directory(self.recovery)
            return record
        except Exception as error:
            # Cleanup failure must never stop a healthy runtime or replace its
            # already durable outcome. Keep this attempt separately inspectable.
            record.update(state='cleanup_incomplete', maintenance_cleanup_complete=False)
            if isinstance(error, base.IntegrityFailure):
                record['data_integrity_failed'] = True
            self.ops.atomic(receipt, json.dumps(record))
            self._sync_directory(self.recovery)
            raise base.RecoveryIncomplete('Maintenance cleanup incomplete; runtime was not restarted') from error


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'stage', 'activate', 'rollback', 'recover',
                                         'recover_forward', 'complete_maintenance'))
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--ops-directory', type=Path, required=True)
    arguments = parser.parse_args()
    adapter = Adapter(json.loads(arguments.profile.read_text()), base.load_ops(arguments.ops_directory))
    print(json.dumps(getattr(adapter, arguments.action)()))

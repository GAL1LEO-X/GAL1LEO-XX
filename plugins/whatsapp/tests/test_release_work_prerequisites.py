"""Exercise the real publication boundary with synthetic services and files."""
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from test_release_recovery import publication
import github_release as release
import release_admin as administration


def assert_tenant_lock_held(root):
    code = ('import fcntl,sys; f=open(sys.argv[1],"a"); '
            'fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB)')
    attempt = subprocess.run([sys.executable, '-I', '-B', '-c', code,
        root / 'private/tenant-admin.lock'], capture_output=True)
    assert attempt.returncode != 0 and b'BlockingIOError' in attempt.stderr


def test_missing_work_is_prepared_under_owner_and_lock_before_backup(publication, monkeypatch):
    p = publication
    work = p.root / 'work'
    work.rmdir()
    admitted = []

    def admit(path):
        assert Path(path) == Path(release.__file__)
        assert_tenant_lock_held(p.root)
        assert not work.exists()
        admitted.append(path)

    def backup(*args):
        assert_tenant_lock_held(p.root)
        assert admitted == [release.__file__]
        assert work == work.resolve(strict=True) and work.is_dir()
        assert stat.S_IMODE(work.stat().st_mode) == 0o700
        assert work.stat().st_uid == os.getuid()
        p.backups.append(args)
        return ['synthetic']

    monkeypatch.setattr(administration, 'require_current', admit)
    monkeypatch.setattr(release, 'runtime_backups', backup)
    assert release.publish(p.checkout, p.target, {})['status'] == 'published'
    assert len(p.backups) == 1
    records = list(work.glob('github-release-*'))
    assert len(records) == 1 and (records[0] / 'plan.json').is_file()


@pytest.mark.parametrize('kind', ['symlink', 'dangling-symlink', 'file', 'group-write', 'other-write'])
def test_unsafe_work_fails_before_backup_without_adoption(publication, kind):
    p = publication
    work = p.root / 'work'
    work.rmdir()
    if kind in ('symlink', 'dangling-symlink'):
        target = p.root / 'unrelated'
        if kind == 'symlink':
            target.mkdir(mode=0o700)
        work.symlink_to(target, target_is_directory=True)
    elif kind == 'file':
        work.write_bytes(b'synthetic-existing-object')
    else:
        work.mkdir(mode=0o720 if kind == 'group-write' else 0o702)
        work.chmod(0o720 if kind == 'group-write' else 0o702)
    before = work.lstat()
    with pytest.raises(administration.AdminError):
        release.publish(p.checkout, p.target, {})
    after = work.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid) == (
        before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid)
    assert not p.backups and not p.commands
    assert not (p.state / 'whatsapp/pending.json').exists()
    assert not (p.state / 'whatsapp/transaction.json').exists()
    assert release.literal(p.root / 'sally_whatsapp/__init__.py', '__version__') == '0.3.1'


def test_foreign_owned_work_fails_before_backup_without_chown(publication, monkeypatch):
    p = publication
    work = p.root / 'work'
    original = Path.lstat
    observed = []
    # The unprivileged Cloud cannot chown fixtures to another UID. Report that
    # one inode's foreign owner at the filesystem seam; trusted_path and its
    # actual UID policy still run unchanged.
    def lstat(path, *args, **kwargs):
        metadata = original(path, *args, **kwargs)
        if path == work:
            observed.append(path)
            values = list(metadata)
            values[4] = os.getuid() + 1
            return os.stat_result(values)
        return metadata
    monkeypatch.setattr(Path, 'lstat', lstat)
    before = work.lstat()
    with pytest.raises(administration.AdminError):
        release.publish(p.checkout, p.target, {})
    assert observed and work.stat().st_uid == os.getuid() != before.st_uid
    assert not p.backups and not p.commands


def test_unsafe_parent_fails_before_work_creation_or_backup(publication):
    p = publication
    work = p.root / 'work'
    work.rmdir()
    p.root.chmod(0o777)
    with pytest.raises(administration.AdminError):
        release.publish(p.checkout, p.target, {})
    assert not work.exists() and not p.backups and not p.commands
    assert stat.S_IMODE(p.root.stat().st_mode) == 0o777


def test_work_creation_error_occurs_before_backup(publication, monkeypatch):
    p = publication
    work = p.root / 'work'
    work.rmdir()
    original = Path.mkdir

    def mkdir(path, *args, **kwargs):
        if path == work:
            raise PermissionError('synthetic protected filesystem refusal')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'mkdir', mkdir)
    with pytest.raises(PermissionError):
        release.publish(p.checkout, p.target, {})
    assert not p.backups and not p.commands and not work.exists()


def test_owner_admission_failure_prevents_work_creation_and_backup(publication, monkeypatch):
    p = publication
    work = p.root / 'work'
    work.rmdir()

    def reject(path):
        assert_tenant_lock_held(p.root)
        raise administration.AdminError('synthetic owner admission refused')

    monkeypatch.setattr(administration, 'require_current', reject)
    with pytest.raises(administration.AdminError, match='owner admission refused'):
        release.publish(p.checkout, p.target, {})
    assert not work.exists() and not p.backups and not p.commands


def test_existing_protected_work_and_retained_files_are_preserved(publication):
    p = publication
    work = p.root / 'work'
    work.chmod(0o755)
    retained = work / 'retained-synthetic-record'
    retained.write_bytes(b'keep-existing-evidence')
    before = work.stat()
    assert release.publish(p.checkout, p.target, {})['status'] == 'published'
    after = work.stat()
    assert (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid) == (
        before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid)
    assert retained.read_bytes() == b'keep-existing-evidence' and len(p.backups) == 1


def test_dry_run_does_not_create_publication_work(publication):
    p = publication
    work = p.root / 'work'
    work.rmdir()
    assert release.publish(p.checkout, {**p.target, 'dryRun': True}, {})['status'] == 'verified'
    assert not work.exists() and not p.backups and not p.commands

"""WhatsApp-only periodic/boot recovery from an admitted immutable generation.

The stable WhatsApp entrypoint selects this module. No other project's state,
configuration, helpers, publication lock or recovery scheduler is consulted.
"""
import json
import os
import sys

RECOVERY_OWNER_STATES = ('dedicated', 'retiring')


def check():
    """Read-only attestation; safe while the caller already owns its lock."""
    import release_admin as admin
    import release_backup as backup
    generation = admin.require_current(__file__, states=RECOVERY_OWNER_STATES)
    admin.require_current(backup.__file__, expected=generation, states=RECOVERY_OWNER_STATES)
    return {**backup.capabilities(), 'project': 'whatsapp',
            'generation': str(generation.path), 'epoch': generation.epoch,
            'manifestSha256': generation.manifest_sha256,
            'entrypoint': str(admin.ENTRYPOINT)}


def recover_project(project='whatsapp'):
    import fcntl
    import release_admin as admin
    from github_release_common import require
    import github_release as release
    import release_transaction as transaction
    import release_backup as backup
    require(project == 'whatsapp', 'This recovery entrypoint accepts only WhatsApp')
    try:
        # Admission is rechecked after locking, before any journal or service
        # change. A previously imported/retired generation cannot recover.
        with admin.publication_lock(__file__, states=RECOVERY_OWNER_STATES) as generation:
            for module in (release, transaction, backup):
                admin.require_current(module.__file__, expected=generation, states=RECOVERY_OWNER_STATES)
            with (release.ROOT/'private/tenant-admin.lock').open('a') as tenant_lock:
                try:
                    fcntl.flock(tenant_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return
                # Backup stops services before activation creates its journal.
                # A prior published transaction must not skip this recovery.
                if backup.read() is not None:
                    backup.recover(release.ROOT, release.instances(release.ROOT),
                        lambda components, version: release.restore_backup_components(
                            components, version, lock_fd=tenant_lock.fileno()))
                if not transaction.JOURNAL.exists():
                    return
                plan = json.loads(transaction.JOURNAL.read_text())
                if plan['phase'] in ('published', 'rolled-back'):
                    return
                transaction.recover(plan, release.wait_health, lock_fd=tenant_lock.fileno())
    except admin.AdminBusy:
        return  # Another WhatsApp operation owns the publication lock.


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if os.geteuid() != 0:
        raise SystemExit('Root required')
    if args == ['--check']:
        print(json.dumps(check()), flush=True)
    elif not args:
        recover_project()
    else:
        raise SystemExit('Usage: WhatsApp recovery [--check]')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Journald must not receive private configuration or journal contents.
        raise SystemExit('WhatsApp recovery requires inspection of its private administration state') from None

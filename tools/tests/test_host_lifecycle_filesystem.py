"""Real filesystem transactions beneath temporary roots; no host/service action."""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SOURCE = Path(__file__).resolve().parents[2] / 'host/lifecycle/filesystem.py'
spec = importlib.util.spec_from_file_location('lifecycle_filesystem_tested', SOURCE)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


def file_spec(content, *, retention='managed', mode=0o644):
    return {'sha256': hashlib.sha256(content).hexdigest(), 'mode': mode,
            'uid': os.getuid(), 'gid': os.getgid(), 'retention': retention}


def directory_spec():
    return {'mode': 0o755, 'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'retain'}


def manifest(owner='whatsapp', files=None, directories=None, links=None):
    result = {'format': 1, 'owner': owner, 'files': files or {}, 'directories': directories or {}}
    if links is not None:
        result['links'] = links
    return result


@pytest.fixture
def case(tmp_path):
    base = tmp_path / 'host'; base.mkdir()
    (base / 'var/lib').mkdir(parents=True)
    (base / 'etc/app').mkdir(parents=True)
    (base / 'etc/app').chmod(0o755)
    (base / 'etc/app/old.py').write_bytes(b'old source')
    (base / 'etc/app/old.py').chmod(0o644)
    (base / 'etc/app/remove.py').write_bytes(b'retired source')
    (base / 'etc/app/remove.py').chmod(0o644)
    (base / 'etc/app/data.sqlite').write_bytes(b'current data retained')
    (base / 'etc/app/data.sqlite').chmod(0o644)
    before = manifest(files={'/etc/app/old.py': file_spec(b'old source'),
                             '/etc/app/remove.py': file_spec(b'retired source'),
                             '/etc/app/data.sqlite': file_spec(b'current data retained', retention='retain')},
                      directories={'/etc/app': directory_spec()})
    after = manifest(files={'/etc/app/old.py': file_spec(b'new source'),
                            '/etc/app/new.py': file_spec(b'raise RuntimeError("never executed")'),
                            '/etc/app/data.sqlite': before['files']['/etc/app/data.sqlite']},
                     directories={'/etc/app': directory_spec(), '/etc/app/new-directory': directory_spec()})
    payloads = {'/etc/app/old.py': b'new source', '/etc/app/new.py': b'raise RuntimeError("never executed")'}
    allowed = set(before['files']) | set(after['files']) | set(before['directories']) | set(after['directories'])
    with engine.Root(base) as root:
        yield root, base, before, after, payloads, allowed


def apply(case, *, operation_id='a' * 32, fault=None):
    root, _, before, after, payloads, allowed = case
    return engine.reconcile(root, operation_id=operation_id, before=before, after=after,
                            payloads=payloads, allowed_paths=allowed, fault=fault)


def verify_after(case, receipt):
    root, base, before, after, _, _ = case
    for path, desired in after['files'].items():
        assert root.snapshot(path) == {key: value for key, value in desired.items() if key != 'retention'}
    assert not (base / 'etc/app/remove.py').exists()
    assert (base / 'etc/app/data.sqlite').read_bytes() == b'current data retained'
    assert (base / 'etc/app/new-directory').is_dir()
    assert receipt['phase'] == 'committed'
    for path, quarantine in receipt['quarantine'].items():
        assert root.snapshot(quarantine) == {key: value for key, value in before['files'][path].items() if key != 'retention'}


def test_install_upgrade_remove_and_exact_quarantine(case):
    receipt = apply(case)
    verify_after(case, receipt)
    root, base, _, after, _, allowed = case
    removed = manifest(files={'/etc/app/data.sqlite': after['files']['/etc/app/data.sqlite']}, directories=after['directories'])
    second = engine.reconcile(root, operation_id='b' * 32, before=after, after=removed,
                              payloads={}, allowed_paths=allowed)
    assert root.snapshot('/etc/app/old.py') is None and root.snapshot('/etc/app/new.py') is None
    assert (base / 'etc/app/new-directory').is_dir()
    assert (base / 'etc/app/data.sqlite').read_bytes() == b'current data retained'
    assert all(root.snapshot(path) is not None for path in receipt['quarantine'].values())
    assert len(second['quarantine']) == 2


@pytest.mark.parametrize('event', ['journal-staging', 'staged-file', 'journal-prepared', 'journal-applying',
                                  'intent-directory', 'created-directory', 'completed-directory', 'intent-file', 'quarantined-file',
                                  'replaced-file', 'removed-file', 'completed-file', 'journal-committed'])
def test_every_durable_phase_resumes_forward_after_new_root(case, event):
    root, base, _, _, payloads, allowed = case
    observed = []
    def crash(name, detail):
        observed.append(name)
        if name == event:
            raise RuntimeError('simulated process interruption')
    with pytest.raises(RuntimeError, match='interruption'):
        apply(case, fault=crash)
    assert event in observed
    with engine.Root(base) as restarted:
        receipt = engine.resume(restarted, owner='whatsapp', operation_id='a' * 32,
                                allowed_paths=allowed, payloads=payloads)
    verify_after(case, receipt)
    replay = apply(case)
    assert replay == receipt


def test_preflight_all_targets_before_creating_control_or_managed_files(case):
    _, base, _, _, _, _ = case
    (base / 'etc/app/remove.py').write_bytes(b'changed by another operation')
    with pytest.raises(engine.LifecycleError, match='changed file'):
        apply(case)
    assert (base / 'etc/app/old.py').read_bytes() == b'old source'
    assert not (base / 'etc/app/new.py').exists()
    assert not (base / 'var/lib/develative-host-lifecycle').exists()


@pytest.mark.parametrize('mutation', ['unmanaged', 'mode', 'hash', 'symlink-file', 'symlink-parent', 'unsafe-parent'])
def test_unmanaged_mismatch_and_symlink_escape_are_refused_without_writes(case, tmp_path, mutation):
    _, base, _, _, _, _ = case
    outside = tmp_path / 'outside'; outside.mkdir()
    victim = outside / 'old.py'; victim.write_bytes(b'outside remains')
    if mutation == 'unmanaged':
        (base / 'etc/app/new.py').write_bytes(b'unmanaged')
    elif mutation == 'mode':
        (base / 'etc/app/old.py').chmod(0o600)
    elif mutation == 'hash':
        (base / 'etc/app/old.py').write_bytes(b'mismatched')
    elif mutation == 'symlink-file':
        (base / 'etc/app/old.py').unlink(); (base / 'etc/app/old.py').symlink_to(victim)
    elif mutation == 'symlink-parent':
        (base / 'etc/app').rename(base / 'etc/saved'); (base / 'etc/app').symlink_to(outside, target_is_directory=True)
    else:
        (base / 'etc/app').chmod(0o777)
    with pytest.raises(engine.LifecycleError):
        apply(case)
    assert victim.read_bytes() == b'outside remains'
    assert not (base / 'var/lib/develative-host-lifecycle').exists()


def test_operation_identity_binds_plan_payload_and_exact_policy(case):
    apply(case)
    root, _, before, after, payloads, allowed = case
    with pytest.raises(engine.LifecycleError, match='policy'):
        engine.resume(root, owner='whatsapp', operation_id='a' * 32, allowed_paths=allowed | {'/etc/unapproved'})
    changed = copy.deepcopy(after); changed['files']['/etc/app/new.py'] = file_spec(b'different')
    with pytest.raises(engine.LifecycleError, match='another plan'):
        engine.reconcile(root, operation_id='a' * 32, before=before, after=changed,
                         payloads={**payloads, '/etc/app/new.py': b'different'}, allowed_paths=allowed)
    with pytest.raises(engine.LifecycleError, match='Payload digest'):
        engine.resume(root, owner='whatsapp', operation_id='a' * 32, allowed_paths=allowed,
                      payloads={'/etc/app/new.py': b'not the declared payload'})


def test_retained_data_directories_and_independent_policy_cannot_be_overridden(case):
    root, _, before, after, payloads, allowed = case
    changed = copy.deepcopy(after); changed['files'].pop('/etc/app/data.sqlite')
    with pytest.raises(engine.LifecycleError, match='Retained'):
        engine.reconcile(root, operation_id='a' * 32, before=before, after=changed, payloads=payloads, allowed_paths=allowed)
    changed = copy.deepcopy(after); changed['directories'].pop('/etc/app')
    with pytest.raises(engine.LifecycleError, match='Directories are retained'):
        engine.reconcile(root, operation_id='a' * 32, before=before, after=changed, payloads=payloads, allowed_paths=allowed)
    with pytest.raises(engine.LifecycleError, match='outside the independent'):
        engine.reconcile(root, operation_id='a' * 32, before=before, after=after, payloads=payloads,
                         allowed_paths=allowed - {'/etc/app/new.py'})


def test_partial_operation_is_not_reinterpreted_as_fresh_and_missing_stage_needs_payload(case):
    root, base, _, _, _, allowed = case
    def crash(event, detail):
        if event == 'journal-staging':
            raise RuntimeError('interrupt')
    with pytest.raises(RuntimeError): apply(case, fault=crash)
    with pytest.raises(engine.LifecycleError, match='supply the same'):
        engine.resume(root, owner='whatsapp', operation_id='a' * 32, allowed_paths=allowed)
    assert (base / 'etc/app/old.py').read_bytes() == b'old source'
    (base / 'var/lib/develative-host-lifecycle/whatsapp/operations' / ('a' * 32) / 'journal.json').unlink()
    with pytest.raises(engine.LifecycleError, match='incomplete'):
        apply(case)
    assert (base / 'etc/app/old.py').read_bytes() == b'old source'


def test_explicit_small_control_payload_survives_kill_before_any_staging(case):
    root, base, _, _, _, _ = case
    path = '/etc/control-receipt.json'
    dynamic = json.dumps({'observed_process': 312, 'invocation': 'fixture-only'}).encode()
    after = manifest('host', files={path: file_spec(dynamic, mode=0o600)})
    def crash(event, detail):
        if event == 'journal-staging': raise RuntimeError('lost caller memory')
    with pytest.raises(RuntimeError):
        engine.reconcile(root, operation_id='e' * 32, before=manifest('host'), after=after,
                         payloads={path: dynamic}, inline_payloads={path}, allowed_paths={path}, fault=crash)
    del dynamic
    assert not (base / path.lstrip('/')).exists()
    with engine.Root(base) as restarted:
        receipt = engine.resume(restarted, owner='host', operation_id='e' * 32, allowed_paths={path})
    assert json.loads(root.read_bytes(path)) == {'observed_process': 312, 'invocation': 'fixture-only'}
    assert receipt['phase'] == 'committed'


def test_inline_payload_bound_and_tampering_fail_closed(case):
    root, base, _, _, _, _ = case
    path = '/etc/control-receipt.json'
    oversized = b'x' * (engine.MAX_INLINE_ENCODED_BYTES * 3 // 4 + 1)
    after = manifest('host', files={path: file_spec(oversized)})
    with pytest.raises(engine.LifecycleError, match='encoded bound'):
        engine.reconcile(root, operation_id='e' * 32, before=manifest('host'), after=after,
                         payloads={path: oversized}, inline_payloads={path}, allowed_paths={path})
    assert not (base / 'var/lib/develative-host-lifecycle').exists()
    def crash(event, detail):
        if event == 'journal-staging': raise RuntimeError('interrupt')
    after = manifest('host', files={path: file_spec(b'actual')})
    with pytest.raises(RuntimeError):
        engine.reconcile(root, operation_id='e' * 32, before=manifest('host'), after=after,
                         payloads={path: b'actual'}, inline_payloads={path}, allowed_paths={path}, fault=crash)
    journal_path = base / 'var/lib/develative-host-lifecycle/host/operations' / ('e' * 32) / 'journal.json'
    journal = json.loads(journal_path.read_bytes()); journal['inline_payloads'][path] = 'eA=='
    journal_path.write_bytes(engine.encoded(journal))
    with pytest.raises(engine.LifecycleError, match='Payload digest'):
        engine.resume(root, owner='host', operation_id='e' * 32, allowed_paths={path})
    assert not (base / path.lstrip('/')).exists()


def test_payload_and_quarantine_tampering_stop_without_restoring_old_files(case):
    root, base, _, _, _, allowed = case
    receipt = apply(case)
    quarantine = next(iter(receipt['quarantine'].values()))
    (base / quarantine.lstrip('/')).write_bytes(b'tampered quarantine')
    with pytest.raises(engine.LifecycleError, match='Quarantine'):
        engine.resume(root, owner='whatsapp', operation_id='a' * 32, allowed_paths=allowed)
    assert (base / 'etc/app/old.py').read_bytes() == b'new source'


def test_staged_payload_tampering_and_late_target_change_fail_before_managed_writes(case):
    root, base, _, _, payloads, allowed = case
    def crash(event, detail):
        if event == 'journal-prepared':
            raise RuntimeError('interrupt')
    with pytest.raises(RuntimeError): apply(case, fault=crash)
    staged = base / 'var/lib/develative-host-lifecycle/whatsapp/operations' / ('a' * 32) / 'payload-0'
    staged.chmod(0o600); staged.write_bytes(b'tampered')
    with pytest.raises(engine.LifecycleError, match='staged payload'):
        engine.resume(root, owner='whatsapp', operation_id='a' * 32, allowed_paths=allowed, payloads=payloads)
    assert (base / 'etc/app/old.py').read_bytes() == b'old source'
    assert not (base / 'etc/app/new-directory').exists()


def test_staging_does_not_allow_a_late_mismatch_before_first_managed_write(case):
    _, base, _, _, _, _ = case
    def changed(event, detail):
        if event == 'journal-applying':
            (base / 'etc/app/remove.py').write_bytes(b'changed during staging')
    with pytest.raises(engine.LifecycleError, match='differs from both'):
        apply(case, fault=changed)
    assert (base / 'etc/app/old.py').read_bytes() == b'old source'
    assert not (base / 'etc/app/new-directory').exists()


def test_resume_does_not_adopt_matching_unmanaged_file_without_prior_intent(case):
    root, base, _, _, payloads, allowed = case
    def crash(event, detail):
        if event == 'journal-prepared':
            raise RuntimeError('interrupt')
    with pytest.raises(RuntimeError): apply(case, fault=crash)
    path = base / 'etc/app/new.py'; path.write_bytes(payloads['/etc/app/new.py']); path.chmod(0o644)
    with pytest.raises(engine.LifecycleError, match='before its recorded intent'):
        engine.resume(root, owner='whatsapp', operation_id='a' * 32, allowed_paths=allowed, payloads=payloads)
    assert (base / 'etc/app/old.py').read_bytes() == b'old source'


def test_interruption_between_mkdir_and_final_metadata_resumes_only_recorded_new_directory(case, monkeypatch):
    root, base, _, _, payloads, allowed = case
    original = root._mkdir
    def partial(path, spec):
        if path == '/etc/app/new-directory':
            with root._parent(path) as (parent, name):
                os.mkdir(name, 0o700, dir_fd=parent)
                os.fsync(parent)
            raise RuntimeError('power loss before directory metadata')
        original(path, spec)
    monkeypatch.setattr(root, '_mkdir', partial)
    with pytest.raises(RuntimeError, match='power loss'): apply(case)
    assert (base / 'etc/app/new-directory').stat().st_mode & 0o777 == 0o700
    monkeypatch.setattr(root, '_mkdir', original)
    receipt = engine.resume(root, owner='whatsapp', operation_id='a' * 32, allowed_paths=allowed, payloads=payloads)
    verify_after(case, receipt)
    assert (base / 'etc/app/new-directory').stat().st_mode & 0o777 == 0o755


def test_same_owner_lock_busy_other_owner_progresses_without_shared_lock(case):
    root, base, _, _, _, _ = case
    receipt = apply(case)
    lock = base / 'var/lib/develative-host-lifecycle/whatsapp/lock'
    inode = lock.stat().st_ino
    with lock.open('rb') as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(engine.LifecycleBusy): apply(case)
        result = engine.reconcile(root, operation_id='b' * 32, before=manifest('box'),
             after=manifest('box', files={'/etc/box.py': file_spec(b'box')}),
             payloads={'/etc/box.py': b'box'}, allowed_paths={'/etc/box.py'})
        assert result['phase'] == 'committed'
    assert lock.stat().st_ino == inode
    assert root.snapshot('/etc/box.py')['sha256'] == hashlib.sha256(b'box').hexdigest()
    assert receipt['owner'] == 'whatsapp'


def test_exact_named_links_install_replace_remove_without_following_targets(case):
    root, base, _, _, _, _ = case
    target = '/etc/app/old.py'; link = '/etc/app/enabled'
    link_spec = {'target': target, 'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'managed'}
    before = manifest('host')
    after = manifest('host', links={link: link_spec})
    receipt = engine.reconcile(root, operation_id='b' * 32, before=before, after=after,
                              payloads={}, allowed_paths={link, target})
    assert os.readlink(base / link.lstrip('/')) == target
    assert root.link(link) == {key: value for key, value in link_spec.items() if key != 'retention'}
    removed = engine.reconcile(root, operation_id='c' * 32, before=after, after=before,
                              payloads={}, allowed_paths={link, target})
    assert not (base / link.lstrip('/')).is_symlink()
    assert os.readlink(base / removed['quarantine'][link].lstrip('/')) == target
    assert (base / 'etc/app/old.py').read_bytes() == b'old source'
    assert receipt['phase'] == 'committed'


@pytest.mark.parametrize('event', ['intent-file', 'quarantined-file', 'replaced-file', 'completed-file', 'journal-committed'])
def test_link_replacement_resumes_without_dereference_or_target_mutation(case, event):
    root, base, _, _, _, _ = case
    link = '/etc/app/enabled'
    old = {'target': '/etc/app/old.py', 'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'managed'}
    new = {**old, 'target': '/etc/app/remove.py'}
    os.symlink(old['target'], base / link.lstrip('/'))
    before, after = manifest('host', links={link: old}), manifest('host', links={link: new})
    allowed = {link, old['target'], new['target']}
    def crash(name, detail):
        if name == event: raise RuntimeError('interrupted link update')
    with pytest.raises(RuntimeError):
        engine.reconcile(root, operation_id='d' * 32, before=before, after=after,
                         payloads={}, allowed_paths=allowed, fault=crash)
    receipt = engine.resume(root, owner='host', operation_id='d' * 32, allowed_paths=allowed)
    assert os.readlink(base / link.lstrip('/')) == new['target']
    assert os.readlink(base / receipt['quarantine'][link].lstrip('/')) == old['target']
    assert (base / 'etc/app/old.py').read_bytes() == b'old source'
    assert (base / 'etc/app/remove.py').read_bytes() == b'retired source'


@pytest.mark.parametrize('bad_target', ['/etc/app/missing', '/etc/app/enabled', '/etc/app/../old.py'])
def test_links_refuse_unattested_dangling_recursive_or_noncanonical_targets(case, bad_target):
    root, base, _, _, _, _ = case
    spec = {'target': bad_target, 'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'managed'}
    with pytest.raises(engine.LifecycleError):
        engine.reconcile(root, operation_id='b' * 32, before=manifest('host'),
            after=manifest('host', links={'/etc/app/enabled': spec}), payloads={},
            allowed_paths={'/etc/app/enabled', bad_target})
    assert not (base / 'etc/app/enabled').is_symlink()


def test_fresh_upgrade_manifests_are_compared_exactly_and_bounded_schema_is_closed():
    desired = manifest(files={'/etc/a': file_spec(b'a')})
    assert engine.equivalent_managed(desired, {**desired, 'links': {}})
    different = copy.deepcopy(desired); different['files']['/etc/a']['mode'] = 0o600
    assert not engine.equivalent_managed(desired, different)
    for invalid in ({**desired, 'extra': True}, {**desired, 'format': True}, {**desired, 'owner': 'other'},
                    manifest(files={'/etc/../a': file_spec(b'a')}),
                    manifest(files={'/etc/a': {**file_spec(b'a'), 'mode': 0o4755}})):
        with pytest.raises(engine.LifecycleError): engine.validate_manifest(invalid)


def test_marking_inactive_artifacts_retained_preserves_inode_and_exact_directory_tree(case):
    root, base, _, _, _, _ = case
    path = '/etc/app/old.py'
    before = manifest(files={path: file_spec(b'old source')})
    after = copy.deepcopy(before); after['files'][path]['retention'] = 'retain'
    inode = (base / path.lstrip('/')).stat().st_ino
    tree = sorted(item.name for item in (base / 'etc/app').iterdir())
    receipt = engine.reconcile(root, operation_id='e' * 32, before=before, after=after,
                               payloads={}, allowed_paths={path})
    assert receipt['changed'] == [] and receipt['quarantine'] == {}
    assert (base / path.lstrip('/')).stat().st_ino == inode
    assert sorted(item.name for item in (base / 'etc/app').iterdir()) == tree
    assert engine.resume(root, owner='whatsapp', operation_id='e' * 32,
                         allowed_paths={path}) == receipt


def test_inspect_operation_validates_exact_intent_without_mutating_or_resuming(case):
    root, base, _, _, _, allowed = case
    with pytest.raises(engine.LifecycleError):
        engine.inspect_operation(root, owner='whatsapp', operation_id='a' * 32, allowed_paths=allowed)
    assert not (base / 'var/lib/develative-host-lifecycle').exists()
    def interrupt(event, detail):
        if event == 'journal-staging': raise RuntimeError('durable intent only')
    with pytest.raises(RuntimeError): apply(case, fault=interrupt)
    def snapshot():
        return {item.relative_to(base): (item.read_bytes(), item.stat().st_mtime_ns, item.stat().st_ctime_ns)
                for item in base.rglob('*') if item.is_file()}
    before = snapshot()
    intent = engine.inspect_operation(root, owner='whatsapp', operation_id='a' * 32, allowed_paths=allowed)
    assert intent['phase'] == 'staging' and intent['done'] == []
    assert snapshot() == before
    intent['after']['files'].clear()
    assert engine.inspect_operation(root, owner='whatsapp', operation_id='a' * 32,
                                    allowed_paths=allowed)['after']['files']
    with pytest.raises(engine.LifecycleError, match='policy'):
        engine.inspect_operation(root, owner='whatsapp', operation_id='a' * 32,
                                 allowed_paths=allowed | {'/etc/unreviewed'})
    assert snapshot() == before


def test_relative_apache_links_preserve_literal_and_quarantine(case):
    root, base, _, _, _, _ = case
    for name in ('sites-available', 'sites-enabled'):
        (base / 'etc/apache2' / name).mkdir(parents=True)
    target = '/etc/apache2/sites-available/app.conf'
    link = '/etc/apache2/sites-enabled/app.conf'
    (base / target.lstrip('/')).write_bytes(b'physical vhost')
    spec = {'target': '../sites-available/app.conf', 'resolved_target': target,
            'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'managed'}
    before, after = manifest('host'), manifest('host', links={link: spec})
    allowed = {link, target}
    engine.reconcile(root, operation_id='f' * 32, before=before, after=after,
                     payloads={}, allowed_paths=allowed)
    assert os.readlink(base / link.lstrip('/')) == spec['target']
    assert root.link(link)['resolved_target'] == target
    receipt = engine.reconcile(root, operation_id='1' * 32, before=after, after=before,
                               payloads={}, allowed_paths=allowed)
    assert os.readlink(base / receipt['quarantine'][link].lstrip('/')) == spec['target']
    assert (base / target.lstrip('/')).read_bytes() == b'physical vhost'


@pytest.mark.parametrize('literal,resolved', [('../../../../escape', '/escape'),
    ('../app/old.py', '/etc/wrong'), ('old.py', None), ('../app/../app/old.py', '/etc/app/old.py')])
def test_relative_links_reject_escape_mismatch_missing_resolution_and_aliases(case, literal, resolved):
    root, base, _, _, _, _ = case
    spec = {'target': literal, 'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'managed'}
    if resolved is not None: spec['resolved_target'] = resolved
    with pytest.raises(engine.LifecycleError):
        engine.reconcile(root, operation_id='f' * 32, before=manifest('host'),
                         after=manifest('host', links={'/etc/app/enabled': spec}),
                         payloads={}, allowed_paths={'/etc/app/enabled', '/etc/app/old.py', '/escape', '/etc/wrong'})
    assert not (base / 'etc/app/enabled').is_symlink()


def test_relative_link_rejects_literal_drift_and_symlink_endpoint(case):
    root, base, _, _, _, _ = case
    link, target = '/etc/app/enabled', '/etc/app/old.py'
    spec = {'target': 'old.py', 'resolved_target': target, 'uid': os.getuid(),
            'gid': os.getgid(), 'retention': 'managed'}
    os.symlink('../app/old.py', base / link.lstrip('/'))
    with pytest.raises(engine.LifecycleError):
        engine.reconcile(root, operation_id='f' * 32, before=manifest('host', links={link: spec}),
                         after=manifest('host'), payloads={}, allowed_paths={link, target})
    (base / link.lstrip('/')).unlink()
    (base / target.lstrip('/')).unlink()
    os.symlink('remove.py', base / target.lstrip('/'))
    with pytest.raises(engine.LifecycleError):
        engine.reconcile(root, operation_id='e' * 32, before=manifest('host'),
                         after=manifest('host', links={link: spec}), payloads={}, allowed_paths={link, target})

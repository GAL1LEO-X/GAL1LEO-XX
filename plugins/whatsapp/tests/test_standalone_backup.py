"""External IdP backups on synthetic files/SQLite, with all service I/O replaced."""
from contextlib import closing
import copy
import importlib.util
import io
import json
import hashlib
import os
from pathlib import Path
import pwd
import sqlite3
import sys
import tarfile
from types import SimpleNamespace

import pytest

from sally_whatsapp.tenancy import Instance, render_config
from sally_whatsapp.store import SCHEMA
from test_backup_runtime import prepare_installation

SCRIPTS = Path(__file__).parents[1]/'scripts'
sys.path.insert(0, str(SCRIPTS))
import backup_validation as validation
import tenant_database as secure


def tar(path, files):
    with tarfile.open(path, 'w:gz') as output:
        for name, content in files.items():
            info = tarfile.TarInfo(name); info.size = len(content)
            output.addfile(info, io.BytesIO(content))


@pytest.fixture
def case(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('standalone_backup_runtime', SCRIPTS/'backup_runtime.py')
    backup = importlib.util.module_from_spec(spec); spec.loader.exec_module(backup)
    host = tmp_path/'host'; host.mkdir()
    def mapped(value):
        path = Path(value)
        return path if path.is_relative_to(host) else host/str(path).lstrip('/')
    project = mapped('/srv/openai-codex/projects/whatsapp-personal')
    project.mkdir(parents=True)
    logical = Instance('fixture', 'Synthetic', 'opaque-external-subject', 8824,
        public_hostname='messages.team.example.test', issuer='https://identity.example.test',
        jwks_url='https://identity.example.test/keys', auth_mode='external-oidc',
        oauth_client_id='mcp-client', pairing_client_id='pairing-client')
    instance = SimpleNamespace(**{name:getattr(logical, name) for name in
        ('slug','base','auth_mode','subject','public_url','issuer','effective_jwks_url',
         'chatgpt_client','link_client','bridge_port','gateway_port')}, service_user=pwd.getpwuid(os.getuid()).pw_name,
        **{name:mapped(getattr(logical, name)) for name in
        ('config_dir','state_dir','gateway_home','private_dir','wrapper')})
    for path in (instance.config_dir, instance.state_dir, instance.private_dir,
                 instance.gateway_home/'sessions', instance.gateway_home/'media'):
        path.mkdir(parents=True, exist_ok=True)
    config = instance.config_dir/'config.toml'
    config.write_text(render_config(logical, authorize_url='https://identity.example.test/authorize',
        token_url='https://identity.example.test/token').replace(str(logical.state_dir), str(instance.state_dir)))
    identity = {'protocol':1, 'id':'a'*32, 'tenant':hashlib.sha256(json.dumps(
        [instance.subject,instance.public_url,'default'], separators=(',', ':')).encode()).hexdigest()}
    (instance.config_dir/'technical-state.json').write_text(json.dumps(identity))
    for name in ('encryption.key','webhook.key','waha.key'):
        (instance.config_dir/name).write_text('synthetic-not-a-credential')
    with closing(sqlite3.connect(instance.state_dir/'archive.sqlite')) as db:
        db.executescript(SCHEMA)
        db.execute('INSERT INTO state(key,value) VALUES (?,?)', (secure.KEY,json.dumps(identity)))
        db.execute('INSERT INTO state(key,value) VALUES (?,?)', ('backup-proof','"synthetic"'))
        db.commit()
    (project/'private').mkdir(exist_ok=True)
    registry = project/'private/tenants.json'
    registry.write_text(json.dumps({'format':1,'instances':{'fixture':{'spec':logical.record()}}}))
    calls = []; snapshots = []
    def run(argv, **options):
        args = list(map(str, argv)); calls.append(args)
        if args[0] == 'systemctl' or args[0] == str(instance.wrapper):
            assert args[-1] in (instance.base+'.service', 'whatsapp-waha.service')
            assert 'is-active' in args
            return SimpleNamespace(returncode=3)
        assert args == [str(project/'.venv/bin/python'), str(project/'scripts/package_source.py'), args[-1]]
        assert Path(args[-1]).is_relative_to(host/'var/backups')
        tar(Path(args[-1]), {name:b'# synthetic source\n' for name in
            ('pyproject.toml','requirements.lock','sally_whatsapp/__init__.py','sally_whatsapp/store.py')})
        return SimpleNamespace(returncode=0)
    original = backup.snapshot_database
    def snapshot(source, target):
        source, target = mapped(source), Path(target)
        assert source.is_relative_to(host) and target.is_relative_to(host)
        snapshots.append(source)
        original(source, target)
    monkeypatch.setattr(backup, 'ROOT', project)
    monkeypatch.setattr(backup, 'Path', mapped)
    prepare_installation(backup, host, monkeypatch)
    monkeypatch.setattr(backup, 'snapshot_database', snapshot)
    monkeypatch.setattr(secure, '_TRUST_ROOT', host)
    monkeypatch.setattr(secure, '_TRUST_UID', os.getuid())
    def tenant_snapshot(instance,target,**options):
        snapshots.append(instance.state_dir/'archive.sqlite')
        secure.snapshot_tenant_database(instance,target,**options)
    monkeypatch.setattr(backup, 'snapshot_tenant_database', tenant_snapshot)
    monkeypatch.setattr(backup, 'subprocess', SimpleNamespace(run=run))
    monkeypatch.setattr(backup.httpx, 'Client', lambda **kwargs: pytest.fail('inactive fixture must not use HTTP'))
    return SimpleNamespace(backup=backup, instance=instance, logical=logical, host=host,
        mapped=mapped, project=project, registry=registry, config=config, calls=calls, snapshots=snapshots)


def test_external_backup_omits_local_idp_and_passes_explicit_validation(case):
    result = case.backup.backup(case.instance)
    snapshot = Path(result['backup'])
    assert result['complete']
    assert [p.name for p in case.snapshots] == ['archive.sqlite']
    assert not case.mapped('/var/lib/sally-browser').exists()
    assert {p.name for p in snapshot.iterdir()} == {
        'manifest.json','archive.sqlite','source.tar.gz','private-runtime.tar.gz'}
    manifest = validation.validate_snapshot(snapshot,'fixture',runtime_prefix=case.host,auth_mode='external-oidc')
    assert manifest['format'] == 'whatsapp-isolated-backup-v5'
    assert manifest['auth_mode'] == 'external-oidc'
    with closing(sqlite3.connect(snapshot/'archive.sqlite')) as db:
        assert db.execute('SELECT value FROM state WHERE key=?',('backup-proof',)).fetchone()[0] == '"synthetic"'
    with tarfile.open(snapshot/'private-runtime.tar.gz') as archive:
        assert all('sally-browser' not in member.name for member in archive)
    with pytest.raises(ValueError):
        validation.validate_snapshot(snapshot,'fixture',runtime_prefix=case.host)


@pytest.mark.parametrize('missing', ['config.toml','encryption.key','webhook.key','waha.key'])
def test_writer_never_publishes_complete_when_required_material_disappears(case,monkeypatch,missing):
    snapshot = case.backup.snapshot_tenant_database
    def lose_file(instance,target,**options):
        snapshot(instance,target,**options)
        (case.instance.config_dir/missing).unlink()
    monkeypatch.setattr(case.backup,'snapshot_tenant_database',lose_file)
    restored = []; completed = []
    monkeypatch.setattr(case.backup,'restore_components',lambda *args,**kw:restored.append(args) or [])
    journal = SimpleNamespace(before_stop=lambda *args:None,copy_complete=lambda *args:completed.append(args))
    with pytest.raises(case.backup.BackupError) as failure:
        case.backup.backup(case.instance,recovery_id='synthetic-operation',recovery=journal)
    assert not failure.value.complete and not completed
    assert len(restored) == 1
    assert [stage for stage,_ in failure.value.failures] == ['snapshot']
    assert 'missing required files' in str(failure.value.failures[0][1])


def test_complete_journal_is_written_only_after_full_validator_accepts_artifact(case,monkeypatch):
    original = case.backup.validate_snapshot; order = []
    def validate(*args,**options):
        result = original(*args,**options)
        order.append('validated')
        return result
    monkeypatch.setattr(case.backup,'validate_snapshot',validate)
    journal = SimpleNamespace(before_stop=lambda *args:None,copy_complete=lambda *args:order.append('complete'))
    assert case.backup.backup(case.instance,recovery_id='synthetic-operation',recovery=journal)['complete']
    assert order == ['validated','complete']


@pytest.mark.parametrize('field', ['public_url','issuer','owner_subject','jwks_url','oauth_client_ids','link_client_id'])
def test_external_identity_mismatch_stops_before_snapshot_and_services(case, field):
    import tomllib
    values = tomllib.loads(case.config.read_text())['bridge']
    values[field] = ['other-client'] if field == 'oauth_client_ids' else 'different-explicit-identity'
    case.config.write_text('[bridge]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in values.items())+'\n')
    with pytest.raises(ValueError, match='External OIDC backup configuration'):
        case.backup.backup(case.instance)
    assert case.calls == case.snapshots == []
    assert not (case.host/'var/backups').exists()


@pytest.mark.parametrize('damage', ['missing','malformed','mode-none','mode-unknown'])
def test_invalid_external_selection_does_not_authorize_skip(case, damage):
    if damage == 'missing': case.config.unlink()
    elif damage == 'malformed': case.config.write_text('not TOML [')
    else: case.instance.auth_mode = None if damage == 'mode-none' else 'automatic'
    with pytest.raises((ValueError,OSError)):
        case.backup.backup(case.instance)
    assert case.calls == case.snapshots == []


def test_legacy_missing_mode_still_requires_shared_authentication(case):
    del case.instance.auth_mode
    with pytest.raises(case.backup.BackupError) as failure:
        case.backup.backup(case.instance)
    assert not failure.value.complete
    assert [p.name for p in case.snapshots] == ['archive.sqlite','db.sqlite3']


def test_managed_backup_v5_requires_both_idp_configs_and_explicit_mode(case):
    case.instance.auth_mode = 'managed-authelia'
    auth = case.mapped('/var/lib/sally-browser/stack/authelia/db.sqlite3')
    auth.parent.mkdir(parents=True)
    with closing(sqlite3.connect(auth)) as db:
        db.execute('CREATE TABLE user_opaque_identifier(service TEXT,sector_id TEXT,username TEXT,identifier TEXT)')
    for name in ('authelia.yml','users.yml'):
        path = case.mapped('/var/lib/sally-browser/stack/config')/name
        path.parent.mkdir(parents=True,exist_ok=True); path.write_text('synthetic only')
    result = case.backup.backup(case.instance)
    manifest = validation.validate_snapshot(result['backup'],'fixture',runtime_prefix=case.host)
    assert manifest['format'] == 'whatsapp-isolated-backup-v5' and manifest['auth_mode'] == 'managed-authelia'
    assert 'shared-authelia.sqlite3' in manifest['files']
    with pytest.raises(ValueError):
        validation.validate_snapshot(result['backup'],'fixture',runtime_prefix=case.host,auth_mode='external-oidc')


def test_external_snapshot_cannot_relax_hash_or_inventory_gate(case):
    result = case.backup.backup(case.instance); snapshot = Path(result['backup'])
    path = snapshot/'archive.sqlite'; original = path.read_bytes(); path.write_bytes(original+b'tampered')
    with pytest.raises(ValueError,match='size differs'):
        validation.validate_snapshot(snapshot,'fixture',runtime_prefix=case.host,auth_mode='external-oidc')
    path.write_bytes(original)
    (snapshot/'shared-authelia.sqlite3').write_bytes(b'undeclared')
    with pytest.raises(ValueError,match='inventory'):
        validation.validate_snapshot(snapshot,'fixture',runtime_prefix=case.host,auth_mode='external-oidc')


@pytest.mark.parametrize('damage', ['missing-registry','duplicate-mode','unknown-mode','different-slug','untrusted'])
def test_registry_authority_is_required_for_explicit_external_mode(case, damage):
    value = json.loads(case.registry.read_text())
    if damage == 'missing-registry': case.registry.unlink()
    elif damage == 'duplicate-mode':
        case.registry.write_text(case.registry.read_text().replace('"auth_mode":', '"auth_mode":"managed-authelia","auth_mode":'))
    elif damage == 'unknown-mode':
        value['instances']['fixture']['spec']['auth_mode']='auto'
        case.registry.write_text(json.dumps(value))
    elif damage == 'different-slug':
        value['instances']['fixture']['spec']['slug']='another'
        case.registry.write_text(json.dumps(value))
    checked = []
    def trusted(path):
        assert path == case.registry
        checked.append(path)
        if damage == 'untrusted': raise ValueError('untrusted administrative registry')
        return path
    with pytest.raises((ValueError,OSError)):
        case.backup.registered_instances(case.registry, SimpleNamespace(trusted_path=trusted))
    assert checked == [case.registry]
    assert case.calls == case.snapshots == []


def test_valid_registry_carries_explicit_mode_and_legacy_records_stay_managed(case):
    admin = SimpleNamespace(trusted_path=lambda path:path)
    selected = case.backup.registered_instances(case.registry, admin)['fixture']
    assert isinstance(selected, Instance) and selected.auth_mode == 'external-oidc'
    assert selected.record() == case.logical.record()
    legacy = Instance('fixture','Synthetic','11111111-1111-4111-8111-111111111111',8824).record()
    del legacy['auth_mode']
    case.registry.write_text(json.dumps({'format':1,'instances':{'fixture':{'spec':legacy}}}))
    assert case.backup.registered_instances(case.registry, admin)['fixture'].auth_mode == 'managed-authelia'


def test_release_validator_requires_matching_registered_mode(case, monkeypatch):
    import github_release as release
    result = case.backup.backup(case.instance)
    receipt = json.dumps(result)
    monkeypatch.setattr(release, 'BACKUPS', case.host/'var/backups')
    # Only map archive paths to the synthetic host; real validation and mode selection remain.
    def validate(directory, user, **options):
        return validation.validate_snapshot(directory,user,runtime_prefix=case.host,**options)
    monkeypatch.setattr(release, 'validate_snapshot', validate)
    assert release.verify_backups(receipt,['fixture'],auth_modes={'fixture':'external-oidc'}) == [result['backup']]
    with pytest.raises(release.ReleaseError,match='backup validation failed'):
        release.verify_backups(receipt,['fixture'])
    with pytest.raises(release.ReleaseError,match='authentication modes'):
        release.verify_backups(receipt,['fixture'],auth_modes={})


@pytest.mark.parametrize('damage', ['format','missing-mode','wrong-mode','invalid-mode-input'])
def test_external_manifest_format_is_not_inferred_from_missing_files(case, damage):
    result = case.backup.backup(case.instance); snapshot = Path(result['backup'])
    path = snapshot/'manifest.json'; manifest = json.loads(path.read_text())
    if damage == 'format': manifest['format']='whatsapp-isolated-backup-v3'
    elif damage == 'missing-mode': del manifest['auth_mode']
    elif damage == 'wrong-mode': manifest['auth_mode']='managed-authelia'
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        validation.validate_snapshot(snapshot,'fixture',runtime_prefix=case.host,
            auth_mode=None if damage=='invalid-mode-input' else 'external-oidc')


@pytest.mark.parametrize('damage', ['none','writable-registry','writable-parent','symlink'])
def test_actual_administration_protection_precedes_registry_selection(case, monkeypatch, damage):
    import os
    import release_admin as administration
    # The only authority seam maps administrative UID0 to this fixture's owner.
    monkeypatch.setattr(administration, '_TRUST_ROOT', case.host)
    monkeypatch.setattr(administration, '_trusted_uid', lambda uid:uid==os.geteuid())
    if damage == 'writable-registry': case.registry.chmod(0o666)
    elif damage == 'writable-parent': case.registry.parent.chmod(0o777)
    elif damage == 'symlink':
        original = case.registry.with_suffix('.original')
        case.registry.rename(original); case.registry.symlink_to(original)
    if damage == 'none':
        assert case.backup.registered_instances(case.registry,administration)['fixture'].auth_mode == 'external-oidc'
    else:
        with pytest.raises(administration.AdminError):
            case.backup.registered_instances(case.registry,administration)
    assert case.calls == case.snapshots == []

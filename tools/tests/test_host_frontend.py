"""Host frontend effects on isolated files, synthetic material and fake Apache."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


front = module('frontend_provider_tests', 'host/frontend/provider.py')
engine = module('frontend_filesystem_tests', 'host/lifecycle/filesystem.py')


def spec(data):
    return {'sha256': front.digest(data), 'mode': 0o640, 'uid': 0, 'gid': 0, 'retention': 'managed'}


@pytest.fixture
def registry():
    raw = {'/etc/apache2/apache2.conf': b'IncludeOptional sites-enabled/*.conf\n'}
    hooks = {}
    for event in ('deploy', 'post'):
        name = '/usr/local/lib/develative-host-frontend/legacy-' + event
        raw[name] = b'#!/bin/sh\n# Synthetic preserved hook; tests never execute it.\n'
        hooks[event] = {'path': name, 'sha256': front.digest(raw[name])}
    consumers, lineages = {}, {}
    for owner, slug in [('box', 'web'), ('whatsapp', 'owner'), ('host', 'sally')]:
        name, host = owner + '.' + slug, slug + '.example.test'
        vhost = '/etc/apache2/sites-enabled/' + slug + '.conf'
        raw[vhost] = ('# Synthetic pinned ' + name + '\n<VirtualHost *:443>\nServerName ' + host + '\n</VirtualHost>\n').encode()
        lineage = '/etc/letsencrypt/live/' + host
        consumers[name] = {'owner': owner, 'status': 'active', 'domains': [host], 'vhosts': [vhost], 'lineages': [lineage]}
        lineages[lineage] = {'domains': [host], 'consumers': [name],
            'source': {'certificate': lineage + '/fullchain.pem', 'key': lineage + '/privkey.pem'},
            'destinations': [{'consumer': name, 'mode': 'copy', 'certificate': '/etc/tls/' + slug + '-cert.pem',
                'key': '/etc/tls/' + slug + '-key.pem', 'uid': 0, 'gid': 0, 'certificate_mode': 0o640, 'key_mode': 0o600}]}
    value = {'format': 1, 'provider': front.PROVIDER, 'version': front.VERSION, 'owner': 'host',
        'apache': {'unit': 'apache2.service', 'config_path': '/etc/apache2/apache2.conf'},
        'scheduler': {'owner': 'host', 'unit': 'certbot.timer'}, 'artifacts': {name: spec(data) for name, data in raw.items()},
        'directories': {name: {'mode': 0o750, 'uid': 0, 'gid': 0, 'retention': 'retain'}
                        for name in ('/etc', '/etc/apache2', '/etc/apache2/sites-enabled', '/etc/develative-host-frontend',
                                     '/usr', '/usr/local', '/usr/local/lib', '/usr/local/lib/develative-host-frontend')},
        'links': {}, 'host_files': ['/etc/apache2/apache2.conf', *(item['path'] for item in hooks.values())],
        'consumers': consumers, 'lineages': lineages, 'legacy_hooks': hooks}
    for hook in hooks.values(): value['artifacts'][hook['path']]['mode'] = 0o750
    return value, raw


@pytest.fixture
def root(tmp_path):
    (tmp_path / 'var/lib').mkdir(parents=True)
    with engine.Root(tmp_path) as value:
        yield value


def local_manifest(value, root):
    """Map production root ownership to the isolated fixture authority."""
    value = copy.deepcopy(value)
    for kind in ('files', 'directories', 'links'):
        for metadata in value.get(kind, {}).values():
            metadata.update(uid=root.uid, gid=root.gid)
    return value


def empty():
    return {'format': 1, 'owner': 'host', 'files': {}, 'directories': {}, 'links': {}}


class Apache:
    def __init__(self, root):
        self.root, self.events, self.fail_reload = root, [], False
    def validate_staged(self, manifest, payloads):
        self.events.append('stage')
        assert all(front.digest(body) == manifest['files'][name]['sha256'] for name, body in payloads.items())
        return {'ok': True, 'configuration_sha256': front.digest(front.encoded(manifest))}
    def validate_active(self, manifest):
        self.events.append('active')
        assert all(self.root.snapshot(name)['sha256'] == item['sha256'] for name, item in manifest['files'].items())
        return {'ok': True, 'configuration_sha256': front.digest(front.encoded(manifest))}
    def reload_apache(self, fingerprint):
        self.events.append('reload')
        if self.fail_reload: raise RuntimeError('synthetic response lost')
        return True
    def validate_certificate_pair(self, certificate, key, domains):
        self.events.append('pair')
        return certificate == b'SYNTHETIC-CERT' and key == b'SYNTHETIC-KEY' and bool(domains)


def apply(root, adapter, operation, before, rendered):
    after = local_manifest(rendered['manifest'], root)
    paths = (set(before['files']) | set(after['files']) | set(before['directories']) | set(after['directories'])
             | set(before.get('links', {})) | set(after.get('links', {})))
    result = front.reconcile_edge(root, engine=engine, operation_id=operation, before=before, after=after,
        payloads=rendered['payloads'], allowed_paths=paths, adapter=adapter)
    return result, after


@pytest.mark.parametrize('owner,remaining', [('box', 'whatsapp.owner'), ('whatsapp', 'box.web')])
def test_adoption_and_application_retirement_preserve_other_app_and_host(registry, root, owner, remaining):
    value, raw = registry
    original = copy.deepcopy(value)
    adapter = Apache(root)
    _, current = apply(root, adapter, '1' * 32, empty(), front.render(value, raw))
    retired = front.retire_consumers(value, owner)
    result, _ = apply(root, adapter, '2' * 32, current, front.render(retired, raw))
    assert result['phase'] == 'complete'
    assert value == original
    assert root.read_bytes(value['consumers'][remaining]['vhosts'][0]) == raw[value['consumers'][remaining]['vhosts'][0]]
    assert root.read_bytes('/etc/apache2/apache2.conf') == raw['/etc/apache2/apache2.conf']
    assert root.read_bytes('/etc/apache2/sites-enabled/sally.conf') == raw['/etc/apache2/sites-enabled/sally.conf']
    assert retired['scheduler'] == value['scheduler']
    for item in value['consumers'].values():
        if item['owner'] == owner: assert root.snapshot(item['vhosts'][0]) is None
    assert adapter.events == ['stage', 'active', 'reload'] * 2


def test_retiring_last_application_retains_host_and_single_scheduler(registry):
    value, raw = registry
    for owner in ('box', 'whatsapp'): value = front.retire_consumers(value, owner)
    rendered = front.render(value, raw)
    assert '/etc/apache2/sites-enabled/sally.conf' in rendered['payloads']
    assert value['scheduler']['unit'] == 'certbot.timer'
    with pytest.raises(front.FrontendError): front.retire_consumers(value, 'host')


def test_pinned_box_and_sally_cannot_be_rewritten_by_template_defaults(registry):
    value, raw = registry
    raw['/etc/apache2/sites-enabled/web.conf'] += b'# unreviewed change\n'
    with pytest.raises(front.FrontendError, match='Pinned'): front.render(value, raw)


def test_cross_owner_shared_vhost_is_not_silently_retained_with_removed_app_routes(registry):
    value, raw = registry
    old = value['consumers']['whatsapp.owner']['vhosts'][0]
    value['consumers']['whatsapp.owner']['vhosts'] = value['consumers']['box.web']['vhosts'][:]
    del value['artifacts'][old]; del raw[old]
    with pytest.raises(front.FrontendError, match='mixed-owner'):
        front.render(value, raw)


def test_configtest_failure_precedes_any_managed_activation(registry, root):
    value, raw = registry
    adapter = Apache(root)
    adapter.validate_staged = lambda *args: {'ok': False}
    with pytest.raises(front.FrontendError, match='Staged'):
        apply(root, adapter, '3' * 32, empty(), front.render(value, raw))
    assert root.snapshot('/etc/apache2/apache2.conf') is None
    assert adapter.events == []
    assert front._load_receipt(root, '3' * 32)['phase'] == 'prepared'


def test_reload_failure_has_durable_phase_and_resumes_without_republishing(registry, root):
    value, raw = registry
    rendered = front.render(value, raw)
    adapter = Apache(root); adapter.fail_reload = True
    with pytest.raises(RuntimeError): apply(root, adapter, '4' * 32, empty(), rendered)
    assert front._load_receipt(root, '4' * 32)['phase'] == 'reloading'
    adapter.fail_reload = False
    result, _ = apply(root, adapter, '4' * 32, empty(), rendered)
    assert result['phase'] == 'complete'
    assert adapter.events == ['stage', 'active', 'reload', 'active', 'reload']
    apply(root, adapter, '4' * 32, empty(), rendered)
    assert adapter.events.count('reload') == 2


def test_fresh_and_upgrade_render_same_managed_manifest(registry):
    value, raw = registry
    assert front.render(value, raw) == front.render(json.loads(json.dumps(value)), copy.deepcopy(raw))


def test_relative_enabled_link_preserves_literal_and_retires_only_its_consumer(registry, root):
    value, raw = registry
    old = value['consumers']['whatsapp.owner']['vhosts'][0]
    target = '/etc/apache2/sites-available/owner.conf'
    raw[target] = raw.pop(old)
    value['artifacts'][target] = value['artifacts'].pop(old)
    value['directories']['/etc/apache2/sites-available'] = value['directories']['/etc/apache2/sites-enabled'].copy()
    value['links'][old] = {'target': '../sites-available/owner.conf', 'resolved_target': target,
                           'uid': 0, 'gid': 0, 'retention': 'managed'}
    value['consumers']['whatsapp.owner']['vhosts'].append(target)
    _, before = apply(root, Apache(root), '8' * 32, empty(), front.render(value, raw))
    assert root.link(old)['target'] == '../sites-available/owner.conf'
    assert root.link(old)['resolved_target'] == target
    apply(root, Apache(root), '9' * 32, before, front.render(front.retire_consumers(value, 'whatsapp'), raw))
    assert root.link(old) is None and root.snapshot(target) is None
    assert root.snapshot(value['consumers']['box.web']['vhosts'][0]) is not None


class Renewal:
    def __init__(self): self.events = []
    def legacy_deploy(self, hook, lineage, hosts):
        self.events.append(('legacy', hook, lineage, hosts)); return {'status': 'delegated'}
    def validate_lineage(self, lineage, source, hosts):
        self.events.append(('validate', lineage, hosts))
        return {'domains': hosts, 'certificate_sha256': 'b' * 64, 'key_matches': True, 'source_revision': 'c' * 64}
    def deploy_materials(self, lineage, source, targets, proof, apache):
        self.events.append(('deploy', targets, apache))
        return {'status': 'complete', 'source_revision': proof['source_revision']}
    def legacy_post(self, hook):
        self.events.append(('post', hook)); return {'status': 'delegated'}


def test_exact_lineage_and_domains_route_wa_without_legacy_allowlist_failure(registry):
    value, _ = registry; adapter = Renewal()
    lineage = '/etc/letsencrypt/live/owner.example.test'
    outcome = front.handle_deploy_hook(value, lineage=lineage, renewed_domains='owner.example.test', adapter=adapter)
    assert outcome['status'] == 'complete'
    assert [event[0] for event in adapter.events] == ['validate', 'deploy']


@pytest.mark.parametrize('lineage,hosts', [('/other/lineage', 'owner.example.test'),
    ('/etc/letsencrypt/live/owner.example.test', 'web.example.test'),
    ('/etc/letsencrypt/live/owner.example.test', 'owner.example.test web.example.test'),
    ('/etc/letsencrypt/live/owner.example.test', 'owner.example.test owner.example.test')])
def test_mismatched_lineage_or_domain_set_has_no_hook_effect(registry, lineage, hosts):
    adapter = Renewal()
    with pytest.raises(front.FrontendError): front.handle_deploy_hook(registry[0], lineage=lineage, renewed_domains=hosts, adapter=adapter)
    assert adapter.events == []


def test_unknown_other_service_keeps_exact_attested_legacy_route(registry):
    value, _ = registry; adapter = Renewal()
    front.handle_deploy_hook(value, lineage='/etc/letsencrypt/live/other.example.test',
                            renewed_domains='other.example.test', adapter=adapter)
    assert adapter.events == [('legacy', value['legacy_hooks']['deploy'],
                              '/etc/letsencrypt/live/other.example.test', ['other.example.test'])]


def test_post_event_is_not_multiplied_per_renewed_lineage(registry):
    value, _ = registry; adapter = Renewal()
    for host in ('owner.example.test', 'web.example.test'):
        front.handle_deploy_hook(value, lineage='/etc/letsencrypt/live/' + host, renewed_domains=host, adapter=adapter)
    assert not any(event[0] == 'post' for event in adapter.events)
    front.handle_post_hook(value, adapter=adapter)
    assert adapter.events[-1] == ('post', value['legacy_hooks']['post'])


def test_legacy_source_change_blocks_execution(registry, root):
    value, raw = registry; adapter = Apache(root)
    apply(root, adapter, '9' * 32, empty(), front.render(value, raw))
    calls = []
    runner = type('Runner', (), {'execute_legacy': lambda _, selected, env: calls.append((selected, env))})()
    hook = value['legacy_hooks']['deploy']
    front.invoke_pinned_legacy(root, hook, event='deploy', lineage='/etc/letsencrypt/live/other.example.test',
                              renewed_domains=['other.example.test'], runner=runner)
    assert len(calls) == 1
    (root.base / hook['path'].lstrip('/')).write_bytes(b'# Unexpected replaced source\n')
    with pytest.raises(front.FrontendError, match='protected source'):
        front.invoke_pinned_legacy(root, hook, event='deploy', lineage='/etc/letsencrypt/live/other.example.test',
                                  renewed_domains=['other.example.test'], runner=runner)
    assert len(calls) == 1


def test_retired_consumer_renewal_does_not_recreate_vhost_or_copy_material(registry):
    value = front.retire_consumers(registry[0], 'whatsapp'); adapter = Renewal()
    outcome = front.handle_deploy_hook(value, lineage='/etc/letsencrypt/live/owner.example.test',
                                      renewed_domains='owner.example.test', adapter=adapter)
    assert outcome['deployed'] is False and adapter.events == []


def test_tls_copies_complete_before_reload_and_retry_keeps_original_plan(root):
    (root.base / 'etc/tls').mkdir(parents=True)
    cert, key = b'SYNTHETIC-CERT', b'SYNTHETIC-KEY'
    proof = {'domains': ['owner.example.test'], 'key_matches': True, 'certificate_sha256': front.digest(cert),
             'source_revision': front.digest(front.encoded({'certificate_sha256': front.digest(cert), 'key_sha256': front.digest(key)}))}
    target = {'consumer': 'whatsapp.owner', 'mode': 'copy', 'certificate': '/etc/tls/fullchain.pem',
              'key': '/etc/tls/privkey.pem', 'uid': root.uid, 'gid': root.gid, 'certificate_mode': 0o640, 'key_mode': 0o600}
    adapter = Apache(root); adapter.fail_reload = True
    kwargs = dict(engine=engine, operation_id='5' * 32, targets=[target], proof=proof, certificate=cert, key=key,
                  allowed_paths={target['certificate'], target['key']}, adapter=adapter)
    with pytest.raises(RuntimeError): front.deploy_materials(root, **kwargs)
    assert root.read_bytes(target['certificate']) == cert and root.read_bytes(target['key']) == key
    assert root.snapshot(target['key'])['mode'] == 0o600
    assert front._load_receipt(root, '5' * 32)['phase'] == 'reloading'
    adapter.fail_reload = False
    result = front.deploy_materials(root, **kwargs)
    assert result['status'] == 'complete' and len(result['copied_paths']) == 2
    assert adapter.events == ['pair', 'stage', 'active', 'reload', 'pair', 'active', 'reload']
    with pytest.raises(front.FrontendError, match='source changed'):
        front.deploy_materials(root, **{**kwargs, 'certificate': b'STALE-COPY'})


finite = module('frontend_adapter_tests', 'host/frontend/adapter.py')


def finite_profile(value, root):
    tools = {}
    for tool in ('apache', 'openssl', 'systemctl'):
        name = '/usr/sbin/apache2' if tool == 'apache' else '/usr/bin/' + tool
        selected = root.base / name.lstrip('/')
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_bytes(b'#!/bin/sh\nexit 0\n'); selected.chmod(0o700)
        tools[tool] = {'path': name, 'sha256': front.digest(selected.read_bytes())}
    (root.base / 'etc/letsencrypt').mkdir(parents=True, exist_ok=True)
    targets = sorted(item['vhosts'][0] for item in value['consumers'].values())
    return {'format': 1, 'apache': {**value['apache'], 'server_root': '/etc/apache2'},
        'tools': tools, 'environment': {},
        'config_files': [value['apache']['config_path'], *targets],
        'includes': [{'file': value['apache']['config_path'], 'line': 1,
                      'text': 'IncludeOptional sites-enabled/*.conf', 'targets': targets}],
        'tls': [], 'dependencies': {},
        'certbot_lock': {'directory': '/etc/letsencrypt', 'protocol': 'posix-lockf-unlink-before-close-v1',
                         'source': tools['systemctl'].copy()},
        'lineages': {name: {'archive_directory': name.replace('/live/', '/archive/'),
            'renewal': {'path': name.replace('/live/', '/renewal/') + '.conf', 'sha256': front.digest(b'renewal fixture\n')}}
            for name in value['lineages']}}


class FiniteCommands:
    def __init__(self): self.calls, self.stages = [], []
    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if '-t' in argv:
            entry = Path(argv[argv.index('-f') + 1])
            assert entry.is_file()
            text = entry.read_text()
            if 'configtest-' in str(entry):
                assert 'IncludeOptional sites-enabled/' not in text
                children = [Path(line.split('"')[1]) for line in text.splitlines() if line.startswith('Include ')]
                assert children and all(item.is_file() for item in children)
                assert all('configtest-' in str(item) for item in children)
                self.stages.append({str(item): item.read_bytes() for item in children})
        return b''


def staged_setup(registry, root):
    value, raw = copy.deepcopy(registry)
    for kind in ('artifacts', 'directories', 'links'):
        for item in value[kind].values(): item.update(uid=root.uid, gid=root.gid)
    (root.base / front.STATE.lstrip('/')).mkdir(parents=True, mode=0o700)
    profile = finite_profile(value, root)
    for name, item in value['directories'].items():
        existing = root.directory(name)
        if existing is not None: item.update(existing)
    runner = FiniteCommands()
    adapter = finite.HostAdapter(root, engine, value, profile, runner=runner)
    return value, raw, profile, runner, adapter


def test_finite_apply_stages_entire_graph_then_validates_and_reloads_exact_unit(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    with adapter.lease():
        result = finite.apply_configuration(adapter, operation_id='a' * 32, before=empty(), pinned_artifacts=raw)
    assert result['phase'] == 'complete'
    assert len(runner.stages) == 1 and len(runner.stages[0]) == 3
    assert len(runner.calls) == 3
    assert runner.calls[-1] == [adapter.physical(profile['tools']['systemctl']['path']), 'reload', 'apache2.service']
    assert root.read_bytes('/etc/apache2/sites-enabled/web.conf') == raw['/etc/apache2/sites-enabled/web.conf']
    with pytest.raises(finite.provider.FrontendError, match='lease'):
        adapter.validate_active(result['after'])


def test_finite_stage_rejects_unmodelled_nested_include_before_publication(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    name = '/etc/apache2/sites-enabled/web.conf'
    raw[name] += b'Include /etc/unpinned-secret.conf\n'
    value['artifacts'][name]['sha256'] = front.digest(raw[name])
    adapter = finite.HostAdapter(root, engine, value, profile, runner=runner)
    with adapter.lease(), pytest.raises(finite.provider.FrontendError, match='Unmodelled'):
        finite.apply_configuration(adapter, operation_id='b' * 32, before=empty(), pinned_artifacts=raw)
    assert runner.calls == [] and root.snapshot('/etc/apache2/apache2.conf') is None


def test_finite_active_graph_detects_extra_globbed_file_and_does_not_reload(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    with adapter.lease():
        result = finite.apply_configuration(adapter, operation_id='c' * 32, before=empty(), pinned_artifacts=raw)
        rogue = root.base / 'etc/apache2/sites-enabled/rogue.conf'
        rogue.write_text('# outside manifest\n')
        with pytest.raises(finite.provider.FrontendError, match='Uninventoried'):
            adapter.validate_active(result['after'])
    assert len(runner.calls) == 3


def test_retire_last_lineage_quarantines_only_exact_renewal_and_retries(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    value = front.retire_consumers(value, 'whatsapp')
    adapter = finite.HostAdapter(root, engine, value, profile, runner=runner)
    registry_path = root.base / front.REGISTRY.lstrip('/')
    registry_path.parent.mkdir(parents=True); registry_path.write_bytes(front.encoded(value))
    for entry in profile['lineages'].values():
        selected = root.base / entry['renewal']['path'].lstrip('/')
        selected.parent.mkdir(parents=True, exist_ok=True); selected.write_bytes(b'renewal fixture\n')
        selected.chmod(0o600)
    archive = root.base / 'etc/letsencrypt/archive/owner.example.test'
    archive.mkdir(parents=True); (archive / 'privkey1.pem').write_bytes(b'preserved synthetic key')
    with adapter.lease():
        first = adapter.retire_renewals(operation_id='d' * 32)
        second = adapter.retire_renewals(operation_id='d' * 32)
    removed = '/etc/letsencrypt/renewal/owner.example.test.conf'
    assert first == second and set(first['quarantine']) == {removed}
    assert root.snapshot(removed) is None
    assert root.read_bytes(first['quarantine'][removed]) == b'renewal fixture\n'
    assert root.snapshot('/etc/letsencrypt/renewal/web.example.test.conf') is not None
    assert (archive / 'privkey1.pem').read_bytes() == b'preserved synthetic key'
    assert runner.calls == []


def test_retirement_reads_current_registry_under_lease(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    selected = root.base / front.REGISTRY.lstrip('/')
    selected.parent.mkdir(parents=True); selected.write_bytes(front.encoded(front.retire_consumers(value, 'box')))
    with adapter.lease(), pytest.raises(finite.provider.FrontendError, match='registry changed'):
        adapter.retire_renewals(operation_id='e' * 32)
    assert runner.calls == []


def test_finite_openssl_pair_and_exact_san_with_synthetic_material(registry, root):
    import datetime
    import shutil
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    value, raw, profile, _, adapter = staged_setup(registry, root)
    binary = root.base / profile['tools']['openssl']['path'].lstrip('/')
    shutil.copyfile('/usr/bin/openssl', binary); binary.chmod(0o700)
    profile['tools']['openssl']['sha256'] = front.digest(binary.read_bytes())
    adapter = finite.HostAdapter(root, engine, value, profile)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'owner.example.test')])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(
        now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1)).add_extension(
        x509.SubjectAlternativeName([x509.DNSName('owner.example.test')]), critical=False).sign(key, hashes.SHA256())
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    assert adapter.validate_certificate_pair(cert_bytes, key_bytes, ['owner.example.test']) is True
    with pytest.raises(finite.provider.FrontendError, match='SAN'):
        adapter.validate_certificate_pair(cert_bytes, key_bytes, ['web.example.test'])
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong = other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with pytest.raises(finite.provider.FrontendError, match='do not match'):
        adapter.validate_certificate_pair(cert_bytes, wrong, ['owner.example.test'])
    assert not list((root.base / front.STATE.lstrip('/')).glob('tls-check-*'))


def test_certbot_lock_busy_in_other_process_refuses_before_configuration_effects(registry, root):
    import subprocess
    import sys
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    selected = root.base / 'etc/letsencrypt/.certbot.lock'
    script = 'import fcntl,os,sys; f=os.open(sys.argv[1],os.O_CREAT|os.O_WRONLY,0o600); fcntl.lockf(f,fcntl.LOCK_EX); print("locked",flush=True); sys.stdin.readline()'
    child = subprocess.Popen([sys.executable, '-c', script, str(selected)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'locked'
        with adapter.lease(), pytest.raises(finite.provider.FrontendError, match='Certbot is busy'):
            finite.apply_configuration(adapter, operation_id='f' * 32, before=empty(), pinned_artifacts=raw)
        assert runner.calls == [] and root.snapshot('/etc/apache2/apache2.conf') is None
        assert selected.exists()
    finally:
        child.communicate('\n', timeout=5)


def test_uninventoried_include_is_rejected_before_first_publication(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    rogue = root.base / 'etc/apache2/sites-enabled/rogue.conf'
    rogue.parent.mkdir(parents=True); rogue.write_text('UnknownDirective\n')
    with adapter.lease(), pytest.raises(finite.provider.FrontendError, match='Uninventoried'):
        finite.apply_configuration(adapter, operation_id='0a' * 16, before=empty(), pinned_artifacts=raw)
    assert runner.calls == [] and root.snapshot('/etc/apache2/apache2.conf') is None
    assert rogue.read_text() == 'UnknownDirective\n'


def test_runner_enforces_incremental_output_bound_and_timeout():
    import sys
    runner = finite.Runner()
    with pytest.raises(finite.provider.FrontendError, match='output exceeds'):
        runner.run([sys.executable, '-c', 'import os; os.write(1,b"x"*2097152)'], environment={}, timeout=5)
    with pytest.raises(finite.provider.FrontendError, match='timed out'):
        runner.run([sys.executable, '-c', 'import time; time.sleep(5)'], environment={}, timeout=0.05)
    assert runner.run([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'],
                      environment={}, input_bytes=b'bounded public input', timeout=5) == b'bounded public input'


def test_source_hashes_are_verified_for_entire_closure_before_operational_compile(monkeypatch):
    import hashlib
    sources = {name: b'raise AssertionError("must not execute before all hashes pass")\n' for name in finite.SOURCES}
    manifest = {'format': 1, 'sources': {name: hashlib.sha256(body).hexdigest() for name, body in sources.items()}}
    manifest['sources']['host/lifecycle/filesystem.py'] = '0' * 64
    body = front.encoded(manifest)
    def read(selected):
        selected = str(selected)
        if selected == '/reviewed.json': return body
        return next(content for name, content in sources.items() if selected.endswith(name))
    monkeypatch.setattr(finite, '_protected_bytes', read)
    with pytest.raises(finite.provider.FrontendError, match='Neutral source differs'):
        finite._bootstrap_sources('/reviewed.json', hashlib.sha256(body).hexdigest())


def test_tool_identity_cannot_select_an_interpreter_from_profile(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    profile['tools']['systemctl']['path'] = '/usr/bin/python3'
    with pytest.raises(finite.provider.FrontendError, match='finite allowlist'):
        finite.HostAdapter(root, engine, value, profile, runner=runner)
    assert runner.calls == []


def test_direct_lineage_is_rechecked_before_reload_and_changed_proof_is_not_adopted(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    lineage = '/etc/letsencrypt/live/owner.example.test'
    archive = root.base / profile['lineages'][lineage]['archive_directory'].lstrip('/')
    live = root.base / lineage.lstrip('/')
    archive.mkdir(parents=True); live.mkdir(parents=True)
    for target, content in (('fullchain1.pem', b'certificate-one'), ('privkey1.pem', b'key-one')):
        (archive / target).write_bytes(content); (archive / target).chmod(0o600)
    (live / 'fullchain.pem').symlink_to('../../archive/owner.example.test/fullchain1.pem')
    (live / 'privkey.pem').symlink_to('../../archive/owner.example.test/privkey1.pem')
    adapter.validate_certificate_pair = lambda *args: True  # Crypto is checked by the independent real-OpenSSL test above.
    with adapter.lease():
        proof = adapter.validate_lineage(lineage, value['lineages'][lineage]['source'], ['owner.example.test'])
        (archive / 'fullchain1.pem').write_bytes(b'certificate-two')
        for _ in range(2):
            with pytest.raises(finite.provider.FrontendError, match='changed before reload'):
                adapter.reload_apache('a' * 64)
        assert adapter.material[2] == proof
    assert runner.calls == []


def test_finite_apply_resumes_after_profile_published_before_registry(registry, root, monkeypatch):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    original = engine.reconcile
    crashed = False
    def interrupt(*args, **kwargs):
        nonlocal crashed
        def fault(event, detail):
            nonlocal crashed
            if not crashed and event == 'replaced-file' and detail['path'] == finite.PROFILE:
                crashed = True
                raise RuntimeError('synthetic interruption after profile')
        return original(*args, **{**kwargs, 'fault': fault})
    monkeypatch.setattr(engine, 'reconcile', interrupt)
    with adapter.lease(), pytest.raises(RuntimeError, match='synthetic interruption'):
        finite.apply_configuration(adapter, operation_id='ac' * 16, before=empty(), pinned_artifacts=raw)
    assert crashed and root.snapshot(finite.PROFILE) is not None and root.snapshot(front.REGISTRY) is None
    monkeypatch.setattr(engine, 'reconcile', original)
    with adapter.lease():
        result = finite.apply_configuration(adapter, operation_id='ac' * 16, before=empty(), pinned_artifacts=raw)
    assert result['phase'] == 'complete' and root.snapshot(finite.PROFILE) is not None


def test_cli_help_is_stdlib_only_and_works_before_provider_bootstrap():
    import subprocess
    import sys
    result = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'host/frontend/adapter.py'), '--help'],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    assert '--source-manifest' in result.stdout and 'deploy-hook' in result.stdout
    assert result.stderr == ''






def test_pending_http_consumer_publishes_http_without_claiming_tls_or_running_hook(registry):
    value, raw = copy.deepcopy(registry)
    lineage = value['consumers']['whatsapp.owner']['lineages'][0]
    del value['lineages'][lineage]
    value['consumers']['whatsapp.owner'].update(status='pending_tls', lineages=[])
    rendered = front.render(value, raw)
    assert value['consumers']['whatsapp.owner']['vhosts'][0] in rendered['payloads']
    adapter = Renewal()
    result = front.handle_deploy_hook(value, lineage=lineage, renewed_domains='owner.example.test', adapter=adapter)
    assert result == {'status': 'pending_tls', 'deployed': False, 'reason': 'await-explicit-lineage-binding'}
    assert adapter.events == []
    assert front.validate_registry(front.retire_consumers(value, 'whatsapp'))['consumers']['whatsapp.owner']['status'] == 'retired'
    value['consumers']['whatsapp.owner']['status'] = 'active'
    with pytest.raises(front.FrontendError, match='lineage references'):
        front.validate_registry(value)


def test_candidate_module_is_staged_before_loader_is_published(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    name = value['apache']['config_path']
    target = '/usr/local/lib/develative-host-qos/foreign/module.so'
    raw[target] = b'synthetic module bytes; not executed'
    value['artifacts'][target] = {**spec(raw[target]), 'uid': root.uid, 'gid': root.gid, 'retention': 'retain'}
    value['host_files'].append(target)
    for directory in ['/usr/local/lib/develative-host-qos', '/usr/local/lib/develative-host-qos/foreign']:
        value['directories'][directory] = {'mode': 0o750, 'uid': root.uid, 'gid': root.gid, 'retention': 'retain'}
    line = 'LoadModule box_priority_module ' + target
    raw[name] += line.encode() + b'\n'; value['artifacts'][name]['sha256'] = front.digest(raw[name])
    profile['modules'] = [{'file': name, 'line': 2, 'text': line, 'path': target, 'identifier': 'box_priority_module'}]
    class ModuleCommands(FiniteCommands):
        def run(self, argv, **kwargs):
            if '-t' in argv:
                entry = Path(argv[argv.index('-f') + 1])
                if 'configtest-' in str(entry):
                    import shlex
                    parsed = next(shlex.split(item) for item in entry.read_text().splitlines() if item.startswith('LoadModule'))
                    assert root.snapshot(target) is None
                    assert Path(parsed[2]).read_bytes() == raw[target]
                    assert 'configtest-' in parsed[2]
            return super().run(argv, **kwargs)
    adapter = finite.HostAdapter(root, engine, value, profile, runner=ModuleCommands())
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='7' * 32, before=empty(), pinned_artifacts=raw)
    assert root.read_bytes(target) == raw[target]
    assert root.read_bytes(name) == raw[name]








@pytest.mark.parametrize('owner,remaining', [('box', 'whatsapp.owner'), ('whatsapp', 'box.web')])
def test_finite_application_retirement_retries_from_receipt_and_preserves_survivor(registry, root, owner, remaining):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='17' * 16, before=empty(), pinned_artifacts=raw)
        result = adapter.retire_application(owner=owner, operation_id='18' * 16)
        count = len(runner.calls)
        again = adapter.retire_application(owner=owner, operation_id='18' * 16)
        status = adapter.retirement_status(owner)
    assert result == again and result['phase'] == 'complete'
    assert len(runner.calls) == count + 1 and '-t' in runner.calls[-1]
    assert status['status'] == 'retired' and remaining in status['retained_consumers']
    assert root.read_bytes(value['consumers'][remaining]['vhosts'][0]) == raw[value['consumers'][remaining]['vhosts'][0]]
    assert adapter.registry['scheduler'] == value['scheduler']
    assert root.snapshot('/etc/apache2/sites-enabled/sally.conf') is not None
    assert result['context'] == {'kind': 'retire-application', 'owner': owner,
        'retired_owner_sha256': front.retirement_identity(adapter.registry, owner)}


def test_finite_retirement_resumes_lost_reload_response_with_original_plan(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='27' * 16, before=empty(), pinned_artifacts=raw)
    original = runner.run
    def fail_reload(argv, **kwargs):
        if 'reload' in argv: raise RuntimeError('lost reload response')
        return original(argv, **kwargs)
    runner.run = fail_reload
    with adapter.lease(), pytest.raises(RuntimeError, match='lost reload'):
        adapter.retire_application(owner='whatsapp', operation_id='28' * 16)
    saved = front._load_receipt(root, '28' * 16)
    assert saved['phase'] == 'reloading'
    current = finite.load_protected_json(root, front.REGISTRY)
    adapter = finite.HostAdapter(root, engine, current, profile, runner=runner)
    runner.run = original
    with adapter.lease():
        result = adapter.retire_application(owner='whatsapp', operation_id='28' * 16)
    assert result['before'] == saved['before'] and result['phase'] == 'complete'
    assert root.snapshot('/etc/apache2/sites-enabled/web.conf') is not None


def test_application_route_cannot_be_disguised_as_retained_host_resource(registry):
    value, _ = registry
    value['host_files'].extend(value['consumers']['whatsapp.owner']['vhosts'])
    with pytest.raises(front.FrontendError, match='unremovable'):
        front.validate_registry(value)






def test_render_and_update_survivor_need_no_already_retired_source_bytes(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='37' * 16, before=empty(), pinned_artifacts=raw)
        removed = adapter.retire_application(owner='box', operation_id='38' * 16)
    retired = adapter.registry
    needed = {name: root.read_bytes(name) for name in front.managed_manifest(retired)['files'] if name != front.REGISTRY}
    assert value['consumers']['box.web']['vhosts'][0] not in needed
    assert front.render(retired, needed)['manifest'] == front.managed_manifest(retired)
    with adapter.lease():
        result = finite.apply_configuration(adapter, operation_id='39' * 16, before=removed['after'], pinned_artifacts=needed)
    assert result['phase'] == 'complete'
    assert root.snapshot(value['consumers']['whatsapp.owner']['vhosts'][0]) is not None


def test_sequential_app_removal_retires_only_own_renewals_without_reopening_removed_sources(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    for item in profile['lineages'].values():
        selected = root.base / item['renewal']['path'].lstrip('/')
        selected.parent.mkdir(parents=True, exist_ok=True); selected.write_bytes(b'renewal fixture\n'); selected.chmod(0o600)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='47' * 16, before=empty(), pinned_artifacts=raw)
        adapter.retire_application(owner='box', operation_id='48' * 16)
        first = adapter.retire_renewals(owner='box', operation_id='49' * 16)
        adapter.retire_application(owner='whatsapp', operation_id='4a' * 16)
        second = adapter.retire_renewals(owner='whatsapp', operation_id='4b' * 16)
    assert set(first['selected']) == {'/etc/letsencrypt/renewal/web.example.test.conf'}
    assert set(second['selected']) == {'/etc/letsencrypt/renewal/owner.example.test.conf'}
    assert root.snapshot('/etc/letsencrypt/renewal/sally.example.test.conf') is not None
    assert root.snapshot('/etc/apache2/sites-enabled/sally.conf') is not None


@pytest.mark.parametrize('key,value', [('APACHE_HTTPD', '/usr/bin/python3'),
                                      ('APACHE_ENVVARS', '/tmp/custom-env'), ('APACHE_ARGUMENTS', '-k start')])
def test_apache_wrapper_cannot_select_another_program_or_shell_source_from_profile(registry, root, key, value):
    current, raw, profile, runner, adapter = staged_setup(registry, root)
    profile['environment'][key] = value
    with pytest.raises(finite.provider.FrontendError, match='environment'):
        finite.HostAdapter(root, engine, current, profile, runner=runner)


def test_python_supervisor_keeps_lease_after_caller_death_and_client_fd_closure(tmp_path):
    import fcntl
    import os
    import signal
    import subprocess
    import sys
    import time
    selected = tmp_path / 'lease'; selected.write_bytes(b''); selected.chmod(0o600)
    ready, release, done = [tmp_path / name for name in ('ready', 'release', 'done')]
    child_code = '''import os,sys,time
from pathlib import Path
for fd in range(3,1024):
 try: os.close(fd)
 except OSError: pass
Path(sys.argv[1]).write_text(str(os.getpid()))
while not Path(sys.argv[2]).exists(): time.sleep(.01)
Path(sys.argv[3]).write_text('finished')
'''
    caller_code = '''import fcntl,importlib.util,os,sys
spec=importlib.util.spec_from_file_location('tested',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fd=os.open(sys.argv[2],os.O_RDWR); fcntl.flock(fd,fcntl.LOCK_EX)
m.Runner().run([sys.executable,'-c',sys.argv[3],*sys.argv[4:]],environment={'PATH':'/usr/bin:/bin'},timeout=8,pass_fds=(fd,))
'''
    caller = subprocess.Popen([sys.executable, '-B', '-c', caller_code, str(ROOT / 'host/frontend/adapter.py'),
                               str(selected), child_code, str(ready), str(release), str(done)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    descriptor = os.open(selected, os.O_RDWR)
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline: time.sleep(.01)
        assert ready.exists()
        caller.kill(); caller.wait(timeout=5)
        with pytest.raises(BlockingIOError): fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        release.write_text('go')
        deadline = time.monotonic() + 5
        acquired = False
        while time.monotonic() < deadline:
            try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB); acquired = True; break
            except BlockingIOError: time.sleep(.01)
        assert acquired and done.read_text() == 'finished'
    finally:
        release.touch(exist_ok=True)
        if caller.poll() is None: caller.kill(); caller.wait(timeout=5)
        os.close(descriptor)




def test_completed_apply_receipt_does_not_hide_later_physical_vhost_drift(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='57' * 16, before=empty(), pinned_artifacts=raw)
        target = root.base / value['consumers']['whatsapp.owner']['vhosts'][0].lstrip('/')
        target.write_bytes(b'# unexpected changed vhost\n')
        count = len(runner.calls)
        with pytest.raises(finite.provider.FrontendError, match='metadata differs'):
            finite.apply_configuration(adapter, operation_id='57' * 16, before=empty(), pinned_artifacts=raw)
    assert len(runner.calls) == count and target.read_bytes() == b'# unexpected changed vhost\n'


def test_pinned_outer_loader_uses_captured_provider_without_sibling_read(tmp_path):
    source = (ROOT / 'host/frontend/adapter.py').read_bytes()
    namespace = {'__name__': 'frontend_snapshot_adapter', '__file__': str(tmp_path / 'missing' / 'adapter.py'),
                 '_PINNED_PROVIDER': front}
    exec(compile(source, namespace['__file__'], 'exec'), namespace)
    assert namespace['provider'] is front


def test_durable_pending_configuration_blocks_new_retirement_and_configuration_after_caller_loss(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    ordinary = runner.run
    def fail_reload(argv, **kwargs):
        if 'reload' in argv: raise RuntimeError('synthetic lost reload response')
        return ordinary(argv, **kwargs)
    runner.run = fail_reload
    with adapter.lease(), pytest.raises(RuntimeError):
        finite.apply_configuration(adapter, operation_id='61' * 16, before=empty(), pinned_artifacts=raw)
    assert front._load_receipt(root, '61' * 16)['phase'] == 'reloading'
    fresh = finite.HostAdapter(root, engine, value, profile, runner=runner)
    with fresh.lease():
        for action in (
            lambda: fresh.retire_application(owner='whatsapp', operation_id='62' * 16),
            lambda: fresh.retire_renewals(owner='whatsapp', operation_id='63' * 16),
            lambda: finite.apply_configuration(fresh, operation_id='64' * 16, before=empty(), pinned_artifacts=raw),
            lambda: fresh.legacy_post(value['legacy_hooks']['post']),
        ):
            with pytest.raises((front.FrontendError, finite.provider.FrontendError), match='durable frontend operation'):
                action()
        assert root.snapshot(value['consumers']['whatsapp.owner']['vhosts'][0]) is not None
        assert front._load_receipt(root, '62' * 16) is None
        runner.run = ordinary
        resumed = finite.apply_configuration(fresh, operation_id='61' * 16, before=empty(), pinned_artifacts=raw)
        assert resumed['phase'] == 'complete'
        assert fresh.retire_application(owner='whatsapp', operation_id='62' * 16)['phase'] == 'complete'


def test_renewal_operation_identity_survives_unrelated_consumer_registry_change(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    for item in profile['lineages'].values():
        selected = root.base / item['renewal']['path'].lstrip('/')
        selected.parent.mkdir(parents=True, exist_ok=True); selected.write_bytes(b'renewal fixture\n'); selected.chmod(0o600)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='71' * 16, before=empty(), pinned_artifacts=raw)
        adapter.retire_application(owner='box', operation_id='72' * 16)
        first = adapter.retire_renewals(owner='box', operation_id='73' * 16)
        adapter.retire_application(owner='whatsapp', operation_id='74' * 16)
        repeated = adapter.retire_renewals(owner='box', operation_id='73' * 16)
    assert first == repeated and first['phase'] == 'complete'
    assert set(first['selected']) == {'/etc/letsencrypt/renewal/web.example.test.conf'}
    assert root.snapshot('/etc/letsencrypt/renewal/owner.example.test.conf') is not None


@pytest.mark.parametrize('content', [b'{"phase":"complete"}', b'{"phase":"prepared","phase":"complete"}', b'not json'])
def test_unknown_or_malformed_receipt_blocks_admission_before_effects(registry, root, content):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    folder = root.base / (front.STATE + '/operations').lstrip('/')
    folder.mkdir(mode=0o700)
    selected = folder / ('f' * 32 + '.json'); selected.write_bytes(content); selected.chmod(0o600)
    with adapter.lease(), pytest.raises(ValueError):
        finite.apply_configuration(adapter, operation_id='81' * 16, before=empty(), pinned_artifacts=raw)
    assert root.snapshot('/etc/apache2/apache2.conf') is None and runner.calls == []


@pytest.mark.parametrize('tamper', ['unknown', 'bytes', 'journal'])
def test_receipt_quarantine_requires_exact_engine_provenance(registry, root, tamper):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='91' * 16, before=empty(), pinned_artifacts=raw)
        folder = root.base / (front.STATE + '/operations').lstrip('/')
        if tamper == 'unknown':
            artifact = folder / ('.lifecycle-' + 'f' * 32 + '-0.quarantine')
            artifact.write_bytes(b'forged'); artifact.chmod(0o600)
        else:
            artifact = next(folder.glob('.lifecycle-*.quarantine'))
            if tamper == 'bytes': artifact.write_bytes(b'corrupted')
            else:
                engine_id = artifact.name.split('-')[1]
                journal = root.base / ('var/lib/develative-host-lifecycle/host/operations/' + engine_id + '/journal.json')
                journal.write_bytes(b'{}')
        count = len(runner.calls)
        with pytest.raises(ValueError):
            adapter.retire_application(owner='box', operation_id='92' * 16)
        assert len(runner.calls) == count
        assert root.snapshot(value['consumers']['box.web']['vhosts'][0]) is not None


def test_interrupted_receipt_publication_admits_only_original_operation(registry, root, monkeypatch):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    real = engine.reconcile
    interrupted = False
    def reconcile(*args, **kwargs):
        nonlocal interrupted
        paths = list(kwargs['after']['files'])
        if len(paths) == 1 and paths[0].startswith(front.STATE + '/operations/'):
            record = json.loads(kwargs['payloads'][paths[0]])
            if record['phase'] == 'files_committed' and not interrupted:
                def fault(event, details):
                    nonlocal interrupted
                    if event == 'quarantined-file':
                        interrupted = True
                        raise RuntimeError('synthetic receipt writer died')
                kwargs['fault'] = fault
        return real(*args, **kwargs)
    monkeypatch.setattr(engine, 'reconcile', reconcile)
    with adapter.lease():
        with pytest.raises(RuntimeError, match='writer died'):
            finite.apply_configuration(adapter, operation_id='93' * 16, before=empty(), pinned_artifacts=raw)
        assert interrupted
        with pytest.raises(finite.provider.FrontendError, match='durable frontend operation'):
            adapter.retire_application(owner='box', operation_id='94' * 16)
        result = finite.apply_configuration(adapter, operation_id='93' * 16, before=empty(), pinned_artifacts=raw)
        assert result['phase'] == 'complete'
        assert adapter.retire_application(owner='box', operation_id='94' * 16)['phase'] == 'complete'




@pytest.mark.parametrize('interleaving', ['other-retirement', 'survivor-register'])
def test_completed_retirement_reobserves_survivor_without_rewinding_original_receipt(registry, root, interleaving):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='a1' * 16, before=empty(), pinned_artifacts=raw)
        original = adapter.retire_application(owner='box', operation_id='a2' * 16)
        receipt_bytes = root.read_bytes(front.STATE + '/operations/' + 'a2' * 16 + '.json')
        if interleaving == 'other-retirement':
            adapter.retire_application(owner='whatsapp', operation_id='a3' * 16)
        else:
            before = front.managed_manifest(adapter.registry)
            before['files'][front.REGISTRY].update(uid=root.uid, gid=root.gid)
            before['files'][finite.PROFILE] = {**root.snapshot(finite.PROFILE), 'retention': 'managed'}
            new = copy.deepcopy(adapter.registry)
            # A new pending tenant may share an explicitly registered HTTP vhost
            # of its same application; no certificate or listener is invented.
            new['consumers']['whatsapp.pending'] = {'owner': 'whatsapp', 'status': 'pending_tls',
                'domains': ['pending.example.test'], 'vhosts': [new['consumers']['whatsapp.owner']['vhosts'][0]], 'lineages': []}
            current_raw = {name: root.read_bytes(name) for name in front.managed_manifest(new)['files'] if name != front.REGISTRY}
            other = finite.HostAdapter(root, engine, new, profile, runner=runner)
            # The lease remains the same open descriptor; this is the finite
            # operation body, not a competing nested lock acquisition.
            other.locked, other.lock_fd = True, adapter.lock_fd
            finite.apply_configuration(other, operation_id='a3' * 16, before=before, pinned_artifacts=current_raw)
            adapter.registry = new
        calls = len(runner.calls)
        replay = adapter.retire_application(owner='box', operation_id='a2' * 16)
        assert root.read_bytes(front.STATE + '/operations/' + 'a2' * 16 + '.json') == receipt_bytes
        assert replay['after'] == original['after'] and replay['context'] == original['context']
        assert replay['current_configuration_sha256'] != original['current_configuration_sha256']
        assert replay['retirement']['registry_sha256'] == front.digest(front.encoded(adapter.registry))
        assert len(runner.calls) == calls + 1 and '-t' in runner.calls[-1]
        assert root.snapshot(value['consumers']['host.sally']['vhosts'][0]) is not None


def test_completed_retirement_rejects_changed_same_owner_records(registry, root):
    value, raw, profile, runner, adapter = staged_setup(registry, root)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='b1' * 16, before=empty(), pinned_artifacts=raw)
        adapter.retire_application(owner='box', operation_id='b2' * 16)
        changed = copy.deepcopy(adapter.registry)
        changed['consumers']['box.new'] = {'owner': 'box', 'status': 'retired',
            'domains': ['new.example.test'], 'vhosts': changed['consumers']['box.web']['vhosts'], 'lineages': []}
        target = root.base / front.REGISTRY.lstrip('/')
        target.write_bytes(front.encoded(changed)); adapter.registry = changed
        calls = len(runner.calls)
        with pytest.raises(finite.provider.FrontendError, match='different application records'):
            adapter.retire_application(owner='box', operation_id='b2' * 16)
        assert len(runner.calls) == calls

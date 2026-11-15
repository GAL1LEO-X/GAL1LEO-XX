"""Configuration bindings use real receipt/files and a synthetic foreign DSO.

The binary is never loaded: this suite proves hash/configuration semantics only.
"""
import types

import pytest
from test_host_qos_applicator import case, qos


@pytest.fixture
def frontend(case, monkeypatch):
    root, base, policy, kernel, accounts, _ = case
    binary = b'foreign-binary-fixture'.ljust(16136, b'\0')
    monkeypatch.setattr(qos, 'MODULE_SHA256', qos.sha(binary))
    policy['foreign_module']['sha256'] = qos.sha(binary)
    raw = qos.canonical(policy); (base / qos.POLICY.lstrip('/')).write_bytes(raw)
    def lookup(name):
        item = accounts[name]
        return types.SimpleNamespace(pw_name=name, pw_uid=item['uid'], pw_gid=item['gid'], pw_dir=item['home'], pw_shell=item['shell'])
    common = dict(policy_path=qos.POLICY, expected_sha256=qos.sha(raw), kernel_factory=kernel.factory,
                  lookup=lookup, census=lambda: [lookup(name) for name in accounts])
    qos.operate(root, action='apply', operation_id='a' * 32, **common)
    prefix = '/etc/develative-host-frontend/'
    loader = '/etc/apache2/mods-available/host-priority.load'
    http, tls = '/etc/apache2/sites-available/wa.conf', '/etc/apache2/sites-available/wa-tls.conf'
    consumer = {'owner': 'whatsapp', 'status': 'active', 'domains': ['wa.example.test'], 'vhosts': [http, tls]}
    registry = {'format': 1, 'provider': 'develative-host-frontend', 'owner': 'host',
                'apache': {'unit': 'apache2.service'}, 'consumers': {'whatsapp.personal': consumer}}
    profile = {'modules': [{'identifier': 'box_priority_module', 'path': qos.MODULE_DESTINATION,
                           'file': loader, 'line': 1, 'text': 'LoadModule box_priority_module ' + qos.MODULE_DESTINATION}]}
    payloads = {prefix + 'registry.json': qos.canonical(registry), prefix + 'profile.json': qos.canonical(profile),
        qos.MODULE_DESTINATION: binary, loader: (profile['modules'][0]['text'] + '\n').encode(),
        http: b'<VirtualHost *:80>\nServerName wa.example.test\n</VirtualHost>\n',
        tls: b'<VirtualHost *:443>\nServerName wa.example.test\nBoxPriorityDSCP 34\n</VirtualHost>\n'}
    def publish(identifier='e' * 32, before=None):
        after = qos.adoption.manifest()
        for name, content in payloads.items():
            path = base / name.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content); path.chmod(0o644)
            after['files'][name] = {**root.snapshot(name), 'retention': 'managed'}
        receipt = {'format': 1, 'operation_id': identifier, 'phase': 'complete', 'before': before or qos.adoption.manifest(),
            'after': after, 'allowed_paths': sorted(payloads), 'context': {'kind': 'configuration'}}
        receipt['plan_sha256'] = qos.sha(qos.canonical({key: receipt[key] for key in ('before', 'after', 'allowed_paths', 'context')}))
        path = base / ('var/lib/develative-host-frontend/operations/' + identifier + '.json')
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(qos.canonical(receipt)); path.chmod(0o600)
        lock = base / 'var/lib/develative-host-frontend/operation.lock'; lock.touch(mode=0o600)
        return identifier, qos.sha(path.read_bytes()), after
    def bind(operation='f' * 32, receipt=None, **extra):
        identifier, digest, _ = receipt or published
        return qos.register_frontend(root, operation_id=operation, consumer_id='whatsapp.personal',
            frontend_operation_id=identifier, frontend_receipt_sha256=digest, **common, **extra)
    published = publish()
    return root, base, payloads, registry, publish, bind, published


def test_tls_binding_preserves_unmarked_http_and_never_claims_traffic_verification(frontend):
    root, _, _, _, _, bind, receipt = frontend
    result = bind()
    assert result['status'] == 'configuration-bound' and result['runtime_verified'] is False
    assert result['receipt_sha256'] == receipt[1]
    item = qos.read_control(root, qos.FRONTENDS)['bindings']['whatsapp.personal']
    assert len(item['vhosts']) == 2 and item['proof_scope'] == 'configuration-and-reload-command-return-only'


@pytest.mark.parametrize('change', ['unmarked-tls', 'other-mark', 'module'])
def test_binding_rejects_changed_directive_or_module_before_registry_publication(frontend, change):
    root, base, payloads, _, publish, bind, _ = frontend
    tls = '/etc/apache2/sites-available/wa-tls.conf'
    if change == 'unmarked-tls': payloads[tls] = payloads[tls].replace(b'BoxPriorityDSCP 34\n', b'')
    elif change == 'other-mark': payloads[tls] = payloads[tls].replace(b'34', b'48')
    else: payloads[qos.MODULE_DESTINATION] += b'x'
    with pytest.raises(qos.QoSError): bind(receipt=publish())
    assert root.snapshot(qos.FRONTENDS) is None


@pytest.mark.parametrize('phase', ['frontend-prepared', 'frontend-registry'])
def test_binding_resumes_each_publication_phase(frontend, phase):
    _, _, _, _, _, bind, _ = frontend
    def crash(event, detail):
        if event == phase: raise RuntimeError('lost process')
    with pytest.raises(RuntimeError): bind(fault=crash)
    assert bind()['status'] == 'configuration-bound'


def test_new_receipt_explicitly_adopts_previous_binding_and_replay_ignores_unrelated_consumers(frontend):
    root, base, payloads, registry, publish, bind, original = frontend
    bind()
    payloads['/etc/apache2/sites-available/wa-tls.conf'] += b'# approved next configuration\n'
    upgrade = publish('d' * 32, before=original[2])
    assert bind('c' * 32, receipt=upgrade)['receipt_sha256'] == upgrade[1]
    registry['consumers']['box.other'] = {'owner': 'box', 'status': 'active', 'domains': ['other.example.test'], 'vhosts': []}
    path = base / 'etc/develative-host-frontend/registry.json'; path.write_bytes(qos.canonical(registry))
    assert bind('c' * 32, receipt=upgrade)['status'] == 'configuration-bound'
    with pytest.raises(qos.QoSError): bind()  # The original target really changed.


def test_new_receipt_without_previous_preimage_cannot_replace_a_binding(frontend):
    root, _, _, _, publish, bind, _ = frontend
    bind(); before = root.read_bytes(qos.FRONTENDS)
    with pytest.raises(qos.QoSError, match='adopt'): bind('c' * 32, receipt=publish('d' * 32))
    assert root.read_bytes(qos.FRONTENDS) == before

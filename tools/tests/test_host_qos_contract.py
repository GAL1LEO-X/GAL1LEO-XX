"""Neutral QoS plans on synthetic documents: never invoke tc/nft/systemd."""
import copy
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('host_qos_contract', ROOT / 'host/qos/contract.py')
qos = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qos)


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def profile():
    return {'kind': 'ets', 'handle': 'b040:', 'bands': 3, 'strict': 1,
            'quanta': [9000, 3000], 'priomap': [2] * 16,
            'af41_class': 'b040:2', 'cs6_class': 'b040:1',
            'af41_dscp': 34, 'cs6_dscp': 48, 'ecn_mask': 252,
            'families': ['ipv4', 'ipv6']}


def rebind(manifest, artifacts):
    evidence = {'format': 1, 'complete': True, 'reviewed_sections': sorted(qos.SECTIONS)}
    evidence.update({name + '_sha256': qos.digest(artifacts[name]) for name in
                     ('source', 'parameters', 'observation')})
    artifacts['attestation'] = encoded(evidence)
    refs = {name: {'file': name + ('.py' if name == 'source' else '.json'), 'sha256': qos.digest(data)}
            for name, data in artifacts.items()}
    manifest['policy'] = {'generation': qos.digest(qos.canonical(refs)), 'artifacts': refs}
    return manifest, artifacts


@pytest.fixture
def bundle():
    manifest = json.loads((ROOT / 'host/qos/manifest.example.json').read_text())
    consumers = {
        'box.frontend': {'owner': 'box', 'required_class': 'AF41', 'binding_id': 'box-proxy', 'status': 'active'},
        'whatsapp.frontend': {'owner': 'whatsapp', 'required_class': 'AF41', 'binding_id': 'wa-proxy', 'status': 'active'},
        'host.essential': {'owner': 'host', 'required_class': 'CS6', 'binding_id': 'essential', 'status': 'active'},
    }
    bindings = {}
    for index, (name, item) in enumerate(consumers.items()):
        bindings[item['binding_id']] = {'consumer': name, 'owner': item['owner'],
            'required_class': item['required_class'], 'mechanism': 'uid',
            'identity': {'uid': 2300 + index, 'account': 'synthetic-' + str(index),
                         'unit': 'synthetic-' + str(index) + '.service'}, 'evidence_sha256': 'a' * 64}
    bindings['essential'].update(mechanism='host-essential', identity={'policy_section': 'essential_services'})
    manifest['consumers'] = consumers
    observation = {'format': 1, 'interface': 'synthetic0', 'profile': profile(),
                   'sections': {name: {'synthetic': name} for name in qos.SECTIONS}, 'bindings': bindings}
    artifacts = {'source': b'raise AssertionError("Never execute this synthetic policy source")\n',
                 'parameters': encoded({'format': 1, 'interface': 'synthetic0',
                                        'configuration': {'synthetic': True, 'profile': profile()}}),
                 'observation': encoded(observation)}
    return rebind(manifest, artifacts)


def test_missing_live_policy_is_explicitly_blocked_and_example_never_invents_parameters():
    manifest = json.loads((ROOT / 'host/qos/manifest.example.json').read_text())
    result = qos.plan(manifest, {}, 'inspect')
    assert result['status'] == 'blocked' and result['next_manifest'] is None
    assert result['commands'] == result['host_changes'] == result['binding_changes'] == []
    assert result['host_policy_action'] == 'retain' and not result['apply_supported']
    with pytest.raises(qos.ContractError, match='Policy is missing'):
        qos.equivalent_managed(manifest, copy.deepcopy(manifest))


@pytest.mark.parametrize('retired,remaining', [('box.frontend', 'whatsapp.frontend'),
                                             ('whatsapp.frontend', 'box.frontend')])
def test_retirement_preserves_other_product_and_host_policy(bundle, retired, remaining):
    manifest, artifacts = bundle
    original = copy.deepcopy(manifest)
    result = qos.plan(manifest, artifacts, 'retire-consumer', consumer_id=retired)
    after = result['next_manifest']
    assert manifest == original  # pure preview, even the input is unchanged
    assert after['policy'] == original['policy']
    assert after['consumers'][remaining] == original['consumers'][remaining]
    assert after['consumers']['host.essential'] == original['consumers']['host.essential']
    assert after['consumers'][retired]['status'] == 'retired'
    assert result['binding_changes'] == [{'action': 'withdraw', 'consumer': retired,
                                         'binding_id': original['consumers'][retired]['binding_id']}]
    assert result['commands'] == result['host_changes'] == [] and not result['mutated']
    repeated = qos.plan(after, artifacts, 'retire-consumer', consumer_id=retired)
    assert not repeated['changed'] and repeated['binding_changes'] == []


def test_last_application_retirement_never_resets_qdisc_or_removes_host_policy(bundle):
    manifest, artifacts = bundle
    for name in ('box.frontend', 'whatsapp.frontend'):
        manifest = qos.plan(manifest, artifacts, 'retire-consumer', consumer_id=name)['next_manifest']
    result = qos.plan(manifest, artifacts, 'inspect')
    assert result['remaining_consumers'] == ['host.essential']
    assert result['host_policy_action'] == 'retain'
    with pytest.raises(qos.ContractError, match='host essential'):
        qos.plan(manifest, artifacts, 'retire-consumer', consumer_id='host.essential')


def test_consumer_registration_requires_exact_attested_binding_and_is_idempotent(bundle):
    manifest, artifacts = bundle
    item = manifest['consumers'].pop('whatsapp.frontend')
    plan = qos.plan(manifest, artifacts, 'register-consumer', consumer_id='whatsapp.frontend', requested=item)
    assert plan['changed'] and plan['next_manifest']['consumers']['whatsapp.frontend'] == item
    again = qos.plan(plan['next_manifest'], artifacts, 'register-consumer', consumer_id='whatsapp.frontend', requested=item)
    assert not again['changed'] and again['binding_changes'] == []
    with pytest.raises(qos.ContractError, match='exact attested'):
        qos.plan(manifest, artifacts, 'register-consumer', consumer_id='whatsapp.other', requested=item)


@pytest.mark.parametrize('fault', ['stale-plan', 'wrong-owner', 'class-escalation', 'unknown-retire', 'reactivate'])
def test_registry_ownership_and_stale_handoff_are_rejected(bundle, fault):
    manifest, artifacts = bundle
    item = copy.deepcopy(manifest['consumers']['whatsapp.frontend'])
    with pytest.raises(qos.ContractError):
        if fault == 'stale-plan':
            qos.plan(manifest, artifacts, 'inspect', expected_digest='0' * 64)
        elif fault == 'unknown-retire':
            qos.plan(manifest, artifacts, 'retire-consumer', consumer_id='whatsapp.missing')
        else:
            if fault == 'wrong-owner': item['owner'] = 'box'
            elif fault == 'class-escalation': item['required_class'] = 'CS6'
            else: manifest['consumers']['whatsapp.frontend']['status'] = 'retired'
            qos.plan(manifest, artifacts, 'register-consumer', consumer_id='whatsapp.frontend', requested=item)


@pytest.mark.parametrize('fault', ['two-classes', 'no-cs6', 'lost-leaves', 'different-interface', 'changed-source', 'missing-attestation'])
def test_incomplete_or_different_policy_never_produces_actionable_plan(bundle, fault):
    manifest, artifacts = bundle
    observed = json.loads(artifacts['observation'])
    if fault == 'two-classes': observed['profile']['bands'] = 2
    elif fault == 'no-cs6': observed['profile']['cs6_class'] = None
    elif fault == 'lost-leaves': observed['sections']['leaf_qdiscs'] = []
    elif fault == 'different-interface': observed['interface'] = 'other0'
    if fault in ('two-classes', 'no-cs6', 'lost-leaves', 'different-interface'):
        artifacts['observation'] = encoded(observed)
        rebind(manifest, artifacts)  # even a matching digest cannot change the preservation contract
    elif fault == 'changed-source': artifacts['source'] += b'# different\n'
    else: artifacts.pop('attestation')
    result = qos.plan(manifest, artifacts, 'retire-consumer', consumer_id='whatsapp.frontend')
    assert result['status'] == 'blocked' and result['next_manifest'] is None
    assert result['binding_changes'] == result['commands'] == result['host_changes'] == []


@pytest.mark.parametrize('invalid', ['0.0.0.0', '::ffff:192.0.2.25', 'fe80::25%eth0', 'ff02::1'])
def test_frontend_binding_needs_explicit_nonwildcard_listener_and_identity(bundle, invalid):
    manifest, artifacts = bundle
    observation = json.loads(artifacts['observation'])
    binding = observation['bindings']['wa-proxy']
    binding.update(mechanism='frontend-socket', identity={
        'unit': 'whatsapp-frontend.service', 'worker_user': 'synthetic-wa',
        'listen_addresses': ['192.0.2.25', '2001:db8::25'], 'port': 443, 'protocol': 'tcp'})
    artifacts['observation'] = encoded(observation); rebind(manifest, artifacts)
    assert qos.plan(manifest, artifacts, 'inspect')['status'] == 'planned'
    binding['identity']['listen_addresses'] = [invalid]
    artifacts['observation'] = encoded(observation); rebind(manifest, artifacts)
    assert qos.plan(manifest, artifacts, 'inspect')['status'] == 'blocked'


@pytest.mark.parametrize('name', ['whatsapp-frontend.service', 'box-frontend.service', 'whatsapp@owner.service'])
def test_realistic_unit_names_are_accepted_without_literal_backslash(name):
    qos._binding_identity({'mechanism': 'uid', 'identity': {
        'uid': 2300, 'account': 'synthetic-wa', 'unit': name}})
    for invalid in (name.replace('.service', 'Xservice'), name.replace('.service', r'\.service')):
        with pytest.raises(qos.ContractError):
            qos._binding_identity({'mechanism': 'uid', 'identity': {
                'uid': 2300, 'account': 'synthetic-wa', 'unit': invalid}})


def test_quanta_and_priomap_are_supplied_evidence_not_guessed_defaults(bundle):
    manifest, artifacts = bundle
    observation = json.loads(artifacts['observation'])
    parameters = json.loads(artifacts['parameters'])
    observation['profile']['quanta'] = [8192, 4096]
    observation['profile']['priomap'] = [0, 1, 2, 2] * 4
    artifacts['observation'] = encoded(observation)
    rebind(manifest, artifacts)
    assert qos.plan(manifest, artifacts, 'inspect')['status'] == 'blocked'
    parameters['configuration']['profile'] = copy.deepcopy(observation['profile'])
    artifacts['parameters'] = encoded(parameters)
    rebind(manifest, artifacts)
    assert qos.plan(manifest, artifacts, 'inspect')['status'] == 'planned'
    for field in ('quanta', 'priomap'):
        missing = copy.deepcopy(observation)
        del missing['profile'][field]
        artifacts['observation'] = encoded(missing)
        rebind(manifest, artifacts)
        assert qos.plan(manifest, artifacts, 'inspect')['status'] == 'blocked'


def test_fresh_and_upgraded_managed_manifest_must_converge_exactly(bundle):
    fresh, _ = bundle
    upgraded = json.loads(encoded(fresh))
    assert qos.equivalent_managed(fresh, upgraded) == qos.digest(qos.canonical(fresh))
    upgraded['consumers']['whatsapp.frontend']['status'] = 'retired'
    with pytest.raises(qos.ContractError, match='differ'):
        qos.equivalent_managed(fresh, upgraded)
    upgraded = copy.deepcopy(fresh); upgraded['sessions'] = {'ignored': 'not allowed'}
    with pytest.raises(qos.ContractError): qos.equivalent_managed(fresh, upgraded)


def test_manifest_rejects_traversal_duplicate_artifacts_and_generation_tampering(bundle):
    manifest, _ = bundle
    for fault in ('traversal', 'duplicate', 'generation'):
        changed = copy.deepcopy(manifest)
        if fault == 'traversal': changed['policy']['artifacts']['source']['file'] = '../box/policy.py'
        elif fault == 'duplicate': changed['policy']['artifacts']['source']['file'] = 'observation.json'
        else: changed['policy']['generation'] = 'a' * 64
        with pytest.raises(qos.ContractError): qos.validate_manifest(changed)


def test_json_has_no_duplicate_keys_or_nonfinite_values():
    for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'{"x":-1e999}'):
        with pytest.raises(qos.ContractError): qos.decode(data)


@pytest.mark.parametrize('mechanism', ['uid', 'frontend-socket'])
def test_overlapping_selectors_cannot_plan_independent_retirement(bundle, mechanism):
    manifest, artifacts = bundle
    observation = json.loads(artifacts['observation'])
    for index, binding_id in enumerate(('box-proxy', 'wa-proxy')):
        binding = observation['bindings'][binding_id]
        binding['mechanism'] = mechanism
        if mechanism == 'uid':
            # Different account/unit labels do not make a numeric UID distinct.
            binding['identity']['uid'] = 2300
        else:
            binding['identity'] = {'unit': f'synthetic-{index}.service',
                'worker_user': f'synthetic-{index}', 'port': 443, 'protocol': 'tcp',
                'listen_addresses': ['2001:db8::25'] if index == 0 else ['2001:db8:0:0::25', '192.0.2.25']}
    artifacts['observation'] = encoded(observation)
    rebind(manifest, artifacts)
    result = qos.plan(manifest, artifacts, 'retire-consumer', consumer_id='box.frontend')
    assert result['status'] == 'blocked' and result['next_manifest'] is None
    assert result['binding_changes'] == [] and 'Overlapping' in result['blockers'][0]


@pytest.mark.parametrize('owner,mode', [(1000, 0o100640), (0, 0o100666), (0, 0o120777)])
def test_administrative_paths_require_root_no_write_and_no_symlink(monkeypatch, owner, mode):
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(st_uid=owner, st_mode=mode))
    with pytest.raises(qos.ContractError, match='root-owned'):
        qos._administrative(Path('/synthetic/host/manifest.json'))


def test_component_lifecycle_is_host_owned_outside_app_distribution():
    component = json.loads((ROOT / 'host/qos/component.json').read_text())
    assert component['owner'] == 'host' and component['application_lifecycle'] == 'retain'
    assert component['source'] == 'host/qos' and component['execution'] == 'finite-host-apply-with-explicit-admission'
    text = (ROOT / 'host/qos/contract.py').read_text()
    assert 'import subprocess' not in text
    assert 'plugins.whatsapp' not in text and 'github_release' not in text


def shared_vhosts(bundle):
    manifest, artifacts = bundle
    observation = json.loads(artifacts['observation'])
    observation['shared_listeners'] = {'host.https': {'owner': 'host', 'unit': 'apache2.service',
        'worker_user': 'www-data', 'listen_addresses': ['0.0.0.0', '::'], 'port': 443, 'protocol': 'tcp'}}
    for name, binding_id in (('box', 'box-proxy'), ('whatsapp', 'wa-proxy')):
        observation['bindings'][binding_id].update(mechanism='frontend-vhost', identity={
            'unit': 'apache2.service', 'worker_user': 'www-data', 'shared_listener_binding': 'host.https',
            'server_names': [name + '.example.test'], 'vhost_file': '/etc/apache2/sites-available/' + name + '.conf',
            'vhost_sha256': '1' * 64, 'module_file': '/usr/local/lib/box-network-priority/v1/mod_box_priority.so',
            'module_sha256': '2' * 64, 'directive': {'name': 'BoxPriorityDSCP', 'value': 34}})
    artifacts['observation'] = encoded(observation)
    return rebind(manifest, artifacts)


def test_distinct_vhosts_share_host_listener_and_retirement_keeps_other_binding(bundle):
    manifest, artifacts = shared_vhosts(bundle)
    observation = json.loads(artifacts['observation'])
    assert qos.plan(manifest, artifacts, 'inspect')['status'] == 'planned'
    result = qos.plan(manifest, artifacts, 'retire-consumer', consumer_id='whatsapp.frontend')
    assert result['status'] == 'planned'
    assert result['binding_changes'] == [{'action': 'withdraw', 'consumer': 'whatsapp.frontend', 'binding_id': 'wa-proxy'}]
    assert result['next_manifest']['consumers']['box.frontend'] == manifest['consumers']['box.frontend']
    assert result['next_manifest']['policy'] == manifest['policy']
    assert qos.verify_policy(result['next_manifest'], artifacts)['shared_listeners'] == observation['shared_listeners']
    assert not result['apply_supported']  # File/module hashes still need actual applicator preflight.


@pytest.mark.parametrize('change', ['duplicate-name', 'listener-owner', 'missing-listener', 'unit', 'module-hash',
                                  'module-traversal', 'vhost-path', 'directive', 'wildcard-name', 'alias-listener'])
def test_shared_frontend_binding_requires_exact_owned_listener_and_pinned_vhost(bundle, change):
    manifest, artifacts = shared_vhosts(bundle)
    observation = json.loads(artifacts['observation'])
    identity = observation['bindings']['wa-proxy']['identity']
    if change == 'duplicate-name': identity['server_names'] = ['box.example.test']
    elif change == 'listener-owner': observation['shared_listeners']['host.https']['owner'] = 'box'
    elif change == 'missing-listener': identity['shared_listener_binding'] = 'host.missing'
    elif change == 'unit': identity['unit'] = 'other.service'
    elif change == 'module-hash': identity['module_sha256'] = 'unverified'
    elif change == 'module-traversal': identity['module_file'] = '/usr/lib/apache2/modules/../other.so'
    elif change == 'vhost-path': identity['vhost_file'] = '/tmp/synthetic.conf'
    elif change == 'directive': identity['directive']['value'] = 48
    elif change == 'wildcard-name': identity['server_names'] = ['*.example.test']
    else: observation['shared_listeners']['host.alias'] = copy.deepcopy(observation['shared_listeners']['host.https'])
    artifacts['observation'] = encoded(observation)
    manifest, artifacts = rebind(manifest, artifacts)
    assert qos.plan(manifest, artifacts, 'inspect')['status'] == 'blocked'


def test_shared_host_socket_cannot_also_be_owned_by_an_application(bundle):
    manifest, artifacts = shared_vhosts(bundle)
    observation = json.loads(artifacts['observation'])
    observation['bindings']['wa-proxy'].update(mechanism='frontend-socket', identity={
        'unit': 'other.service', 'worker_user': 'other', 'listen_addresses': ['192.0.2.12'], 'port': 443, 'protocol': 'tcp'})
    artifacts['observation'] = encoded(observation)
    manifest, artifacts = rebind(manifest, artifacts)
    result = qos.plan(manifest, artifacts, 'inspect')
    assert result['status'] == 'blocked' and 'host-owned shared listener' in result['blockers'][0]

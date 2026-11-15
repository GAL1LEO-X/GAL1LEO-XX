"""Host-owned QoS contract and read-only planner. No network or apply commands.

The policy is supplied as an attested, digest-bound bundle. This module never
reconstructs the live policy from a legacy application installer or an example.
Application retirement always retains the shared policy, including the last
consumer. Host decommissioning is a separate operation, not implemented here.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat

PROVIDER = 'develative-host-qos'
VERSION = '0.1.0'
ROLES = {'source', 'parameters', 'observation', 'attestation'}
SECTIONS = {'root_qdisc', 'leaf_qdiscs', 'classifiers', 'marking', 'essential_services'}
MAX_BYTES = 1024 * 1024


class ContractError(ValueError):
    """A safe contract rejection, without echoing input contents."""


def require(value, message):
    if not value:
        raise ContractError(message)


def keys(value, expected, message):
    require(isinstance(value, dict) and set(value) == set(expected), message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def hexadecimal(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def identifier(value):
    return isinstance(value, str) and re.fullmatch('[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*', value) is not None and len(value) <= 96


def decode(data):
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_BYTES, 'Invalid JSON size')
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, 'Duplicate JSON key')
            result[name] = value
        return result
    def invalid_constant(_):
        raise ContractError('Non-finite JSON value')
    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), 'Non-finite JSON value')
        return number
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant,
                          parse_float=finite_float)
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError('Invalid JSON document') from None


def consumer(value, consumer_id):
    keys(value, {'owner', 'required_class', 'binding_id', 'status'}, 'Invalid consumer record')
    require(identifier(consumer_id) and value['owner'] in ('box', 'whatsapp', 'host')
            and consumer_id.startswith(value['owner'] + '.'), 'Consumer namespace differs from owner')
    require(identifier(value['binding_id']), 'Invalid binding identity')
    require(value['required_class'] == ('CS6' if value['owner'] == 'host' else 'AF41'),
            'Consumer cannot change its priority class')
    require(value['status'] in ('active', 'retired'), 'Invalid consumer state')
    return value


def validate_manifest(value):
    keys(value, {'format', 'provider', 'owner', 'component_version', 'policy', 'consumers'},
         'Invalid host QoS manifest')
    require(type(value['format']) is int and value['format'] == 1
            and value['provider'] == PROVIDER and value['owner'] == 'host'
            and value['component_version'] == VERSION, 'Unsupported provider contract')
    require(isinstance(value['consumers'], dict) and len(value['consumers']) <= 256,
            'Invalid consumer registry')
    for consumer_id, item in value['consumers'].items():
        consumer(item, consumer_id)
    policy = value['policy']
    if policy is not None:
        keys(policy, {'generation', 'artifacts'}, 'Invalid policy reference')
        keys(policy['artifacts'], ROLES, 'The complete policy bundle is required')
        names = set()
        for artifact in policy['artifacts'].values():
            keys(artifact, {'file', 'sha256'}, 'Invalid policy artifact')
            require(isinstance(artifact['file'], str)
                    and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}', artifact['file'])
                    and artifact['file'] not in names and hexadecimal(artifact['sha256']),
                    'Policy artifact path or digest is invalid')
            names.add(artifact['file'])
        require(policy['generation'] == digest(canonical(policy['artifacts'])),
                'Policy generation differs from its immutable artifacts')
    return value


def _profile(value):
    """Minimum invariant; the full source and every policy section remain required."""
    expected = {'kind': 'ets', 'handle': 'b040:', 'bands': 3, 'strict': 1,
                'af41_class': 'b040:2', 'cs6_class': 'b040:1',
                'af41_dscp': 34, 'cs6_dscp': 48, 'ecn_mask': 252,
                'families': ['ipv4', 'ipv6']}
    keys(value, set(expected) | {'quanta', 'priomap'}, 'Incomplete three-class policy profile')
    require(canonical({key: value[key] for key in expected}) == canonical(expected),
            'Policy does not preserve the three-class AF41/CS6 contract')
    # Values are explicit evidence, never inferred from an older installer.
    require(isinstance(value['quanta'], list) and len(value['quanta']) == 2
            and all(type(item) is int and 0 < item < 2**32 for item in value['quanta']),
            'Two explicit positive DRR quanta are required')
    require(isinstance(value['priomap'], list) and len(value['priomap']) == 16
            and all(type(item) is int and 0 <= item < 3 for item in value['priomap']),
            'An explicit sixteen-priority mapping is required')


def _binding_identity(binding):
    value = binding['identity']
    unit = lambda name: isinstance(name, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,95}\.service', name)
    account = lambda name: isinstance(name, str) and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', name)
    if binding['mechanism'] == 'uid':
        keys(value, {'uid', 'account', 'unit'}, 'Invalid UID binding identity')
        require(type(value['uid']) is int and 0 < value['uid'] < 2**31
                and account(value['account']) and unit(value['unit']), 'UID binding requires an exact unprivileged account')
    elif binding['mechanism'] == 'frontend-socket':
        keys(value, {'unit', 'worker_user', 'listen_addresses', 'port', 'protocol'}, 'Invalid frontend binding identity')
        require(unit(value['unit']) and account(value['worker_user']) and value['protocol'] == 'tcp'
                and type(value['port']) is int and 1 <= value['port'] <= 65535
                and isinstance(value['listen_addresses'], list) and 0 < len(value['listen_addresses']) <= 16,
                'Frontend binding requires exact listener and worker identities')
        try:
            addresses = [ipaddress.ip_address(item) for item in value['listen_addresses']]
        except (TypeError, ValueError):
            raise ContractError('Frontend listener must be an explicit IP address') from None
        require(all(isinstance(item, str) for item in value['listen_addresses'])
                and all('%' not in item for item in value['listen_addresses'])
                and len(set(addresses)) == len(addresses)
                and all(not item.is_unspecified and not item.is_multicast
                        and not getattr(item, 'ipv4_mapped', None) for item in addresses),
                'Frontend listener cannot be wildcard, scoped, mapped, multicast or duplicated')
    elif binding['mechanism'] == 'frontend-vhost':
        keys(value, {'unit', 'worker_user', 'shared_listener_binding', 'server_names',
                     'vhost_file', 'vhost_sha256', 'module_file', 'module_sha256', 'directive'},
             'Invalid shared frontend vhost identity')
        require(unit(value['unit']) and account(value['worker_user'])
                and identifier(value['shared_listener_binding'])
                and isinstance(value['server_names'], list) and 0 < len(value['server_names']) <= 32,
                'Shared vhost requires an exact host listener and names')
        hostname = lambda name: isinstance(name, str) and len(name) <= 253 and re.fullmatch(
            r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', name)
        require(all(hostname(name) for name in value['server_names'])
                and len(set(value['server_names'])) == len(value['server_names']),
                'Shared vhost names must be exact unique lowercase hostnames')
        path, prefix = value['vhost_file'], '/etc/apache2/sites-available/'
        require(isinstance(path, str) and path.startswith(prefix) and path.endswith('.conf')
                and str(PurePosixPath(path)) == path and '..' not in PurePosixPath(path).parts
                and re.fullmatch('[a-zA-Z0-9_.-]+', path[len(prefix):]),
                'Shared vhost files must be exact administrative paths')
        module = value['module_file']
        require(module == '/usr/local/lib/box-network-priority/v1/mod_box_priority.so'
                or isinstance(module, str) and re.fullmatch(
                    r'/usr/local/lib/develative-host-qos/foreign/sha256-[0-9a-f]{64}/mod_box_priority\.so', module),
                'Foreign module requires its exact preserved or host-owned content-addressed path')
        if isinstance(module, str) and module.startswith('/usr/local/lib/develative-host-qos/foreign/'):
            require(module.split('/')[-2] == 'sha256-' + value['module_sha256'], 'Foreign module path differs from its digest')
        require(hexadecimal(value['vhost_sha256']) and hexadecimal(value['module_sha256'])
                and canonical(value['directive']) == canonical({'name': 'BoxPriorityDSCP', 'value': 34}),
                'Shared vhost requires pinned files and the explicit AF41 directive')
    else:
        require(binding['mechanism'] == 'host-essential' and binding['owner'] == 'host',
                'Host essential binding cannot belong to an application')
        keys(value, {'policy_section'}, 'Invalid essential binding identity')
        require(value['policy_section'] == 'essential_services', 'Wrong essential policy section')


def _selector_keys(binding):
    """Reject provable selector overlap; no implicit shared-selector lifecycle."""
    value = binding['identity']
    if binding['mechanism'] == 'uid':
        return {('uid', value['uid'])}
    if binding['mechanism'] == 'frontend-socket':
        return {('socket', str(ipaddress.ip_address(address)), value['port'], value['protocol'])
                for address in value['listen_addresses']}
    if binding['mechanism'] == 'frontend-vhost':
        return {('vhost', value['shared_listener_binding'], name) for name in value['server_names']}
    return {('host-essential', value['policy_section'])}


def _shared_listeners(value):
    """Sockets remain host-owned; applications own only their vhost bindings."""
    require(isinstance(value, dict) and len(value) <= 32, 'Invalid shared listener registry')
    seen = []
    for name, item in value.items():
        require(identifier(name), 'Invalid shared listener identity')
        keys(item, {'owner', 'unit', 'worker_user', 'listen_addresses', 'port', 'protocol'},
             'Invalid shared listener record')
        require(item['owner'] == 'host', 'Shared listeners must remain host-owned')
        # Reuse socket grammar while explicitly permitting an inventoried host
        # wildcard. No application binding gains ownership of that selector.
        addresses = item['listen_addresses']
        require(isinstance(addresses, list) and 0 < len(addresses) <= 16
                and all(isinstance(address, str) and '%' not in address for address in addresses),
                'Shared listeners require explicit addresses')
        try:
            parsed = [ipaddress.ip_address(address) for address in addresses]
        except ValueError:
            raise ContractError('Invalid shared listener address') from None
        require(len(set(parsed)) == len(parsed) and all(not address.is_multicast
                and not getattr(address, 'ipv4_mapped', None) for address in parsed),
                'Shared listener address is duplicated, mapped or multicast')
        require(isinstance(item['unit'], str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,95}\.service', item['unit'])
                and isinstance(item['worker_user'], str) and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', item['worker_user'])
                and item['protocol'] == 'tcp' and type(item['port']) is int and 1 <= item['port'] <= 65535,
                'Shared listener requires exact unit, worker and TCP port')
        for address in parsed:
            for previous, port, protocol in seen:
                require(not (port == item['port'] and protocol == item['protocol']
                             and address.version == previous.version
                             and (address == previous or address.is_unspecified or previous.is_unspecified)),
                        'Shared listener aliases overlap; declare one host binding')
            seen.append((address, item['port'], item['protocol']))
    return value


def verify_policy(manifest, artifacts):
    """Verify supplied evidence, without claiming observation of the live host."""
    validate_manifest(manifest)
    policy = manifest['policy']
    require(policy is not None, 'Attested live policy source and parameters are still required')
    require(isinstance(artifacts, dict) and set(artifacts) == ROLES, 'Policy artifact content is incomplete')
    for role, data in artifacts.items():
        require(isinstance(data, bytes) and 0 < len(data) <= MAX_BYTES
                and digest(data) == policy['artifacts'][role]['sha256'], 'Policy artifact digest differs')
    parameters, observation, attestation = (decode(artifacts[name]) for name in
                                           ('parameters', 'observation', 'attestation'))
    keys(parameters, {'format', 'interface', 'configuration'}, 'Invalid complete policy parameters')
    require(type(parameters['format']) is int and parameters['format'] == 1
            and isinstance(parameters['interface'], str)
            and re.fullmatch('[a-zA-Z0-9_.:-]{1,15}', parameters['interface'])
            and isinstance(parameters['configuration'], dict) and parameters['configuration'],
            'Complete effective policy parameters are required')
    require(isinstance(observation, dict) and set(observation) in (
        {'format', 'interface', 'profile', 'sections', 'bindings'},
        {'format', 'interface', 'profile', 'sections', 'bindings', 'shared_listeners'}),
        'Invalid policy observation')
    require(type(observation['format']) is int and observation['format'] == 1
            and observation['interface'] == parameters['interface'], 'Policy observation does not match its target')
    _profile(observation['profile'])
    require('profile' in parameters['configuration']
            and canonical(parameters['configuration']['profile']) == canonical(observation['profile']),
            'Observed profile differs from the explicitly supplied policy parameters')
    keys(observation['sections'], SECTIONS, 'Every effective policy section must be supplied')
    for item in observation['sections'].values():
        require(isinstance(item, (dict, list)) and item, 'An effective policy section is missing')
    require(isinstance(observation['bindings'], dict) and len(observation['bindings']) <= 256,
            'Invalid observed consumer bindings')
    shared_listeners = _shared_listeners(observation.get('shared_listeners', {}))
    selectors = set()
    for binding_id, binding in observation['bindings'].items():
        keys(binding, {'consumer', 'owner', 'required_class', 'mechanism', 'identity', 'evidence_sha256'},
             'Invalid observed binding')
        consumer({'owner': binding['owner'], 'required_class': binding['required_class'],
                  'binding_id': binding_id, 'status': 'active'}, binding['consumer'])
        require(binding['mechanism'] in ('uid', 'frontend-socket', 'frontend-vhost', 'host-essential')
                and isinstance(binding['identity'], dict) and binding['identity']
                and hexadecimal(binding['evidence_sha256']), 'Binding mechanism is not attested')
        _binding_identity(binding)
        if binding['mechanism'] == 'frontend-vhost':
            identity = binding['identity']
            shared = shared_listeners.get(identity['shared_listener_binding'])
            require(binding['owner'] in ('box', 'whatsapp') and binding['required_class'] == 'AF41'
                    and shared is not None and shared['unit'] == identity['unit']
                    and shared['worker_user'] == identity['worker_user'],
                    'Shared vhost is not bound to its exact host-owned listener')
        elif binding['mechanism'] == 'frontend-socket':
            identity = binding['identity']
            for shared in shared_listeners.values():
                if shared['port'] == identity['port'] and shared['protocol'] == identity['protocol']:
                    for address in map(ipaddress.ip_address, identity['listen_addresses']):
                        require(not any(address.version == other.version and (address == other or other.is_unspecified)
                                        for other in map(ipaddress.ip_address, shared['listen_addresses'])),
                                'Application socket overlaps a host-owned shared listener; use a vhost binding')
        selected = _selector_keys(binding)
        require(not selectors.intersection(selected),
                'Overlapping consumer selectors require an explicit shared-binding lifecycle')
        selectors.update(selected)
    keys(attestation, {'format', 'complete', 'source_sha256', 'parameters_sha256',
                      'observation_sha256', 'reviewed_sections'}, 'Invalid policy attestation')
    require(type(attestation['format']) is int and attestation['format'] == 1
            and attestation['complete'] is True
            and attestation['reviewed_sections'] == sorted(SECTIONS)
            and all(attestation[role + '_sha256'] == digest(artifacts[role])
                    for role in ('source', 'parameters', 'observation')),
            'Attestation is incomplete or belongs to a different policy')
    # An attestation is administrator-provided evidence, not a digital signature
    # or an excuse to execute the supplied source. The planner has no apply path.
    for consumer_id, item in manifest['consumers'].items():
        if item['status'] == 'active':
            _binding(observation, consumer_id, item)
    return observation


def _binding(observation, consumer_id, value):
    binding = observation['bindings'].get(value['binding_id'])
    require(binding is not None and binding['consumer'] == consumer_id
            and binding['owner'] == value['owner'] and binding['required_class'] == value['required_class'],
            'An exact attested consumer binding is required')


def plan(manifest, artifacts, action, *, consumer_id=None, requested=None, expected_digest=None):
    """Pure plan: no writes, subprocesses, qdisc resets, or privilege changes."""
    validate_manifest(manifest)
    before = digest(canonical(manifest))
    require(expected_digest is None or expected_digest == before, 'Manifest changed; regenerate the plan')
    require(action in ('inspect', 'register-consumer', 'retire-consumer'), 'Unsupported planning action')
    if action == 'inspect':
        require(consumer_id is None and requested is None, 'Inspection takes no consumer change')
    else:
        require(identifier(consumer_id), 'An exact consumer identity is required')
    if action == 'register-consumer':
        consumer(requested, consumer_id)
        require(requested['status'] == 'active', 'Register only an active consumer')
    else:
        require(requested is None, 'Unexpected consumer replacement')
    result = {'format': 1, 'provider': PROVIDER, 'action': action, 'based_on': before,
              'status': 'blocked', 'apply_supported': False, 'mutated': False,
              'host_policy_action': 'retain', 'host_changes': [], 'commands': [],
              'binding_changes': [], 'next_manifest': None, 'blockers': []}
    try:
        observation = verify_policy(manifest, artifacts)
    except ContractError as error:
        result['blockers'] = [str(error)]
        return result
    candidate = copy.deepcopy(manifest)
    if action == 'register-consumer':
        _binding(observation, consumer_id, requested)
        old = candidate['consumers'].get(consumer_id)
        require(old is None or old == requested, 'Existing consumer must not be replaced or silently reactivated')
        candidate['consumers'][consumer_id] = copy.deepcopy(requested)
        if old is None:
            result['binding_changes'] = [{'action': 'register', 'consumer': consumer_id,
                                          'binding_id': requested['binding_id']}]
    elif action == 'retire-consumer':
        require(consumer_id in candidate['consumers'], 'Unknown consumer; no wildcard retirement')
        require(candidate['consumers'][consumer_id]['owner'] != 'host',
                'Application retirement cannot remove the host essential policy')
        if candidate['consumers'][consumer_id]['status'] != 'retired':
            result['binding_changes'] = [{'action': 'withdraw', 'consumer': consumer_id,
                                          'binding_id': candidate['consumers'][consumer_id]['binding_id']}]
        candidate['consumers'][consumer_id]['status'] = 'retired'
    result.update(status='planned', next_manifest=candidate,
                  changed=canonical(candidate) != canonical(manifest),
                  remaining_consumers=sorted(name for name, item in candidate['consumers'].items()
                                             if item['status'] == 'active'))
    return result


def equivalent_managed(fresh, upgraded):
    """Strict convergence of managed state; no field is silently ignored.

    Data, sessions, operator secrets and inactive rollback archives belong
    outside this manifest. They cannot hide a difference in provider topology.
    """
    validate_manifest(fresh)
    validate_manifest(upgraded)
    require(fresh['policy'] is not None and upgraded['policy'] is not None,
            'Policy is missing; cannot certify managed topology convergence')
    require(canonical(fresh) == canonical(upgraded), 'Fresh and upgraded managed manifests differ')
    return digest(canonical(fresh))


def _administrative(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Host contract path must be root-owned, protected, and free of symlinks')


def protected_read(path):
    path = Path(path).absolute()
    _administrative(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022 and 0 < info.st_size <= MAX_BYTES,
                'Invalid protected contract file')
        data = stream.read(MAX_BYTES + 1)
        require(0 < len(data) <= MAX_BYTES, 'Contract file grew while reading')
        return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'register-consumer', 'retire-consumer', 'compare-managed'))
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--consumer-id')
    parser.add_argument('--consumer', type=Path)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--other-manifest', type=Path)
    args = parser.parse_args(argv)
    manifest = decode(protected_read(args.manifest))
    validate_manifest(manifest)
    if args.action == 'compare-managed':
        require(args.other_manifest is not None and args.bundle is None and args.consumer is None
                and args.consumer_id is None and args.expected_sha256 is None, 'Invalid comparison arguments')
        other = decode(protected_read(args.other_manifest))
        result = {'equivalent': True, 'managed_sha256': equivalent_managed(manifest, other), 'mutated': False}
    else:
        require(args.other_manifest is None, 'Unexpected comparison manifest')
        artifacts = {}
        if manifest['policy'] is not None:
            require(args.bundle is not None, 'The complete protected artifact directory is required')
            _administrative(args.bundle)
            artifacts = {role: protected_read(args.bundle / value['file'])
                         for role, value in manifest['policy']['artifacts'].items()}
        requested = decode(protected_read(args.consumer)) if args.consumer else None
        result = plan(manifest, artifacts, args.action, consumer_id=args.consumer_id,
                      requested=requested, expected_digest=args.expected_sha256)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 2 if result.get('status') == 'blocked' else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ContractError, OSError):
        raise SystemExit('Host QoS contract rejected; no changes were made') from None

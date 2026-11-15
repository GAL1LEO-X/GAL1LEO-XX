"""Finite host-owned QoS applicator. No application imports or shell commands.

The immutable policy binds the two acquired sources and the observed three-class
profile. Registry changes have a separate durable intent; every kernel mutation
is followed by observation. Retiring the last app never resets TC or I/O.
"""
import argparse
import base64
import copy
from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import subprocess
import sys
import time
import types
if __name__!='__main__':
    from host.installation import active as installation_profile, mapped as installation_path
else:
    installation_profile=installation_path=None

PROVIDER = 'develative-host-qos'
VERSION = '0.1.0'
POLICY = '/etc/develative-host-qos/policy.json'
REGISTRY = '/etc/develative-host-qos/registry.json'
STATE = '/var/lib/develative-host-qos'
LOCK = STATE + '/operation.lock'
SOURCES = ('host/installation.py', 'host/qos/applicator.py', 'host/qos/contract.py', 'host/qos/adoption.py', 'host/qos/processes.py', 'host/lifecycle/filesystem.py')
SOURCE_HASHES = {'network': '2331c08bc3a0a857e3a2d0a97673200b8ff6cf2462033157a880489730770603',
                 'resources': '61bf4abe7f323e680422ac20b0eec148c549ce8a6c79f19094a29a2f0fe409e6'}
LIBRARY_SHA256 = '73de55c6eb01a8adac831e45adb12e7d6597f6d8dcd96d7a85b7d9f6fd7d054d'
MODULE_SHA256 = '1c75ae419f3cc14932f4b7981eeb7b84cf68250cb2a08b4b29413bb49c421362'
MODULE_SOURCE = '/usr/local/lib/box-network-priority/v1/mod_box_priority.so'
MODULE_DESTINATION = '/usr/local/lib/develative-host-qos/foreign/sha256-' + MODULE_SHA256 + '/mod_box_priority.so'
TABLES = ('develative_host_qos', 'develative_host_qos_apps')
LEGACY_TABLES = ('box_priority', 'whatsapp_priority')
MAX_BYTES = 1024 * 1024
TOOLS = {'tc': '/usr/sbin/tc', 'nft': '/usr/sbin/nft'}
engine = contract = adoption = processes = None


class QoSError(ValueError):
    pass


def require(value, message):
    if not value:
        raise QoSError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names), 'Unexpected or incomplete QoS fields')


def decode(value):
    require(isinstance(value, bytes) and len(value) <= MAX_BYTES, 'QoS document exceeds its bound')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate QoS key')
            result[key] = value
        return result
    try:
        return json.loads(value, object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(QoSError('Nonfinite QoS value')))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise QoSError('Invalid QoS JSON') from None


def protected(path):
    path = Path(path).absolute()
    require(path == path.resolve(strict=True), 'Source must be physical')
    for entry in (path, *path.parents):
        info = entry.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022
                and (stat.S_ISREG(info.st_mode) if entry == path else stat.S_ISDIR(info.st_mode)),
                'Source must be administratively protected')
    return path


def load_sources(manifest=None, expected=None):
    global engine, contract, adoption, processes, installation_profile, installation_path
    source_root = Path(__file__).resolve().parents[2]
    contents = {}
    if manifest is not None:
        require(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected), 'Source manifest pin required')
        raw = protected(manifest).read_bytes()
        require(len(raw) <= MAX_BYTES and sha(raw) == expected, 'Source manifest differs from its pin')
        value = decode(raw); fields(value, {'format', 'sources'})
        require(value['format'] == 1 and set(value['sources']) == set(SOURCES), 'Incomplete QoS source closure')
        for name in SOURCES:
            contents[name] = protected(source_root / name).read_bytes()
            require(sha(contents[name]) == value['sources'][name], 'QoS source differs from bootstrap pin')
    else:
        require(__name__ != '__main__', 'An explicit protected source manifest is required')
        contents = {name: (source_root / name).read_bytes() for name in SOURCES}
    # A local library caller may have explicitly selected a synthetic profile.
    # Keep that identity without replacing another consumer's imported module.
    # A pinned operational CLI starts unselected and resolves WA only if a WA
    # action is requested; BOX-only QoS does not read the WA marker.
    previous = installation_profile.__globals__ if manifest is None and installation_profile is not None else {}
    selected = previous.get('_selected')
    context = previous.get('_installed_context')
    if context is None and previous.get('_locator_state') is not None:
        context = (Path('/'), 0)
    if selected is not None:
        selected = installation_profile()  # Preserve live drift checks.
    layout=types.ModuleType('_qos_installation_layout')
    layout.__file__=str(source_root/'host/installation.py')
    sys.modules[layout.__name__]=layout
    exec(compile(contents['host/installation.py'],layout.__file__,'exec'),layout.__dict__)
    if selected is not None:
        if context is not None:
            layout.activate_installation(root=context[0], trusted_uid=context[1])
        else:
            copied = (layout.Installation.legacy() if selected.compatibility
                      else layout.Installation.from_dict(selected.as_dict()))
            if selected.roster is not None:
                copied = copied.with_roster(selected.roster)
            layout.select(copied)
    installation_profile,installation_path=layout.active,layout.mapped
    modules = []
    for name in ('host/lifecycle/filesystem.py', 'host/qos/contract.py', 'host/qos/adoption.py', 'host/qos/processes.py'):
        module = types.ModuleType('qos_' + Path(name).stem)
        module.__file__ = str(source_root / name)
        exec(compile(contents[name], module.__file__, 'exec'), module.__dict__)
        modules.append(module)
    engine, contract, adoption, processes = modules


def normalize_tc(qdiscs, filters):
    require(isinstance(qdiscs, list) and isinstance(filters, list), 'Invalid TC observation')
    queues = []
    for entry in qdiscs:
        require(isinstance(entry, dict), 'Invalid qdisc observation')
        allowed = {'kind', 'handle', 'parent', 'root', 'options', 'refcnt', 'bytes', 'packets', 'drops',
                   'overlimits', 'requeues', 'backlog', 'qlen', 'xstats', 'stats', 'stats2'}
        require(set(entry) <= allowed, 'Unknown qdisc property')
        queues.append({key: copy.deepcopy(entry[key]) for key in ('kind', 'handle', 'parent', 'root', 'options') if key in entry})
    classifiers = []
    for entry in filters:
        require(isinstance(entry, dict) and set(entry) <= {'protocol', 'pref', 'kind', 'chain', 'options'},
                'Unknown TC filter property')
        if 'options' not in entry:
            require(set(entry) == {'protocol', 'pref', 'kind', 'chain'}, 'Incomplete TC filter header')
            continue
        classifiers.append(copy.deepcopy(entry))
    return {'qdisc': sorted(queues, key=canonical), 'filter': sorted(classifiers, key=canonical)}


def expected_tc():
    leaf = {'limit': 10240, 'flows': 1024, 'quantum': 1514, 'target': 4999, 'interval': 99999,
            'memory_limit': 33554432, 'ecn': True, 'drop_batch': 64}
    queues = [{'kind': 'ets', 'handle': 'b040:', 'root': True,
               'options': {'bands': 3, 'strict': 1, 'quanta': [12000, 1500], 'priomap': [2] * 16}}]
    queues += [{'kind': 'fq_codel', 'handle': f'b04{i}:', 'parent': f'b040:{i}', 'options': leaf} for i in (1, 2, 3)]
    filters = []
    for offset, protocol in enumerate(('ip', 'ipv6')):
        for pref, tos, cls in ((10, 192, '1'), (20, 136, '2')):
            filters.append({'protocol': protocol, 'pref': pref + offset, 'kind': 'flower', 'chain': 0,
                'options': {'handle': 1, 'classid': 'b040:' + cls, 'keys': {'eth_type': 'ipv4' if protocol == 'ip' else 'ipv6',
                    'ip_tos': tos, 'ip_tos_mask': 'fc'}, 'skip_hw': True, 'not_in_hw': True}})
    return normalize_tc(queues, filters)


def validate_policy(value):
    fields(value, {'format', 'provider', 'component_version', 'source_attestation', 'sources',
                   'parameters', 'initial_consumers', 'foreign_module'})
    require(type(value['format']) is int and value['format'] == 1 and value['provider'] == PROVIDER
            and value['component_version'] == VERSION, 'Unsupported QoS policy')
    fields(value['source_attestation'], {'snapshot_sha256', 'semantic_scope'})
    require(value['source_attestation'] == {'snapshot_sha256': LIBRARY_SHA256,
        'semantic_scope': 'acquired-three-class-policy-only'}, 'Unreviewed QoS source provenance')
    fields(value['sources'], SOURCE_HASHES)
    for name, expected in SOURCE_HASHES.items():
        item = value['sources'][name]; fields(item, {'sha256', 'base64'})
        try:
            content = base64.b64decode(item['base64'], validate=True)
        except (TypeError, ValueError):
            raise QoSError('Invalid source encoding') from None
        require(item['sha256'] == expected == sha(content) and len(content) <= 65536,
                'Acquired QoS source differs from its reviewed hash')
    p = value['parameters']
    fields(p, {'interface', 'io_device', 'io_number', 'io_qos', 'essential_accounts', 'box_account', 'tc', 'weights'})
    require(all(isinstance(p[name], str) for name in ('interface', 'io_device', 'io_number')) and re.fullmatch('[a-zA-Z0-9_.:-]{1,15}', p['interface'])
            and re.fullmatch('/dev/[a-zA-Z0-9_-]+', p['io_device'])
            and re.fullmatch('[0-9]+:[0-9]+', p['io_number']), 'Invalid interface or physical device identity')
    require(p['tc'] == expected_tc(), 'TC parameters differ from the acquired three-class profile')
    require(p['weights'] == {'frontend': 1000, 'applications': 800, 'mail': 100}, 'Effective weights differ from the acquired profile')
    require(isinstance(p['io_qos'], str) and p['io_qos'].split() ==
        [p['io_number'], 'enable=1', 'ctrl=auto', 'rpct=0.00', 'rlat=5000', 'wpct=0.00', 'wlat=5000', 'min=1.00', 'max=10000.00'],
        'Incomplete observed I/O cost parameters')
    fields(p['essential_accounts'], {'_apt', 'bind', 'systemd-timesync'})
    for name, account in {**p['essential_accounts'], 'boxproxy': p['box_account']}.items():
        fields(account, {'uid', 'gid', 'home', 'shell'})
        require(type(account['uid']) is int and 0 < account['uid'] < 2**31
                and type(account['gid']) is int and 0 <= account['gid'] < 2**31
                and isinstance(account['home'], str) and account['home'].startswith('/')
                and account['shell'] == '/usr/sbin/nologin', 'Invalid dedicated account evidence')
    fields(value['foreign_module'], {'source', 'destination', 'sha256', 'size', 'source_available'})
    require(value['foreign_module'] == {'source': MODULE_SOURCE, 'destination': MODULE_DESTINATION,
        'sha256': MODULE_SHA256, 'size': 16136, 'source_available': False}, 'Foreign module provenance differs')
    validate_registry({'format': 1, 'policy_sha256': '0' * 64, 'consumers': value['initial_consumers']}, value)
    return value


def validate_registry(value, policy):
    """Validate host-owned records without consulting an application's live files.

    Policy snapshots and committed journals retain identities after retirement.
    Their root-protected provenance is distinct from current runtime admission.
    """
    fields(value, {'format', 'policy_sha256', 'consumers'})
    require(type(value['format']) is int and value['format'] == 1
            and isinstance(value['policy_sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['policy_sha256'])
            and isinstance(value['consumers'], dict) and len(value['consumers']) <= 256, 'Invalid QoS registry')
    uids = set()
    for name, item in value['consumers'].items():
        fields(item, {'owner', 'account', 'uid', 'gid', 'home', 'unit', 'status'})
        require(item['owner'] in ('box', 'whatsapp') and isinstance(name, str)
                and re.fullmatch(item['owner'] + r'\.[a-z][a-z0-9-]{0,31}', name)
                and item['status'] in ('active', 'retired'), 'Invalid application consumer')
        require(type(item['uid']) is int and 0 < item['uid'] < 2**31 and item['uid'] not in uids
                and type(item['gid']) is int and 0 <= item['gid'] < 2**31, 'Consumer UID must be dedicated')
        uids.add(item['uid'])
        if item['owner'] == 'box':
            require(item['account'] == 'boxproxy' and item['unit'] == 'box-proxy.service'
                    and {k: item[k] for k in ('uid', 'gid', 'home')} ==
                    {k: policy['parameters']['box_account'][k] for k in ('uid', 'gid', 'home')}, 'Invalid BOX account binding')
        else:
            require(isinstance(item['account'], str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', item['account'])
                    and item['account'] not in ('root', 'nobody', 'daemon', 'www-data')
                    and isinstance(item['unit'], str) and re.fullmatch(r'[a-z][a-z0-9-]{0,68}\.service', item['unit'])
                    and isinstance(item['home'], str) and len(item['home']) <= 544
                    and re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', item['home'])
                    and not any(part in ('.', '..') for part in item['home'].split('/')),
                    'Invalid historical WhatsApp identity')
    require(not (uids & {item['uid'] for item in policy['parameters']['essential_accounts'].values()}),
            'Application UID overlaps an essential service')
    return value


def check_installation_bindings(consumers):
    """Only active consumers require a current installed WhatsApp identity."""
    for name, item in consumers.items():
        if item['owner'] != 'whatsapp' or item['status'] != 'active':
            continue
        suffix = name.split('.', 1)[1]
        profile = installation_profile()
        require(item['account'] == profile.account(suffix)
                and item['unit'] == profile.service(suffix) + '.service'
                and item['home'] == profile.instance_paths(suffix)['gateway'],
                'Invalid WhatsApp account binding')


def normalize_nft(value):
    require(isinstance(value, dict) and set(value) == {'nftables'} and isinstance(value['nftables'], list),
            'Invalid nftables observation')
    objects, rules = [], []
    for entry in value['nftables']:
        require(isinstance(entry, dict) and len(entry) == 1, 'Invalid nftables object')
        kind, item = next(iter(entry.items()))
        if kind == 'metainfo': continue
        require(kind in ('table', 'chain', 'counter', 'rule') and isinstance(item, dict), 'Unexpected nftables object')
        item = {key: content for key, content in item.items() if key != 'handle'
                and not (kind == 'counter' and key in ('packets', 'bytes'))}
        (rules if kind == 'rule' else objects).append({kind: item})
    return {'nftables': sorted(objects, key=canonical) + rules}


def nft_policy(policy, consumers, *, legacy=False):
    """Return a finite nft script and its normalized JSON projection, in rule order."""
    names = LEGACY_TABLES if legacy else TABLES
    interface = policy['parameters']['interface']
    essential = sorted(item['uid'] for item in policy['parameters']['essential_accounts'].values())
    boxes = sorted(item['uid'] for item in consumers.values() if item['owner'] == 'box' and item['status'] == 'active')
    whatsapps = sorted(item['uid'] for item in consumers.values() if item['owner'] == 'whatsapp' and item['status'] == 'active')
    output, expected = [], {}
    meta = lambda key: {'meta': {'key': key}}
    payload = lambda protocol, field: {'payload': {'protocol': protocol, 'field': field}}
    match = lambda left, right: {'match': {'op': '==', 'left': left, 'right': right}}
    for index, name in enumerate(names):
        priority = -140 if index == 0 else -141
        comment = ('Essential services first; BOX second; other traffic third' if index == 0 else
                   'WhatsApp resource priority; shared BOX AF41 class')
        counters = ['essential', 'proxy_ipv4', 'proxy_ipv6', 'https_ipv4', 'https_ipv6'] if index == 0 else ['gateway_ipv4', 'gateway_ipv6']
        objects = [{'table': {'family': 'inet', 'name': name, 'comment': comment}},
                   {'chain': {'family': 'inet', 'table': name, 'name': 'output', 'type': 'route',
                              'hook': 'output', 'prio': priority, 'policy': 'accept'}}]
        objects += [{'counter': {'family': 'inet', 'table': name, 'name': counter}} for counter in counters]
        lines = [f'table inet {name} {{', f' comment "{comment}"']
        lines += [f' counter {counter} {{ }}' for counter in counters]
        lines += [' chain output {', f'  type route hook output priority {priority}; policy accept;']
        def rule(selector_text, selector, counter, family, dscp=None, observed_only=False):
            field = 'ip' if family == 'ipv4' else 'ip6'
            line = f'  oifname "{interface}" {selector_text} meta nfproto {family} '
            expr = [match(meta('oifname'), interface), *selector]
            if observed_only:
                line += f'{field} dscp af41 counter name {counter}'
                expr += [match(payload(field, 'dscp'), 'af41'), {'counter': counter}]
            else:
                line += f'counter name {counter} {field} dscp set {dscp}'
                expr += [match(meta('nfproto'), family), {'counter': counter},
                         {'mangle': {'key': payload(field, 'dscp'), 'value': dscp}}]
            lines.append(line)
            objects.append({'rule': {'family': 'inet', 'table': name, 'chain': 'output', 'expr': expr}})
        for uid in boxes if index == 0 else whatsapps:
            for family in ('ipv4', 'ipv6'):
                rule(f'meta skuid {uid}', [match(meta('skuid'), uid)],
                     ('proxy_' if index == 0 else 'gateway_') + family, family, 'af41')
        if index == 0:
            for family in ('ipv4', 'ipv6'):
                rule('tcp sport 443', [match(payload('tcp', 'sport'), 443)], 'https_' + family, family, observed_only=True)
            for protocol, ports in (('tcp', [22, 53, 10000, 20000]), ('udp', [53, 123])):
                for family in ('ipv4', 'ipv6'):
                    rule(protocol + ' sport {' + ','.join(map(str, ports)) + '}',
                         [match(payload(protocol, 'sport'), {'set': ports})], 'essential', family, 'cs6')
            for family in ('ipv4', 'ipv6'):
                rule('meta skuid { ' + ', '.join(map(str, essential)) + ' }',
                     [match(meta('skuid'), {'set': essential})], 'essential', family, 'cs6')
        lines += [' }', '}']
        output.append('\n'.join(lines) + '\n')
        expected[name] = normalize_nft({'nftables': objects})
    return ''.join(output).encode(), expected


def scoped_nft(ruleset):
    require(isinstance(ruleset, dict) and set(ruleset) == {'nftables'}, 'Incomplete ruleset observation')
    entries = {name: [] for name in (*TABLES, *LEGACY_TABLES)}
    chains = {}
    for entry in ruleset['nftables']:
        if 'chain' in entry:
            item = entry['chain']; chains[(item.get('family'), item.get('table'), item.get('name'))] = item
    for entry in ruleset['nftables']:
        if 'metainfo' in entry: continue
        require(isinstance(entry, dict) and len(entry) == 1, 'Invalid ruleset item')
        kind, item = next(iter(entry.items()))
        table = item.get('name') if kind == 'table' else item.get('table')
        if item.get('family') == 'inet' and table in entries:
            entries[table].append(entry)
        elif kind == 'rule':
            # Conservatively include regular chains reached by jump/goto, and
            # otherwise unreachable chains. A foreign DSCP writer anywhere
            # requires separate review; hiding it behind another chain cannot
            # bypass ownership admission.
            require(not any(expr.get('mangle', {}).get('key', {}).get('payload', {}).get('field') == 'dscp'
                            or str(expr.get('xt', {}).get('name', '')).lower() == 'dscp'
                            for expr in item.get('expr', [])), 'Another DSCP writer needs explicit review')
    return {name: normalize_nft({'nftables': value}) for name, value in entries.items() if value}


def read_policy(root, path, expected):
    require(path == POLICY and isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected), 'Exact policy path and digest required')
    raw = root.read_bytes(path, max_bytes=MAX_BYTES)
    require(sha(raw) == expected, 'Immutable policy changed')
    info = root.snapshot(path)
    require(info['sha256'] == expected and info['uid'] == root.uid and not info['mode'] & 0o022, 'Policy is not protected')
    return validate_policy(decode(raw))


def account_record(consumer_id, account, unit, lookup=pwd.getpwnam):
    require(isinstance(consumer_id, str) and re.fullmatch(r'whatsapp\.[a-z][a-z0-9-]{0,31}', consumer_id), 'Only a dedicated WhatsApp account can be enrolled')
    suffix = consumer_id.split('.', 1)[1]
    require(account == installation_profile().account(suffix)
            and unit == installation_profile().service(suffix) + '.service', 'Consumer and account/unit identities differ')
    value = lookup(account)
    require(value.pw_uid > 0 and value.pw_dir == installation_profile().instance_paths(suffix)['gateway']
            and value.pw_shell == '/usr/sbin/nologin', 'Unexpected account UID, home or login shell')
    return {'owner': 'whatsapp', 'account': account, 'uid': value.pw_uid, 'gid': value.pw_gid,
            'home': value.pw_dir, 'unit': unit, 'status': 'active'}


def check_accounts(policy, consumers, lookup=pwd.getpwnam, census=pwd.getpwall):
    check_installation_bindings(consumers)
    expected = {**policy['parameters']['essential_accounts']}
    for item in consumers.values():
        if item['status'] == 'active':
            expected[item['account']] = {**{key: item[key] for key in ('uid', 'gid', 'home')}, 'shell': '/usr/sbin/nologin'}
    all_accounts = census()
    require(isinstance(all_accounts, (list, tuple)) and len(all_accounts) <= 65536, 'Invalid complete account census')
    for name, record in expected.items():
        aliases = [item.pw_name for item in all_accounts if item.pw_uid == record['uid']]
        require(aliases == [name], 'An active priority UID is shared or missing from the complete account census')
        actual = lookup(name)
        require((actual.pw_uid, actual.pw_gid, actual.pw_dir, actual.pw_shell) ==
                (record['uid'], record['gid'], record['home'], record['shell']), 'Consumer account evidence changed')


def read_control(root, path):
    info = root.snapshot(path)
    if info is None: return None
    require(info['uid'] == root.uid and info['gid'] == root.gid and info['mode'] == 0o600,
            'QoS control record is not protected')
    raw = root.read_bytes(path, max_bytes=MAX_BYTES)
    require(sha(raw) == info['sha256'], 'QoS control record changed while reading')
    return decode(raw)


def render_units(policy_sha256, entrypoint, sources_manifest, sources_sha256):
    """Pure host service template; callers publish it through their reviewed engine.

    No destructive ExecStop and no dependency on either application's service.
    The migration adapter must neutralize the legacy ExecStop before stopping it.
    """
    require(re.fullmatch('[0-9a-f]{64}', policy_sha256) and re.fullmatch('[0-9a-f]{64}', sources_sha256),
            'Unit requires exact policy/source pins')
    match = re.fullmatch(r'(/usr/local/lib/develative-host-components/[0-9a-f]{64})/host/qos/applicator.py', entrypoint)
    require(match is not None and sources_manifest == match.group(1) + '/qos-sources.json',
            'Unit must use the immutable neutral source generation')
    command = (f'/usr/bin/python3 -I -B {entrypoint} --sources-manifest {sources_manifest} '
               f'--expected-sources-sha256 {sources_sha256} apply --policy {POLICY} '
               f'--expected-sha256 {policy_sha256} --boot')
    body = ('[Unit]\nDescription=Host three-class resource priority\n'
            'After=network-online.target firewalld.service\nWants=network-online.target\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=' + command + '\n'
            'ExecReload=' + command + '\nTimeoutStartSec=180\nTimeoutStopSec=30\n'
            'CapabilityBoundingSet=CAP_NET_ADMIN\nNoNewPrivileges=yes\n'
            'ProtectHome=yes\nProtectSystem=strict\n'
            'ReadWritePaths=/etc/develative-host-qos /var/lib/develative-host-qos '
            '/var/lib/develative-host-lifecycle/host /sys/fs/cgroup/io.cost.qos\n'
            '[Install]\nWantedBy=multi-user.target\n')
    return {'/etc/systemd/system/develative-host-qos.service': body.encode()}


def consumer_dropins(record):
    """Pure templates, split by administrative vs account-owned destinations."""
    require(record['owner'] == 'whatsapp' and record['status'] == 'active', 'Only active WhatsApp accounts use this template')
    prefix='whatsapp' if installation_profile().compatibility else installation_profile().as_dict()['services']['prefix']
    suffix = record['unit'][len(prefix)+1:-len('.service')]
    require(record['unit'] == installation_profile().service(suffix) + '.service' and re.fullmatch('[a-z][a-z0-9-]{0,31}', suffix)
            and record['home'] == installation_profile().instance_paths(suffix)['gateway'] and type(record['uid']) is int,
            'Invalid consumer drop-in identity')
    weights = b'# Managed by host resource priority.\n[Service]\nCPUWeight=800\nIOWeight=800\n'
    manager = (b'# Managed by host resource priority.\n[Unit]\nRequires=develative-host-qos.service\n'
        b'After=develative-host-qos.service\n[Service]\nSlice=system.slice\nCPUWeight=800\nIOWeight=800\nDelegate=cpu io memory pids\n')
    return {'administrative': {
        '/etc/systemd/system/' + record['unit'] + '.d/60-whatsapp-priority.conf': weights,
        f"/etc/systemd/system/user@{record['uid']}.service.d/60-whatsapp-priority.conf": manager},
        'account': {record['home'] + '/.config/systemd/user/whatsapp-waha.service.d/60-whatsapp-priority.conf': weights,
        record['home'] + '/.config/systemd/user/app.slice.d/60-whatsapp-priority.conf':
            b'# Managed by host resource priority.\n[Slice]\nCPUWeight=800\nIOWeight=800\n'}}


def _persist(root, path, value):
    content = canonical(value)
    before = root.snapshot(path)
    require(before is None or (before['uid'], before['gid'], before['mode']) == (root.uid, root.gid, 0o600),
            'Refusing to adopt an unprotected control record')
    if before == {'sha256': sha(content), 'mode': 0o600, 'uid': root.uid, 'gid': root.gid}:
        return
    spec = {'sha256': sha(content), 'mode': 0o600, 'uid': root.uid, 'gid': root.gid, 'retention': 'managed'}
    manifest = lambda files: {'format': 1, 'owner': 'host', 'files': files, 'directories': {}, 'links': {}}
    before_manifest = manifest({path: {**before, 'retention': 'managed'}} if before else {})
    after_manifest = manifest({path: spec})
    opid = sha(canonical({'path': path, 'before': before_manifest, 'after': after_manifest}))[:32]
    engine.reconcile(root, operation_id=opid, before=before_manifest, after=after_manifest,
                     payloads={path: content}, allowed_paths={path}, inline_payloads={path})


@contextmanager
def lease(root, path=LOCK):
    require(root.directory(STATE) == {'uid': root.uid, 'gid': root.gid, 'mode': 0o700}, 'QoS state must be prepared and protected')
    require(path in (LOCK, STATE + '/adoption.lock'), 'Unknown QoS lease scope')
    with root._parent(path) as (parent, name):
        descriptor = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == root.uid
                    and stat.S_IMODE(info.st_mode) == 0o600, 'Invalid stable QoS lease')
            try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise QoSError('QoS operation is already in progress') from None
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), 'QoS lease identity changed')
            yield descriptor
        finally:
            os.close(descriptor)


def _bounded(argv, stdin=None):
    require(stdin is None or isinstance(stdin, bytes) and len(stdin) <= MAX_BYTES, 'Client input exceeds its bound')
    child = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    selector = selectors.DefaultSelector(); outputs = {child.stdout: bytearray(), child.stderr: bytearray()}
    pending = memoryview(stdin or b''); deadline = time.monotonic() + 20
    try:
        for stream in outputs:
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ)
        if stdin is not None:
            os.set_blocking(child.stdin.fileno(), False)
            if pending: selector.register(child.stdin, selectors.EVENT_WRITE)
            else: child.stdin.close()
        while selector.get_map():
            remaining = deadline - time.monotonic(); require(remaining > 0, 'QoS client timed out')
            for key, _ in selector.select(remaining):
                if key.fileobj == child.stdin:
                    count = os.write(key.fd, pending[:8192]); pending = pending[count:]
                    if not pending: selector.unregister(child.stdin); child.stdin.close()
                else:
                    chunk = os.read(key.fd, 8192)
                    if not chunk: selector.unregister(key.fileobj)
                    else:
                        outputs[key.fileobj].extend(chunk)
                        require(sum(map(len, outputs.values())) <= MAX_BYTES, 'QoS client output exceeded its bound')
        child.wait(timeout=max(0.001, deadline - time.monotonic()))
        require(child.returncode == 0, 'QoS client failed')
        return bytes(outputs[child.stdout])
    finally:
        selector.close()
        if child.poll() is None: child.kill()
        child.wait()  # Lease supervisor must not exit before its own client.
        for stream in (child.stdout, child.stderr, child.stdin):
            if stream is not None: stream.close()


def supervised(argv, stdin, lease_fd):
    """Fork a bounded supervisor holding the lease independently of its caller.

    argv is built only by Kernel below. A killed caller does not release the
    lock while the CLI client can still mutate the kernel; no workload is killed.
    """
    os.fstat(lease_fd)
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        try:
            result = b'1' + _bounded(argv, stdin)
        except BaseException:
            result = b'0'
        try:
            view = memoryview(result)
            while view: view = view[os.write(writer, view):]
        except BrokenPipeError:
            pass
        finally:
            os.close(writer); os.close(lease_fd); os._exit(0)
    os.close(writer)
    try:
        result = bytearray()
        while True:
            chunk = os.read(reader, 8192)
            if not chunk: break
            result.extend(chunk)
            require(len(result) <= MAX_BYTES + 1, 'Supervisor response exceeds its bound')
        require(result[:1] == b'1', 'Scoped QoS client incomplete; observe intent before retry')
        return bytes(result[1:])
    finally:
        os.close(reader); os.waitpid(pid, 0)


class Kernel:
    def __init__(self, root, policy, descriptor):
        require(root.base == Path('/') and os.geteuid() == 0, 'Real kernel access is restricted to the explicit host root')
        self.root, self.policy, self.descriptor = root, policy, descriptor
        for program in TOOLS.values(): protected(program)
        info = Path(policy['parameters']['io_device']).stat()
        number = f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}'
        require(stat.S_ISBLK(info.st_mode) and number == policy['parameters']['io_number'], 'Physical device identity changed')
        sysdev = Path('/sys/dev/block') / number
        require(not (sysdev / 'partition').exists() and (sysdev / 'device').exists(), 'I/O target must be a physical disk')

    def run(self, program, args, stdin=None):
        require(program in TOOLS, 'Unknown QoS program')
        return supervised([TOOLS[program], *args], stdin, self.descriptor)

    def observe(self):
        device = self.policy['parameters']['interface']
        tc = normalize_tc(decode(self.run('tc', ['-j', 'qdisc', 'show', 'dev', device])),
                          decode(self.run('tc', ['-j', 'filter', 'show', 'dev', device, 'parent', 'b040:'])))
        nft = scoped_nft(decode(self.run('nft', ['-j', 'list', 'ruleset'])))
        number = self.policy['parameters']['io_number']
        lines = Path('/sys/fs/cgroup/io.cost.qos').read_text().splitlines()
        selected = [line for line in lines if line.split() and line.split()[0] == number]
        require(len(selected) <= 1, 'Duplicate physical disk I/O evidence')
        return {'tc': tc, 'nft': nft, 'io': selected[0] if selected else None}

    def ready(self):
        adoption.Systemd(types.SimpleNamespace(**globals()), self.root, self.policy, self.descriptor).ready()

    def registration_state(self, record):
        return adoption.Systemd(types.SimpleNamespace(**globals()), self.root, self.policy, self.descriptor).registration_state(record)

    def registration_ready(self, record, previous=None, *, reload=False):
        adoption.Systemd(types.SimpleNamespace(**globals()), self.root, self.policy, self.descriptor).registration_ready(record, previous, reload=reload)

    def syntax(self, content):
        self.run('nft', ['--check', '-f', '-'], content)

    def mutate(self, step):
        if step['kind'] == 'tc':
            while True:
                actual = self.observe()
                require(pending_tc(self.policy, step, actual), 'TC creation differs from pending intent')
                progress = tc_progress(self.policy, actual['tc'])
                if progress == len(step['commands']): break
                self.run('tc', step['commands'][progress])
        elif step['kind'] == 'nft': self.run('nft', ['-f', '-'], step['script'].encode())
        elif step['kind'] == 'io':
            # This write is synchronous in the lease holder; no spawned writer.
            with open('/sys/fs/cgroup/io.cost.qos', 'w') as stream:
                stream.write(self.policy['parameters']['io_number'] + ' enable=1\n')
        else: raise QoSError('Unrecognized finite kernel operation')


def baseline_tc(value):
    """Only an unclassified default MQ device or an empty root can bootstrap."""
    if value == {'qdisc': [], 'filter': []}: return True
    if value.get('filter'): return False
    roots = [item for item in value.get('qdisc', []) if item.get('root')]
    if roots != [{'kind': 'mq', 'handle': '0:', 'root': True}]: return False
    leaf_options = next(item['options'] for item in expected_tc()['qdisc'] if item['kind'] == 'fq_codel')
    leaves = [item for item in value['qdisc'] if not item.get('root')]
    return all(set(item) == {'kind', 'handle', 'parent', 'options'} and item['kind'] == 'fq_codel'
               and item['handle'] == '0:' and re.fullmatch(r':[1-9a-f][0-9a-f]*', item['parent'])
               and item['options'] == leaf_options for item in leaves)


def tc_commands(policy):
    device = policy['parameters']['interface']
    commands = [['qdisc', 'replace', 'dev', device, 'root', 'handle', 'b040:', 'ets',
                 'bands', '3', 'strict', '1', 'quanta', '12000', '1500', 'priomap', *(['2'] * 16)]]
    commands += [['qdisc', 'replace', 'dev', device, 'parent', f'b040:{i}', 'handle', f'b04{i}:',
                  'fq_codel', 'limit', '10240', 'flows', '1024', 'target', '5ms', 'interval', '100ms', 'ecn']
                 for i in (1, 2, 3)]
    for offset, protocol in enumerate(('ip', 'ipv6')):
        for pref, tos, cls in ((10, '0xc0/0xfc', '1'), (20, '0x88/0xfc', '2')):
            commands.append(['filter', 'replace', 'dev', device, 'parent', 'b040:', 'protocol', protocol,
                             'pref', str(pref + offset), 'handle', '1', 'flower', 'skip_hw', 'ip_tos', tos,
                             'classid', 'b040:' + cls])
    return commands


def tc_progress(policy, observed):
    """Recognize only a prefix of this journal-authorized new root creation.

    Kernel default children with handle 0 under the three new classes can be
    replaced. This predicate is never admission for a new, unjournaled action.
    """
    if baseline_tc(observed): return 0
    expected = policy['parameters']['tc']
    roots = [item for item in observed['qdisc'] if item.get('root')]
    require(roots == [item for item in expected['qdisc'] if item.get('root')], 'Pending TC root differs')
    leaves = {item.get('parent'): item for item in observed['qdisc'] if not item.get('root')}
    require(len(leaves) == len(observed['qdisc']) - 1 and set(leaves) <= {'b040:1', 'b040:2', 'b040:3'},
            'Foreign child appeared under pending TC root')
    expected_leaves = {item['parent']: item for item in expected['qdisc'] if not item.get('root')}
    complete = 1
    pending = False
    for i in (1, 2, 3):
        leaf = leaves.get(f'b040:{i}')
        if leaf == expected_leaves[f'b040:{i}']:
            require(not pending, 'TC children are not a recognized creation prefix'); complete += 1
        else:
            pending = True
            require(leaf is None or leaf.get('handle') == '0:'
                    and leaf.get('kind') in ('pfifo', 'pfifo_fast', 'fq_codel', 'noqueue')
                    and set(leaf) <= {'kind', 'handle', 'parent', 'options'}, 'Unexpected pending kernel child')
    ordered = []
    for protocol, pref in (('ip', 10), ('ip', 20), ('ipv6', 11), ('ipv6', 21)):
        ordered.append(next(item for item in expected['filter'] if item['protocol'] == protocol and item['pref'] == pref))
    filters = observed['filter']
    require(all(item in ordered for item in filters) and len(filters) == len({canonical(item) for item in filters}),
            'Unexpected pending TC classifier')
    if filters:
        require(complete == 4 and sorted(filters, key=canonical) == sorted(ordered[:len(filters)], key=canonical),
                'TC classifiers are not a recognized creation prefix')
        complete += len(filters)
    return complete


def pending_tc(policy, step, actual):
    if step['kind'] != 'tc' or actual['nft'] != step['before']['nft'] or actual['io'] != step['before']['io']:
        return False
    try:
        tc_progress(policy, actual['tc']); return True
    except QoSError:
        return False


def kernel_steps(policy, before, consumers, *, allow_legacy):
    require(set(before) == {'tc', 'nft', 'io'} and (before['tc'] == policy['parameters']['tc']
            or allow_legacy and baseline_tc(before['tc'])),
            'TC is neither the complete acquired profile nor an explicit empty/default MQ baseline')
    target_script, target_nft = nft_policy(policy, consumers)
    _, legacy_nft = nft_policy(policy, policy['initial_consumers'], legacy=True)
    allowed = target_nft if not allow_legacy else legacy_nft
    # Existing host state may represent the registry before the requested delta;
    # caller separately attests that state before building this transition.
    require(set(before['nft']) in (set(TABLES), set(LEGACY_TABLES), set())
            and (set(before['nft']) == set(TABLES) or allow_legacy and (before['nft'] == allowed or not before['nft'])),
            'QoS table ownership is incomplete or differs from the adopted policy')
    require(before['io'] in (policy['parameters']['io_qos'], policy['parameters']['io_qos'].replace('enable=1', 'enable=0', 1))
            or allow_legacy and before['io'] is None,
            'I/O tuning changed; no automatic model repair')
    state, steps = copy.deepcopy(before), []
    if state['tc'] != policy['parameters']['tc']:
        after = {**state, 'tc': policy['parameters']['tc']}
        steps.append({'kind': 'tc', 'before': state, 'after': after, 'commands': tc_commands(policy)}); state = after
    if state['io'] != policy['parameters']['io_qos']:
        after = {**state, 'io': policy['parameters']['io_qos']}
        steps.append({'kind': 'io', 'before': state, 'after': after}); state = after
    if state['nft'] != target_nft:
        script = ''.join(f'delete table inet {name}\n' for name in sorted(state['nft'])) + target_script.decode()
        after = {**state, 'nft': target_nft}
        steps.append({'kind': 'nft', 'before': state, 'after': after, 'script': script})
    return steps


def _receipt(registry, consumer_id=None):
    result = {'provider': PROVIDER, 'version': VERSION, 'status': 'complete',
              'capabilities': ['uid-af41', 'three-class-preserved', 'forward-resume', 'host-retained'],
              'registry_sha256': sha(canonical(registry))}
    if consumer_id is not None:
        result.update({'consumer_id': consumer_id, **registry['consumers'][consumer_id]})
        result['consumer_status'] = result.pop('status'); result['status'] = 'complete'
    return result


def operate(root, *, policy_path, expected_sha256, action, operation_id=None, consumer_id=None,
            account=None, unit=None, kernel_factory=Kernel, lookup=pwd.getpwnam, census=pwd.getpwall, fault=None, _lease_fd=None,
            proc_root=Path('/proc')):
    require(action in ('check', 'apply', 'register-consumer', 'retire-consumer'), 'Unknown QoS action')
    if action != 'check':
        require(isinstance(operation_id, str) and re.fullmatch('[0-9a-f]{32}', operation_id), 'Stable operation ID required')
    policy = read_policy(root, policy_path, expected_sha256)
    request = {'policy_sha256': expected_sha256, 'action': action, 'operation_id': operation_id,
               'consumer_id': consumer_id, 'account': account, 'unit': unit}
    emit = fault or (lambda event, detail: None)
    with (lease(root) if _lease_fd is None else nullcontext(_lease_fd)) as descriptor:
        if _lease_fd is not None:
            os.fstat(descriptor)
        policy = read_policy(root, policy_path, expected_sha256)
        backend = kernel_factory(root, policy, descriptor)
        initial = {'format': 1, 'policy_sha256': expected_sha256, 'consumers': policy['initial_consumers']}
        record = read_control(root, REGISTRY)
        registry = validate_registry(initial if record is None else record, policy)
        require(registry['policy_sha256'] == expected_sha256, 'Registry belongs to a different immutable policy')
        check_installation_bindings(registry['consumers'])
        journal_path = STATE + '/operations/' + operation_id + '.json' if operation_id else None
        journal = read_control(root, journal_path) if journal_path else None
        active = read_control(root, STATE + '/active-operation.json')
        if active is not None:
            fields(active, {'format', 'request'})
            require(active['format'] == 1 and isinstance(active['request'], dict), 'Invalid pending-operation pointer')
            if active['request'] != request:
                previous_id = active['request'].get('operation_id')
                require(isinstance(previous_id, str) and re.fullmatch('[0-9a-f]{32}', previous_id), 'Invalid pending operation identity')
                previous = read_control(root, STATE + '/operations/' + previous_id + '.json')
                require(isinstance(previous, dict) and previous.get('request') == active['request'],
                        'Pending-operation pointer differs from its durable intent')
                if action != 'check':
                    require(previous.get('phase') == 'committed',
                            'Another durable QoS operation must be resumed before a new mutation')
                elif previous.get('phase') != 'committed' and active['request'].get('action') == 'retire-consumer':
                    # A read-only observation must not turn an unfinished last
                    # retirement into permission to ignore its active preimage.
                    before = validate_registry(previous['before_registry'], policy)
                    after = validate_registry(previous['after_registry'], policy)
                    require(before['policy_sha256'] == after['policy_sha256'] == expected_sha256
                            and registry in (before, after), 'Pending retirement registry differs')
                    check_installation_bindings(before['consumers'])
                    check_installation_bindings(after['consumers'])
        if journal is None:
            check_accounts(policy, registry['consumers'], lookup, census)
            before = backend.observe()
            _, old_nft = nft_policy(policy, registry['consumers'])
            if action != 'apply':
                backend.ready()
                require(root.snapshot(REGISTRY) is not None and before['tc'] == policy['parameters']['tc']
                        and before['io'] == policy['parameters']['io_qos'] and before['nft'] == old_nft,
                        'Installed host QoS provider is not complete and coherent')
            else:
                require(not before['nft'] or before['nft'] == old_nft or before['nft'] == nft_policy(policy, policy['initial_consumers'], legacy=True)[1],
                        'Actual marking differs from explicit host or adopted legacy policy')
            if action == 'check':
                require(consumer_id is None or consumer_id in registry['consumers'], 'Unknown scoped consumer check')
                require(account is None and unit is None, 'Read-only check cannot change account identity')
                return _receipt(registry, consumer_id)
            after_registry = copy.deepcopy(registry)
            if action == 'register-consumer':
                record = account_record(consumer_id, account, unit, lookup)
                previous = registry['consumers'].get(consumer_id)
                require(previous is None or previous == record, 'Consumer cannot replace an existing or retired identity')
                after_registry['consumers'][consumer_id] = record
            elif action == 'retire-consumer':
                require(consumer_id in registry['consumers'] and account is None and unit is None, 'Unknown retirement target')
                if registry['consumers'][consumer_id]['status'] == 'active':
                    processes.require_uid_quiet(registry['consumers'][consumer_id]['uid'], proc_root=proc_root)
                after_registry['consumers'][consumer_id]['status'] = 'retired'
            else:
                require(consumer_id is None and account is None and unit is None, 'Host apply does not accept a consumer')
            validate_registry(after_registry, policy)
            check_accounts(policy, after_registry['consumers'], lookup, census)
            steps = kernel_steps(policy, before, after_registry['consumers'], allow_legacy=action == 'apply')
            # All syntax checks and ownership/TC/I/O/account checks precede the first kernel mutation.
            for step in steps:
                if step['kind'] == 'nft': backend.syntax(step['script'].encode())
            frontend_retirement = None
            if action == 'retire-consumer':
                frontend_before = read_control(root, FRONTENDS)
                if frontend_before is not None:
                    fields(frontend_before, {'format', 'policy_sha256', 'bindings'})
                    require(frontend_before['policy_sha256'] == expected_sha256, 'Frontend bindings belong to another policy')
                    frontend_after = copy.deepcopy(frontend_before)
                    for name, binding in frontend_after['bindings'].items():
                        if name == consumer_id or consumer_id == 'box.proxy' and binding['owner'] == 'box':
                            binding['status'] = 'retired'
                    frontend_retirement = {'before': frontend_before, 'after': frontend_after}
            registration = (adoption.registration_plan(types.SimpleNamespace(**globals()), root, record,
                                allow_legacy_user=(policy['initial_consumers'].get(consumer_id) == record
                                                   and registry['consumers'].get(consumer_id) == record))
                            if action == 'register-consumer' else None)
            registration_state = backend.registration_state(record) if registration is not None else None
            journal = {'format': 1, 'request': request, 'registration': registration, 'registration_state': registration_state, 'frontend_retirement': frontend_retirement, 'before_registry': registry, 'after_registry': after_registry,
                       'steps': steps, 'done': 0, 'phase': 'prepared', 'initial_state': before}
            _persist(root, STATE + '/active-operation.json', {'format': 1, 'request': request})
            _persist(root, journal_path, journal); emit('prepared', 0)
        else:
            fields(journal, {'format', 'request', 'registration', 'registration_state', 'frontend_retirement', 'before_registry', 'after_registry', 'steps', 'done', 'phase', 'initial_state'})
            require(journal['format'] == 1 and journal['request'] == request, 'Operation ID conflicts with a different request')
            validate_registry(journal['before_registry'], policy); validate_registry(journal['after_registry'], policy)
            if journal['phase'] == 'committed':
                require(journal['done'] == len(journal['steps']), 'Committed intent is incomplete')
                if consumer_id is not None:
                    require(registry['consumers'].get(consumer_id) == journal['after_registry']['consumers'][consumer_id],
                            'Previously completed consumer changed')
                check_accounts(policy, registry['consumers'], lookup, census)
                if journal['registration'] is not None:
                    adoption.verify_registration(types.SimpleNamespace(**globals()), root, journal['registration'])
                    backend.registration_ready(journal['after_registry']['consumers'][consumer_id])
                actual = backend.observe()
                require(actual == {'tc': policy['parameters']['tc'], 'io': policy['parameters']['io_qos'],
                    'nft': nft_policy(policy, registry['consumers'])[1]}, 'Completed provider has drifted')
                return _receipt(registry, consumer_id)
            # Until commit, a retirement still depends on its active preimage,
            # including a restart after the retired registry was published.
            check_installation_bindings(journal['before_registry']['consumers'])
            require(registry in (journal['before_registry'], journal['after_registry']), 'Registry drifted outside durable intent')
            expected_steps = kernel_steps(policy, journal['initial_state'], journal['after_registry']['consumers'], allow_legacy=action == 'apply')
            require(journal['steps'] == expected_steps and type(journal['done']) is int
                    and 0 <= journal['done'] <= len(expected_steps)
                    and journal['phase'] in ('prepared', 'intent', 'kernel-complete', 'committed'), 'Invalid durable kernel intent')
        check_accounts(policy, journal['after_registry']['consumers'], lookup, census)
        if action == 'retire-consumer' and registry['consumers'][consumer_id]['status'] == 'active':
            processes.require_uid_quiet(registry['consumers'][consumer_id]['uid'], proc_root=proc_root)
        if journal['registration'] is not None:
            require(action == 'register-consumer', 'Unexpected registration publication')
            adoption.publish_registration(types.SimpleNamespace(**globals()), root, journal['registration'], request)
            emit('dropins', None)
            backend.registration_ready(journal['after_registry']['consumers'][consumer_id], journal['registration_state'], reload=True)
            emit('consumer-reloaded', None)
        for index, step in enumerate(journal['steps']):
            if index < journal['done']: continue
            actual = backend.observe()
            require(actual in (step['before'], step['after']) or pending_tc(policy, step, actual),
                    'Kernel changed outside the pending bounded operation')
            journal['phase'] = 'intent'; _persist(root, journal_path, journal); emit('intent', index)
            if actual != step['after']:
                if step['kind'] == 'nft': backend.syntax(step['script'].encode())
                backend.mutate(step); emit('mutated', index)
            require(backend.observe() == step['after'], 'Kernel result differs from durable intent; inspect before retry')
            journal['done'] = index + 1; _persist(root, journal_path, journal); emit('observed', index)
        expected_state = journal['steps'][-1]['after'] if journal['steps'] else journal['initial_state']
        require(backend.observe() == expected_state, 'Final host policy observation differs')
        journal['phase'] = 'kernel-complete'; _persist(root, journal_path, journal); emit('kernel-complete', 0)
        _persist(root, REGISTRY, journal['after_registry']); emit('registry', 0)
        if journal['frontend_retirement'] is not None:
            transition = journal['frontend_retirement']
            require(read_control(root, FRONTENDS) in (transition['before'], transition['after']), 'Frontend bindings changed outside pending retirement')
            _persist(root, FRONTENDS, transition['after'])
        journal['phase'] = 'committed'; _persist(root, journal_path, journal); emit('committed', 0)
        return _receipt(journal['after_registry'], consumer_id)


FRONTENDS = '/etc/develative-host-qos/frontend-bindings.json'


@contextmanager
def frontend_lease(root):
    path = '/var/lib/develative-host-frontend/operation.lock'
    with root._parent(path) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == root.uid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'Frontend lease is not protected')
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise QoSError('Frontend operation is in progress') from None
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), 'Frontend lease changed')
            yield
        finally:
            os.close(fd)


def frontend_binding(root, *, consumer_id, operation_id, receipt_sha256):
    require(isinstance(consumer_id, str) and re.fullmatch(r'(whatsapp|box)\.[a-z][a-z0-9.-]{0,63}', consumer_id)
            and re.fullmatch('[0-9a-f]{32}', operation_id) and re.fullmatch('[0-9a-f]{64}', receipt_sha256),
            'Exact frontend consumer and receipt identities required')
    receipt_path = '/var/lib/develative-host-frontend/operations/' + operation_id + '.json'
    receipt = read_control(root, receipt_path)
    require(receipt is not None and sha(root.read_bytes(receipt_path)) == receipt_sha256, 'Frontend receipt pin differs')
    fields(receipt, {'format', 'operation_id', 'plan_sha256', 'phase', 'before', 'after', 'allowed_paths', 'context'})
    require(receipt['format'] == 1 and receipt['operation_id'] == operation_id and receipt['phase'] == 'complete'
            and receipt['plan_sha256'] == sha(canonical({key: receipt[key] for key in ('before', 'after', 'allowed_paths', 'context')})),
            'Frontend receipt is not a completed, digest-bound configuration operation')
    after = engine.validate_manifest(receipt['after'])
    def pinned(path):
        require(path in after['files'], 'Frontend binding artifact is absent from its completed receipt')
        expected = {key: value for key, value in after['files'][path].items() if key != 'retention'}
        require(expected['uid'] == root.uid and not expected['mode'] & 0o022 and root.snapshot(path) == expected,
                'Frontend binding artifact changed after configuration publication')
        return root.read_bytes(path, max_bytes=MAX_BYTES)
    registry = decode(pinned('/etc/develative-host-frontend/registry.json'))
    profile = decode(pinned('/etc/develative-host-frontend/profile.json'))
    require(registry.get('provider') == 'develative-host-frontend' and registry.get('owner') == 'host'
            and registry.get('format') == 1 and registry.get('apache', {}).get('unit') == 'apache2.service',
            'Shared Apache listener must have a host-owned configuration registry')
    require(consumer_id in registry['consumers'], 'Frontend consumer is absent')
    consumer = registry['consumers'][consumer_id]
    require(consumer['owner'] == consumer_id.split('.')[0] and consumer['status'] == 'active', 'Frontend consumer is not active')
    modules = [item for item in profile.get('modules', []) if item.get('identifier') == 'box_priority_module']
    require(len(modules) == 1 and modules[0]['path'] == MODULE_DESTINATION, 'Frontend priority module is not the preserved host-owned artifact')
    module = modules[0]
    require(sha(pinned(MODULE_DESTINATION)) == MODULE_SHA256, 'Foreign module bytes differ from acquired binary')
    loader = pinned(module['file']).decode()
    require(type(module['line']) is int and 0 < module['line'] <= len(loader.splitlines())
            and loader.splitlines()[module['line'] - 1] == module['text']
            and module['text'].strip() == 'LoadModule box_priority_module ' + MODULE_DESTINATION,
            'Priority module loader directive differs')
    vhosts, links, names, selectors, tls = {}, {}, set(), set(), False
    for path in consumer['vhosts']:
        if path in after['links']:
            expected = {key: value for key, value in after['links'][path].items() if key != 'retention'}
            require(root.link(path) == expected, 'Enabled vhost link changed')
            links[path] = expected
            path = engine.resolve_link_target(path, expected['target'])
        require(re.fullmatch(r'/etc/apache2/sites-available/[A-Za-z0-9_.-]+\.conf', path), 'Unknown vhost path')
        if path in vhosts: continue
        content = pinned(path); text = content.decode()
        blocks = re.findall(r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost\s*>', text, re.I | re.S)
        require(blocks, 'Selected vhost has no explicit listener block')
        for selector, body in blocks:
            values = re.findall(r'^\s*BoxPriorityDSCP\s+(\d+)\s*$', body, re.M)
            if any(value.endswith(':443') for value in selector.split()):
                require(values == ['34'], 'TLS vhost has no unambiguous acquired AF41 directive'); tls = True
            else:
                require(values in ([], ['34']), 'HTTP vhost changes the acquired marking semantics')
        names.update(value for line in re.findall(r'^\s*Server(?:Name|Alias)\s+([^#\n]+)', text, re.M) for value in line.split())
        selectors.update(re.findall(r'<VirtualHost\s+([^>]+)>', text, re.I))
        vhosts[path] = sha(content)
    require(vhosts and names == set(consumer['domains']) and tls,
            'Frontend names or TLS vhost selectors differ from the consumer registry')
    return {'owner': consumer['owner'], 'status': 'configuration-bound', 'runtime_verified': False,
        'frontend_operation_id': operation_id, 'receipt_sha256': receipt_sha256,
        'domains': sorted(names), 'vhosts': vhosts, 'links': links, 'consumer_id': consumer_id, 'consumer': consumer, 'module_definition': module,
        'module': {'path': MODULE_DESTINATION, 'sha256': MODULE_SHA256,
                   'loader': module['file'], 'loader_sha256': sha(loader.encode())},
        'shared_listener': {'owner': 'host', 'unit': 'apache2.service', 'vhost_selectors': sorted(selectors)},
        'proof_scope': 'configuration-and-reload-command-return-only',
        'observation': 'historical-completed-configuration-receipt'}


def verify_frontend_binding(root, binding):
    """Reobserve this consumer without pinning other consumers' later changes."""
    def read(path):
        info = root.snapshot(path)
        require(info is not None and info['uid'] == root.uid and not info['mode'] & 0o022,
                'Frontend binding is no longer protected')
        raw = root.read_bytes(path, max_bytes=MAX_BYTES)
        require(sha(raw) == info['sha256'], 'Frontend binding changed while reading')
        return raw
    for path, digest in {**binding['vhosts'], binding['module']['path']: binding['module']['sha256'],
                         binding['module']['loader']: binding['module']['loader_sha256']}.items():
        require(sha(read(path)) == digest, 'Scoped frontend configuration changed')
    for path, expected in binding['links'].items():
        require(root.link(path) == expected, 'Scoped enabled vhost link changed')
    registry = decode(read('/etc/develative-host-frontend/registry.json'))
    profile = decode(read('/etc/develative-host-frontend/profile.json'))
    require(registry.get('provider') == 'develative-host-frontend' and registry.get('owner') == 'host'
            and registry.get('apache', {}).get('unit') == 'apache2.service', 'Shared listener ownership changed')
    require(registry['consumers'].get(binding['consumer_id']) == binding['consumer'], 'Scoped frontend consumer changed')
    require([item for item in profile.get('modules', []) if item.get('identifier') == 'box_priority_module']
            == [binding['module_definition']], 'Scoped frontend module definition changed')


def frontend_transition(root, existing, binding):
    """A new completed frontend receipt explicitly adopts prior pinned files."""
    require(existing['status'] == 'configuration-bound' and all(existing[key] == binding[key]
            for key in ('owner', 'domains', 'shared_listener')), 'Frontend upgrade changes the admitted consumer identity')
    receipt = read_control(root, '/var/lib/develative-host-frontend/operations/' + binding['frontend_operation_id'] + '.json')
    before = engine.validate_manifest(receipt['before'])
    for path, digest in {**existing['vhosts'], existing['module']['path']: existing['module']['sha256'],
                         existing['module']['loader']: existing['module']['loader_sha256']}.items():
        require(path in before['files'] and before['files'][path]['sha256'] == digest,
                'New frontend receipt does not explicitly adopt the previous binding')
    for path, expected in existing['links'].items():
        require(path in before['links'] and {key: value for key, value in before['links'][path].items() if key != 'retention'} == expected,
                'New frontend receipt does not adopt the previous enabled link')


def register_frontend(root, *, policy_path, expected_sha256, operation_id, consumer_id,
                      frontend_operation_id, frontend_receipt_sha256, kernel_factory=Kernel,
                      lookup=pwd.getpwnam, census=pwd.getpwall, fault=None):
    require(re.fullmatch('[0-9a-f]{32}', operation_id), 'Stable frontend binding operation required')
    policy = read_policy(root, policy_path, expected_sha256)
    request = {'action': 'register-frontend', 'operation_id': operation_id, 'policy_sha256': expected_sha256,
        'consumer_id': consumer_id, 'frontend_operation_id': frontend_operation_id,
        'frontend_receipt_sha256': frontend_receipt_sha256}
    emit = fault or (lambda event, detail: None)
    with lease(root) as descriptor, frontend_lease(root):
        backend = kernel_factory(root, policy, descriptor); backend.ready()
        registry = validate_registry(read_control(root, REGISTRY), policy)
        require(registry['policy_sha256'] == expected_sha256, 'UID registry belongs to another policy')
        check_accounts(policy, registry['consumers'], lookup, census)
        require(backend.observe() == {'tc': policy['parameters']['tc'], 'io': policy['parameters']['io_qos'],
            'nft': nft_policy(policy, registry['consumers'])[1]}, 'Kernel policy is not coherent before binding publication')
        active = read_control(root, STATE + '/active-operation.json')
        if active is not None and active['request'] != request:
            previous = read_control(root, STATE + '/operations/' + active['request']['operation_id'] + '.json')
            require(previous is not None and previous['phase'] == 'committed', 'Resume the previous QoS operation first')
        bindings = read_control(root, FRONTENDS) or {'format': 1, 'policy_sha256': expected_sha256, 'bindings': {}}
        fields(bindings, {'format', 'policy_sha256', 'bindings'})
        require(bindings['format'] == 1 and bindings['policy_sha256'] == expected_sha256 and isinstance(bindings['bindings'], dict),
                'Invalid frontend bindings registry')
        path = STATE + '/operations/' + operation_id + '.json'
        journal = read_control(root, path)
        if journal is None:
            binding = frontend_binding(root, consumer_id=consumer_id, operation_id=frontend_operation_id,
                                       receipt_sha256=frontend_receipt_sha256)
            existing = bindings['bindings'].get(consumer_id)
            if existing is not None and existing != binding:
                frontend_transition(root, existing, binding)
            target = copy.deepcopy(bindings); target['bindings'][consumer_id] = binding
            journal = {'format': 1, 'request': request, 'before': bindings, 'after': target, 'phase': 'prepared'}
            _persist(root, STATE + '/active-operation.json', {'format': 1, 'request': request})
            _persist(root, path, journal); emit('frontend-prepared', None)
        else:
            fields(journal, {'format', 'request', 'before', 'after', 'phase'})
            require(journal['format'] == 1 and journal['request'] == request
                    and journal['phase'] in ('prepared', 'committed'), 'Frontend operation identity differs')
            binding = journal['after']['bindings'][consumer_id]
            verify_frontend_binding(root, binding)
            if journal['phase'] == 'committed':
                require(bindings['bindings'].get(consumer_id) == binding, 'Completed frontend binding changed')
            else:
                require(bindings in (journal['before'], journal['after']), 'Frontend bindings changed outside pending intent')
        if journal['phase'] != 'committed':
            _persist(root, FRONTENDS, journal['after']); emit('frontend-registry', None)
            journal['phase'] = 'committed'; _persist(root, path, journal)
        return {'provider': PROVIDER, 'status': 'configuration-bound', 'runtime_verified': False,
                'consumer_id': consumer_id, 'frontend_operation_id': frontend_operation_id,
                'policy_sha256': expected_sha256, 'receipt_sha256': frontend_receipt_sha256}


def prepare(root, *, policy_bytes, expected_sha256, operation_id):
    """Publish a new immutable policy and protected state, with resumable intent."""
    require(re.fullmatch('[0-9a-f]{32}', operation_id) and sha(policy_bytes) == expected_sha256,
            'Preparation needs exact input bytes and a stable identity')
    validate_policy(decode(policy_bytes))
    payloads = {POLICY: policy_bytes, LOCK: b'', STATE + '/adoption.lock': b''}
    directories = {'/etc/develative-host-qos': 0o755,
        '/etc/develative-host-qos/admission-evidence': 0o700, STATE: 0o700, STATE + '/operations': 0o700}
    after = {'format': 1, 'owner': 'host', 'files': {path: {'sha256': sha(content),
        'uid': root.uid, 'gid': root.gid, 'mode': 0o644 if path == POLICY else 0o600,
        'retention': 'retain'} for path, content in payloads.items()}, 'directories': {
            path: {'uid': root.uid, 'gid': root.gid, 'mode': mode, 'retention': 'retain'}
            for path, mode in directories.items()}, 'links': {}}
    before = {'format': 1, 'owner': 'host', 'files': {}, 'directories': {}, 'links': {}}
    receipt = engine.reconcile(root, operation_id=operation_id, before=before, after=after,
        payloads=payloads, allowed_paths=set(payloads) | set(directories), inline_payloads=set(payloads))
    return {'provider': PROVIDER, 'status': 'prepared', 'operation_id': operation_id,
            'policy_sha256': expected_sha256, 'filesystem_phase': receipt['phase'], 'kernel_mutated': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources-manifest'); parser.add_argument('--expected-sources-sha256')
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('inspect', 'prepare', 'activate', 'adopt', 'check', 'apply', 'register-consumer', 'retire-consumer', 'register-frontend'):
        command = commands.add_parser(action)
        command.add_argument('--policy-source' if action == 'prepare' else '--policy', required=True)
        command.add_argument('--expected-sha256', required=True)
        if action == 'apply':
            identity = command.add_mutually_exclusive_group(required=True)
            identity.add_argument('--operation-id'); identity.add_argument('--boot', action='store_true')
        elif action not in ('check', 'inspect'): command.add_argument('--operation-id', required=True)
        if action in ('register-consumer', 'retire-consumer', 'register-frontend'): command.add_argument('--consumer-id', required=True)
        elif action == 'check': command.add_argument('--consumer-id')
        if action == 'register-consumer':
            command.add_argument('--account', required=True); command.add_argument('--unit', required=True)
        if action == 'register-frontend':
            command.add_argument('--frontend-operation-id', required=True); command.add_argument('--frontend-receipt-sha256', required=True)
        if action == 'adopt':
            command.add_argument('--admission', required=True); command.add_argument('--expected-admission-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, 'Explicit host administration requires root')
        load_sources(args.sources_manifest, args.expected_sources_sha256)
        if getattr(args, 'boot', False):
            boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            require(re.fullmatch('[0-9a-f-]{36}', boot_id), 'Invalid boot identity')
            args.operation_id = sha(canonical({'policy': args.expected_sha256, 'boot_id': boot_id}))[:32]
        with engine.Root('/') as root:
            if args.action == 'prepare':
                source = protected(args.policy_source)
                raw = source.read_bytes(); require(len(raw) <= MAX_BYTES, 'Policy source exceeds its bound')
                result = prepare(root, policy_bytes=raw, expected_sha256=args.expected_sha256, operation_id=args.operation_id)
            elif args.action == 'adopt':
                result = adoption.adopt(types.SimpleNamespace(**globals()), root, policy_path=args.policy,
                    expected_sha256=args.expected_sha256, operation_id=args.operation_id, entrypoint=str(Path(__file__).absolute()),
                    sources_manifest=args.sources_manifest, sources_sha256=args.expected_sources_sha256,
                    admission_path=args.admission, admission_sha256=args.expected_admission_sha256,
                    kernel_factory=Kernel, lookup=pwd.getpwnam, census=pwd.getpwall)
            elif args.action == 'activate':
                result = adoption.activate_fresh(types.SimpleNamespace(**globals()), root, policy_path=args.policy,
                    expected_sha256=args.expected_sha256, operation_id=args.operation_id, entrypoint=str(Path(__file__).absolute()),
                    sources_manifest=args.sources_manifest, sources_sha256=args.expected_sources_sha256,
                    kernel_factory=Kernel, lookup=pwd.getpwnam, census=pwd.getpwall)
            elif args.action == 'register-frontend':
                result = register_frontend(root, policy_path=args.policy, expected_sha256=args.expected_sha256,
                    operation_id=args.operation_id, consumer_id=args.consumer_id, frontend_operation_id=args.frontend_operation_id,
                    frontend_receipt_sha256=args.frontend_receipt_sha256)
            elif args.action == 'inspect':
                value = read_policy(root, args.policy, args.expected_sha256)
                result = {'provider': PROVIDER, 'version': VERSION, 'policy_sha256': args.expected_sha256,
                          'status': 'validated', 'interface': value['parameters']['interface'], 'kernel_observed': False}
            else:
                result = operate(root, policy_path=args.policy, expected_sha256=args.expected_sha256, action=args.action,
                    operation_id=getattr(args, 'operation_id', None), consumer_id=getattr(args, 'consumer_id', None),
                    account=getattr(args, 'account', None), unit=getattr(args, 'unit', None))
    except (ValueError, OSError, KeyError):
        parser.exit(1, 'QoS operation incomplete; retain durable intent and inspect its explicit precondition.\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
elif '_PINNED_MODULES' in globals():
    require(isinstance(_PINNED_MODULES, tuple) and len(_PINNED_MODULES) == 4,
            'Pinned QoS dependency closure is incomplete')
    engine, contract, adoption, processes = _PINNED_MODULES
else:
    load_sources()

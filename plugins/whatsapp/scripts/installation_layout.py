"""Public installation identity shared by setup and administrative operations.

This module has no imports from the application, no discovery, and no host
effects. An installation profile is public configuration, never a source of
credentials or executable commands. The legacy layout is selected explicitly
by compatibility callers; new setup uses a complete versioned profile.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


FORMAT = 'whatsapp-installation-v1'
PATH_FIELDS = ('project', 'configuration', 'state', 'gateway', 'backup',
               'administration_code', 'administration_state')
RESERVED_PATHS = frozenset(('/', '/etc', '/srv', '/opt', '/usr', '/usr/local',
    '/usr/local/lib', '/var', '/var/lib', '/var/backups', '/home', '/root', '/run', '/tmp',
    '/proc', '/sys', '/dev'))
RESERVED_ACCOUNTS = frozenset(('root', 'nobody', 'daemon', 'www-data'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical_path(value):
    require(isinstance(value, str) and len(value) <= 512
            and re.fullmatch(r'/[A-Za-z0-9_./-]+', value)
            and str(PurePosixPath(value)) == value
            and all(part not in ('', '.', '..') for part in value[1:].split('/')),
            'Installation paths must be canonical absolute POSIX paths')
    require(value not in RESERVED_PATHS, 'A shared system directory is not an installation root')
    require(not value.startswith(('/home/','/root/','/tmp/','/run/','/proc/','/sys/','/dev/','/var/tmp/')),
            'Installation roots must be durable and accessible with ProtectHome and PrivateTmp enabled')
    return value


def account_name(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', value)
            and value not in RESERVED_ACCOUNTS,
            'Select a dedicated non-root service account')
    return value


def unit_name(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value),
            'Select a literal service name without a suffix, template or command')
    return value


def slug_name(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9-]{1,19}', value)
            and '--' not in value, 'Invalid instance slug')
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode()


@dataclass(frozen=True)
class Installation:
    """Immutable public profile, bound by its canonical digest.

    Paths and identities may differ between hosts. Protected physical paths,
    instance isolation, root-owned administration and authenticated access
    remain requirements; this value alone does not attest those host facts.
    """
    _encoded: bytes
    compatibility: bool = False
    _roster: bytes | None = None

    @classmethod
    def from_dict(cls, value):
        require(isinstance(value, dict) and set(value) == {
            'format', 'paths', 'services', 'accounts', 'ports', 'authentication',
            'frontend'}, 'Unexpected installation profile fields')
        require(value['format'] == FORMAT, 'Unsupported installation profile format')
        paths = value['paths']
        require(isinstance(paths, dict) and set(paths) == set(PATH_FIELDS),
                'Declare every installation root')
        for path in paths.values():
            canonical_path(path)
        selected = list(paths.values())
        for index, left in enumerate(selected):
            for right in selected[index + 1:]:
                require(left != right and not left.startswith(right + '/')
                        and not right.startswith(left + '/'),
                        'Code, configuration, data, backups and administration roots must be separate')
        services = value['services']
        require(isinstance(services, dict) and set(services) == {'prefix', 'recovery'},
                'Declare the application prefix and dedicated recovery identity')
        for name in services.values():
            unit_name(name)
        account_name(services['prefix']+'-build')
        accounts = value['accounts']
        require(isinstance(accounts, dict) and accounts and len(accounts) <= 64,
                'Declare the service account for each initial instance')
        for slug, name in accounts.items():
            slug_name(slug)
            require(slug not in ('administration', 'backup'),
                    'Instance name collides with administrative paths or services')
            account_name(name)
        require(len(set(accounts.values())) == len(accounts),
                'Instances must not share a service account')
        require(services['recovery'] not in {services['prefix'] + '-' + slug for slug in accounts},
                'Recovery and bridge services must have distinct unit names')
        require(services['prefix']+'-build' not in accounts.values(),'Build and runtime accounts must differ')
        ports = value['ports']
        require(isinstance(ports, dict) and set(ports) == set(accounts),
                'Declare the bridge and gateway ports for every instance')
        used = set()
        for pair in ports.values():
            require(isinstance(pair, dict) and set(pair) == {'bridge', 'gateway'}
                    and all(type(port) is int and 1024 <= port <= 65535
                            for port in pair.values()),
                    'Select explicit unprivileged bridge and gateway ports')
            require(pair['bridge'] != pair['gateway'] and not used.intersection(pair.values()),
                    'Instance ports must be distinct')
            used.update(pair.values())
        require(value['authentication'] == 'external-oidc',
                'General setup requires an explicitly registered external OIDC provider')
        require(value['frontend'] in ('new', 'existing'),
                'Select a new or explicitly inventoried existing Apache HTTPS ingress')
        return cls(encoded(value))

    @classmethod
    def legacy(cls):
        """Fixed compatibility identity; never an implicit migration plan."""
        return cls(encoded({'format': 'whatsapp-installation-legacy-v1'}), True)

    def as_dict(self):
        # A fresh copy prevents a caller from mutating an admitted identity.
        return json.loads(self._encoded)

    def with_roster(self, value):
        """Attach a separately admitted, additive allocation snapshot.

        The original installation bytes and identity never change. This is a
        pure validator; operational callers obtain the snapshot only through
        the protected installed pointer, local compilers through explicit input.
        """
        require(not self.compatibility and isinstance(value, dict) and set(value) ==
                {'format', 'installation_sha256', 'revision', 'previous', 'instances'}
                and value['format'] == ROSTER_FORMAT and value['installation_sha256'] == self.sha256
                and type(value['revision']) is int and value['revision'] >= 1
                and (value['previous'] is None if value['revision'] == 1 else
                     isinstance(value['previous'], str) and re.fullmatch('[a-f0-9]{64}', value['previous'])),
                'Invalid installation allocation snapshot')
        additions = value['instances']
        baseline = self.as_dict()
        require(isinstance(additions, dict) and additions
                and not set(additions).intersection(baseline['accounts']),
                'An allocation snapshot cannot replace an initial instance')
        for slug, item in additions.items():
            require(slug not in ('administration', 'backup', 'personal'),
                    'Allocation name collides with administrative or preserved initial entry points')
            require(isinstance(item, dict) and set(item) == {'account', 'bridge', 'gateway'},
                    'Declare exactly the new account and its two ports')
            baseline['accounts'][slug] = item['account']
            baseline['ports'][slug] = {key: item[key] for key in ('bridge', 'gateway')}
        # Reuse all collision, reserved-name, root and maximum-count rules.
        Installation.from_dict(baseline)
        return Installation(self._encoded, False, encoded(value))

    @property
    def roster(self):
        return None if self._roster is None else json.loads(self._roster)

    @property
    def roster_sha256(self):
        return None if self._roster is None else hashlib.sha256(self._roster).hexdigest()

    @property
    def selection(self):
        return self.sha256, self.roster_sha256

    def accounts(self):
        require(not self.compatibility, 'Legacy accounts belong to their registered instances')
        result = self.as_dict()['accounts']
        result.update({slug: item['account'] for slug, item in
                       (self.roster or {}).get('instances', {}).items()})
        return result

    def roster_pointer(self):
        require(not self.compatibility, 'Legacy installations have no allocation pointer')
        return self.path('configuration') + '/administration/instance-roster.json'

    def roster_snapshot(self, digest):
        require(isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest),
                'An exact allocation snapshot digest is required')
        return self.path('configuration') + '/administration/instance-rosters/' + digest + '.json'

    @property
    def sha256(self):
        return hashlib.sha256(self._encoded).hexdigest()

    def path(self, field):
        require(field in PATH_FIELDS, 'Unknown installation root')
        if self.compatibility:
            return {'project': '/srv/openai-codex/projects/whatsapp-personal',
                'configuration': '/etc', 'state': '/var/lib', 'gateway': '/var/lib',
                'backup': '/var/backups/whatsapp-personal',
                'administration_code': '/usr/local/lib/develative-deploy',
                'administration_state': '/var/lib/develative-deploy'}[field]
        return self.as_dict()['paths'][field]

    def service(self, slug):
        slug_name(slug)
        if self.compatibility:
            return 'whatsapp-personal' if slug == 'personal' else 'whatsapp-' + slug
        return self.as_dict()['services']['prefix'] + '-' + slug

    def account(self, slug):
        slug_name(slug)
        if self.compatibility:
            return 'whatsappbridge' if slug == 'personal' else 'wa-' + slug
        require(slug in self.accounts(), 'Instance is absent from the installation profile or admitted roster')
        return self.accounts()[slug]

    def instance_paths(self, slug):
        slug_name(slug)
        if self.compatibility:
            base = self.service(slug)
            return {'configuration': '/etc/' + base, 'state': '/var/lib/' + base,
                    'gateway': '/var/lib/' + base + '-waha'}
        return {field: self.path(field) + '/' + slug
                for field in ('configuration', 'state', 'gateway')}

    def instance_ports(self, slug):
        slug_name(slug)
        require(not self.compatibility, 'Legacy ports belong to the existing instance record')
        if slug in self.as_dict()['ports']:
            return self.as_dict()['ports'][slug]
        item = (self.roster or {}).get('instances', {}).get(slug)
        require(item is not None, 'Instance is absent from the installation profile or admitted roster')
        return {key: item[key] for key in ('bridge', 'gateway')}

    def mapped(self, value):
        """Translate only reviewed historical destinations, preserving suffixes.

        Callers still own their finite command and source policies. This does
        not admit a destination from bundle metadata or execute profile input.
        """
        if self.compatibility:
            return value
        replacements = {
            '/srv/openai-codex/projects/whatsapp-personal': self.path('project'),
            '/usr/local/lib/develative-deploy': self.path('administration_code'),
            '/var/lib/develative-deploy': self.path('administration_state'),
            '/etc/develative-deploy': self.path('configuration') + '/administration',
            '/var/lib/develative-release-gates/whatsapp': self.path('state') + '/.release-gates/whatsapp',
            '/var/backups/whatsapp-personal': self.path('backup'),
            '/opt/develative-releases': self.path('administration_state') + '/builds',
            'develative-release-build': self.as_dict()['services']['prefix'] + '-build',
            'develative-whatsapp-recovery': self.as_dict()['services']['recovery'],
            'whatsapp-personal-backup': self.as_dict()['services']['prefix'] + '-backup',
        }
        for slug in self.accounts():
            old = Installation.legacy().instance_paths(slug)
            new = self.instance_paths(slug)
            replacements.update({old[field]: new[field] for field in old})
            replacements[Installation.legacy().service(slug)]=self.service(slug)
        for root in self.as_dict()['paths'].values():
            if root not in replacements:replacements[root]=root
        # A longest-first single pass avoids remapping replacement strings.
        pattern = '|'.join(re.escape(key) for key in sorted(replacements, key=len, reverse=True))
        return re.sub(pattern, lambda match: replacements[match.group()], value)


# This is a public, root-owned locator, not an environment variable or secret.
# Moving an installation requires a reviewed migration; a malformed/present
# locator must never fall back to a different installation's legacy paths.
PROFILE = Path('/etc/whatsapp-installation.json')
MAX_PROFILE_BYTES = 128 * 1024
_selected = None
_locator_state = None
_installed_context = None


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate installation profile field')
        result[key] = value
    return result


IDENTITY = Path('/etc/whatsapp-installation-identity.json')
IDENTITY_FORMAT = 'whatsapp-installation-identity-v1'
ROSTER_FORMAT = 'whatsapp-instance-roster-v1'
ROSTER_POINTER_FORMAT = 'whatsapp-instance-roster-pointer-v1'


def roster_pointer_record(profile):
    require(profile.roster is not None, 'An allocation snapshot is required')
    return {'format': ROSTER_POINTER_FORMAT, 'installation_sha256': profile.sha256,
            'snapshot_sha256': profile.roster_sha256}


def read_roster(profile, *, root=Path('/'), trusted_uid=0):
    if profile.compatibility:
        return profile
    pointer = Path(root) / profile.roster_pointer().lstrip('/')
    if not os.path.lexists(pointer):
        return profile
    raw = _read_protected(pointer, trusted_uid=trusted_uid, trust_root=root)
    value = json.loads(raw, object_pairs_hook=unique_fields)
    require(isinstance(value, dict) and set(value) ==
            {'format', 'installation_sha256', 'snapshot_sha256'}
            and value['format'] == ROSTER_POINTER_FORMAT
            and value['installation_sha256'] == profile.sha256,
            'Allocation pointer belongs to another installation')
    snapshot = Path(root) / profile.roster_snapshot(value['snapshot_sha256']).lstrip('/')
    content = _read_protected(snapshot, trusted_uid=trusted_uid, trust_root=root)
    require(hashlib.sha256(content).hexdigest() == value['snapshot_sha256'],
            'Allocation snapshot differs from its protected pointer')
    selected = profile.with_roster(json.loads(content, object_pairs_hook=unique_fields))
    require(content == selected._roster and raw == encoded(roster_pointer_record(selected)),
            'Allocation snapshot and pointer must have canonical bytes')
    require(raw == _read_protected(pointer, trusted_uid=trusted_uid, trust_root=root),
            'Allocation pointer changed while reading')
    return selected


def identity_record(profile):
    """Public identity pin, installed separately from the mutable locator.

    The initial mode is an explicit setup choice. Losing both files is an
    error, never evidence that an existing installation uses legacy paths.
    """
    require(isinstance(profile, Installation), 'A validated installation identity is required')
    return {'format': IDENTITY_FORMAT,
            'mode': 'legacy' if profile.compatibility else 'configured',
            'installation_sha256': profile.sha256}


def identity_bytes(profile):
    return encoded(identity_record(profile))


def _read_protected(path, *, trusted_uid=0, trust_root=Path('/')):
    """Bounded no-follow read; fixture seams never come from environment input."""
    path, trust_root = Path(path), Path(trust_root)
    require(trust_root.is_absolute() and trust_root == trust_root.resolve(strict=True),
            'Installation trust root must be a physical absolute directory')
    require(path.is_absolute() and path == path.resolve(strict=True),
            'Installation file must have a physical absolute path')
    relative = path.relative_to(trust_root)
    current = trust_root
    for index, part in enumerate(('', *relative.parts)):
        if part:
            current /= part
        info = current.lstat()
        expected = stat.S_ISREG if index == len(relative.parts) else stat.S_ISDIR
        require(expected(info.st_mode) and info.st_uid == trusted_uid and not info.st_mode & 0o022,
                'Installation file and ancestors must be administratively protected')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == trusted_uid
                and not before.st_mode & 0o022, 'Installation file must be administratively protected')
        raw = stream.read(131073)
        after = os.fstat(stream.fileno())
    now = path.lstat()
    signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    require(signature(before) == signature(after) == signature(now) and len(raw) <= 131072,
            'Installation file changed or exceeded its bound')
    return raw


def read_profile(path, *, expected_sha256=None, trusted_uid=0, trust_root=Path('/')):
    raw = _read_protected(path, trusted_uid=trusted_uid, trust_root=trust_root)
    require(expected_sha256 is None or hashlib.sha256(raw).hexdigest() == expected_sha256,
            'Installation profile differs from the reviewed digest')
    return Installation.from_dict(json.loads(raw, object_pairs_hook=unique_fields))


def read_identity(path, *, trusted_uid=0, trust_root=Path('/')):
    value = json.loads(_read_protected(path, trusted_uid=trusted_uid, trust_root=trust_root),
                       object_pairs_hook=unique_fields)
    require(isinstance(value, dict) and set(value) == {'format', 'mode', 'installation_sha256'}
            and value['format'] == IDENTITY_FORMAT and value['mode'] in ('legacy', 'configured')
            and isinstance(value['installation_sha256'], str)
            and re.fullmatch('[a-f0-9]{64}', value['installation_sha256']),
            'Invalid installation identity record')
    require(value['mode'] != 'legacy' or value == identity_record(Installation.legacy()),
            'Legacy installation identity differs from the explicit compatibility profile')
    return value


def read_installation(*, root=Path('/'), trusted_uid=0):
    """Read an installed identity before importing dependent operational modules.

    ``root``/uid are explicit filesystem-fixture seams. Privileged entry points
    use the default physical host root and root ownership, never environment
    variables, request fields or bundle-supplied installation selectors.
    """
    root = Path(root)
    marker = root / IDENTITY.relative_to('/')
    locator = root / PROFILE.relative_to('/')
    require(os.path.lexists(marker),
            'Installation identity is missing; explicit installation or legacy adoption is required')
    try:
        identity = read_identity(marker, trusted_uid=trusted_uid, trust_root=root)
        if identity['mode'] == 'legacy':
            require(not os.path.lexists(locator),
                    'Legacy installation identity conflicts with a configured locator')
            profile = Installation.legacy()
        else:
            require(os.path.lexists(locator), 'Configured installation locator is missing')
            profile = read_profile(locator, trusted_uid=trusted_uid, trust_root=root)
        require(identity == identity_record(profile),
                'Installation locator differs from the independently pinned identity')
        profile = read_roster(profile, root=root, trusted_uid=trusted_uid)
        require(identity == read_identity(marker, trusted_uid=trusted_uid, trust_root=root),
                'Installation identity changed during the read')
    except OSError as error:
        raise ValueError('Installation identity or locator became unavailable') from error
    return profile


def activate_installation(*, root=Path('/'), trusted_uid=0):
    """Pin a protected installed identity and retain checks after bootstrap.

    Unlike local ``select``, this binds subsequent calls to the same physical
    root and owner policy. Operational entry points keep the default host root;
    alternate roots are explicit inspect/test fixtures, never request input.
    """
    global _selected, _locator_state, _installed_context
    profile = read_installation(root=root, trusted_uid=trusted_uid)
    context = (Path(root), trusted_uid)
    require(_selected is None or _selected.selection == profile.selection,
            'Installation identity is already pinned in this process')
    require(_installed_context is None or _installed_context == context,
            'Installed identity context is already pinned in this process')
    _selected = profile
    _locator_state = profile.selection
    _installed_context = context
    return profile


def active():
    global _selected, _locator_state
    # A local compiler/test process may select an identity explicitly. Installed
    # callers never gain implicit legacy mode from an absent or damaged file.
    if _selected is None:
        _selected = read_installation()
        _locator_state = _selected.selection
    elif _locator_state is not None:
        current = (read_installation() if _installed_context is None else
                   read_installation(root=_installed_context[0], trusted_uid=_installed_context[1]))
        require(current.selection == _locator_state == _selected.selection
                and current.compatibility == _selected.compatibility,
                'Installation identity or locator changed during this operation')
    return _selected


def select(profile):
    """Select an already validated identity for a local compiler/test process.

    The installed entry points read PROFILE; callers must not expose selection
    through request data, environment variables or unreviewed bundle metadata.
    """
    global _selected
    require(isinstance(profile, Installation), 'A validated installation identity is required')
    require(_selected is None or _selected.selection == profile.selection,
            'Installation identity is already pinned in this process')
    _selected = profile
    return profile


def mapped(value):
    return active().mapped(value)


def gateway_port(slug,bridge_port):
    profile=active()
    return bridge_port+1 if profile.compatibility else profile.instance_ports(slug)['gateway']


def preflight_roots(profile=None,*,root=Path('/'),trusted_uid=0):
    """Inspect declared roots only, before provisioning reads or mutations.

    Parent creation/repair belongs to the explicit installation preparation.
    Existing roots must remain physical, administrative and non-writable by
    runtime accounts. Fixture callers can anchor the same check below root.
    """
    profile=active() if profile is None else profile
    if profile.compatibility:return
    root=Path(root).absolute()
    require(root==root.resolve(strict=True),'Physical installation inspection root required')
    for value in profile.as_dict()['paths'].values():
        target=root/value.lstrip('/')
        require(target==target.resolve(strict=True),'Configured roots must be physical existing directories')
        current=root
        for part in ('',*target.relative_to(root).parts):
            if part:current/=part
            info=current.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==trusted_uid and not info.st_mode&0o022,
                    'Prepare the declared protected installation roots before provisioning')

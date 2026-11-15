"""Isolated Certbot store and finite Apache-only deployment; no global hooks.

The host administrator separately installs protected directories, an ACME account,
reviewed plan and timer. This module never installs those prerequisites itself.
"""
import argparse
import configparser
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

CONFIG = '/etc/develative-certificates'
WORK = '/var/lib/develative-certificates'
LOGS = '/var/log/develative-certificates'
SERVER = 'https://acme-v02.api.letsencrypt.org/directory'
SOURCES = ('host/frontend/certificates.py', 'host/frontend/adapter.py',
           'host/frontend/provider.py', 'host/lifecycle/filesystem.py')
TOOLS = {'certbot': '/usr/bin/certbot', 'systemd-run': '/usr/bin/systemd-run',
         'systemctl': '/usr/bin/systemctl'}


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def sha(body):
    return hashlib.sha256(body).hexdigest()


def validate(plan):
    require(isinstance(plan, dict) and set(plan) == {'format', 'account', 'tools', 'lineages'}
            and type(plan['format']) is int and plan['format'] == 1, 'Invalid isolated certificate plan')
    require(isinstance(plan['account'], str) and re.fullmatch('[a-f0-9]{32}', plan['account']),
            'Nominate a previously registered isolated ACME account')
    require(isinstance(plan['tools'], dict) and set(plan['tools']) == set(TOOLS), 'Pin all certificate tools')
    for name, item in plan['tools'].items():
        require(isinstance(item, dict) and set(item) == {'path', 'sha256'} and item['path'] == TOOLS[name]
                and isinstance(item['sha256'], str) and re.fullmatch('[a-f0-9]{64}', item['sha256']),
                'Invalid certificate tool identity')
    require(isinstance(plan['lineages'], dict) and 0 < len(plan['lineages']) <= 64, 'Declare bounded isolated lineages')
    consumers = set()
    for name, item in plan['lineages'].items():
        require(isinstance(name, str) and len(name) <= 253 and '.' in name and all(
            re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in name.split('.')),
            'Use exact DNS certificate names')
        require(isinstance(item, dict) and set(item) == {'consumer', 'webroot'}
                and re.fullmatch(r'(?:host|whatsapp)\.[a-z][a-z0-9.-]*', item['consumer'])
                and re.fullmatch(r'/var/www/[a-zA-Z0-9_-]+', item['webroot'])
                and item['consumer'] not in consumers, 'Declare a distinct finite consumer and webroot')
        consumers.add(item['consumer'])
    return plan


class Certificates:
    def __init__(self, adapter, plan):
        self.adapter, self.root = adapter, adapter.root
        self.plan = copy.deepcopy(validate(plan))
        self.plan_sha = sha(encoded(plan))

    def _protected(self, name, *, directory=False):
        info = self.root.directory(name) if directory else self.root.snapshot(name)
        require(info is not None and info['uid'] == self.root.uid and not info['mode'] & 0o022,
                'Certificate prerequisite is absent or unprotected')
        return info

    def _names(self, name):
        self._protected(name, directory=True)
        with self.root._parent(name) as (parent, leaf):
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try: return sorted(os.listdir(fd))
            finally: os.close(fd)

    def audit(self):
        for name in ('/etc/letsencrypt', '/var/lib/letsencrypt', '/var/log/letsencrypt', CONFIG, WORK, LOGS, WORK+'/operations', CONFIG+'/renewal', CONFIG+'/accounts'):
            self._protected(name, directory=True)
        for name in ('pre', 'deploy', 'post'):
            require(not self._names(CONFIG+'/renewal-hooks/'+name), 'Isolated directory hooks must be empty')
        require(self.root.read_bytes(CONFIG+'/cli.ini') == b'', 'Isolated CLI configuration must be empty')
        self._protected(CONFIG+'/cli.ini')
        self._protected(CONFIG+'/accounts/acme-v02.api.letsencrypt.org/directory/'+self.plan['account'], directory=True)
        for item in self.plan['tools'].values():
            info = self._protected(item['path'])
            require(info['sha256'] == item['sha256'] and info['mode'] & 0o100, 'Certificate executable changed')
        for name in self.plan['lineages']:
            require(self.root.snapshot('/etc/letsencrypt/renewal/'+name+'.conf') is None,
                    'This hostname is still scheduled by global Certbot; require a separate reviewed migration')
        for filename in self._names(CONFIG+'/renewal'):
            require(filename.endswith('.conf') and filename[:-5] in self.plan['lineages'],
                    'Foreign or mixed renewal inventory in isolated store')
            self._renewal(filename[:-5])

    def _renewal(self, name):
        path = CONFIG+'/renewal/'+name+'.conf'
        self._protected(path)
        raw = self.root.read_bytes(path, max_bytes=128*1024).decode()
        parser = configparser.RawConfigParser(strict=True)
        parser.read_string('[lineage]\n'+raw)
        require(not parser.defaults(), 'Unexpected renewal defaults')
        require(set(parser.sections()) <= {'lineage', 'renewalparams', '[webroot_map]'}
                and 'renewalparams' in parser, 'Unknown renewal section')
        for section in parser.values():
            for key, value in section.items():
                if 'hook' in key.lower():
                    require(key.lower() in ('pre_hook', 'post_hook', 'deploy_hook', 'renew_hook')
                            and value.strip() in ('', '""', "''"),
                            'Executable or unknown persisted certificate hooks are forbidden')
        params = parser['renewalparams']
        require(all(params.get(key, value) == value for key, value in
                    (('config_dir', CONFIG), ('work_dir', WORK), ('logs_dir', LOGS))),
                'Persisted renewal store differs')
        require(params.get('authenticator') == 'webroot'
                and params.get('installer', 'None').lower() == 'none'
                and params.get('account') == self.plan['account'] and params.get('server') == SERVER,
                'Renewal authenticator, installer, account or server differs')
        expected = {'archive_dir': CONFIG+'/archive/'+name, 'cert': CONFIG+'/live/'+name+'/cert.pem',
                    'privkey': CONFIG+'/live/'+name+'/privkey.pem', 'chain': CONFIG+'/live/'+name+'/chain.pem',
                    'fullchain': CONFIG+'/live/'+name+'/fullchain.pem'}
        require(all(parser['lineage'].get(k) == v for k, v in expected.items()), 'Renewal paths leave exact isolated lineage')
        webroot = self.plan['lineages'][name]['webroot']
        require(params.get('webroot_path', '').rstrip(', ') == webroot,
                'Renewal webroot differs')
        if '[webroot_map]' in parser:
            require(dict(parser['[webroot_map]']) in ({}, {name: webroot}), 'Mixed renewal webroot/SAN mapping')

    def _material(self, name, *, previous=False):
        bodies, revisions = {}, []
        for kind, prefix in (('certificate', 'fullchain'), ('key', 'privkey')):
            link = self.root.link(CONFIG+'/live/'+name+'/'+prefix+'.pem')
            require(link is not None and link['uid'] == self.root.uid, 'Missing protected isolated certificate link')
            target = os.path.normpath(CONFIG+'/live/'+name+'/'+link['target'])
            match = re.fullmatch(re.escape(CONFIG+'/archive/'+name+'/'+prefix)+r'([1-9][0-9]*)\.pem', target)
            require(match, 'Certificate link leaves exact isolated archive')
            info = self._protected(target)
            require(kind != 'key' or info['mode'] in (0o600, 0o640), 'Unsafe isolated private key mode')
            bodies[kind] = self.root.read_bytes(target, max_bytes=1024*1024)
            require(self.root.snapshot(target) == info, 'Certificate changed during capture')
            revisions.append(match.group(1))
        require(len(set(revisions)) == 1, 'Isolated certificate/key generations differ')
        self.adapter.validate_certificate_pair(bodies['certificate'], bodies['key'], [name], allow_expired=previous)
        return sha(bodies['certificate'])

    def _fingerprint(self, name, *, previous=False):
        if self.root.link(CONFIG+'/live/'+name+'/fullchain.pem') is None: return None
        return self._material(name, previous=previous)

    def command(self, name, action, unit):
        require(name in self.plan['lineages'] and action in ('issue', 'renew'), 'Unknown certificate request')
        require(re.fullmatch('develative-certificates-client-[a-f0-9]{32}', unit), 'Invalid certificate unit')
        webroot = self.plan['lineages'][name]['webroot']
        # ConfigArgParse may also read default files despite --config. Hide the
        # global store and both default user configuration paths in the unit.
        properties = {'Type': 'exec', 'UMask': '0077', 'NoNewPrivileges': 'yes', 'PrivateTmp': 'yes',
            'ProtectHome': 'yes', 'ProtectSystem': 'strict', 'PrivateDevices': 'yes',
            'TemporaryFileSystem': '/etc/letsencrypt:ro /var/lib/letsencrypt:ro /var/log/letsencrypt:ro',
            'ReadWritePaths': ' '.join((CONFIG, WORK, LOGS, webroot)),
            'Environment': 'HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent PATH=/usr/bin:/bin',
            'RuntimeMaxSec': '600', 'TimeoutStopSec': '30', 'KillMode': 'control-group'}
        args = [TOOLS['systemd-run'], '--quiet', '--wait', '--pipe', '--collect', '--unit='+unit]
        for key, value in properties.items(): args.extend(('--property', key+'='+value))
        args.extend((TOOLS['certbot'], 'certonly' if action == 'issue' else 'renew',
            '--config', CONFIG+'/cli.ini', '--config-dir', CONFIG, '--work-dir', WORK, '--logs-dir', LOGS,
            '--no-directory-hooks', '--non-interactive', '--server', SERVER, '--account', self.plan['account'],
            '--authenticator', 'webroot', '--webroot-path', webroot, '--cert-name', name,
            '--pre-hook', '', '--post-hook', '', '--deploy-hook', ''))
        if action == 'issue': args.extend(('--keep-until-expiring', '-d', name))
        else: args.append('--no-random-sleep-on-renew')
        return args

    def _record(self, name): return WORK+'/operations/'+name+'.json'

    def _save(self, name, record):
        # Replace + fsync in an already protected directory. Keep the journal
        # separate from frontend receipts, whose schema has different phases.
        destination = self._record(name)
        with self.root._parent(destination) as (parent, leaf):
            temporary = '.'+leaf+'.'+uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(encoded(record)); stream.flush(); os.fsync(stream.fileno())
                os.rename(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent); os.fsync(parent)
            finally:
                try: os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError: pass

    def _load(self, name):
        info = self.root.snapshot(self._record(name))
        if info is None: return None
        require(info['uid'] == self.root.uid and info['mode'] == 0o600, 'Unsafe certificate journal')
        record = json.loads(self.root.read_bytes(self._record(name)))
        require(set(record) == {'plan_sha256', 'domain', 'action', 'phase', 'unit', 'before', 'profile_update'}
                and record['plan_sha256'] == self.plan_sha and record['domain'] == name
                and record['action'] in ('issue', 'renew')
                and record['phase'] in ('requesting', 'deployment-pending', 'complete')
                and re.fullmatch('develative-certificates-client-[a-f0-9]{32}', record['unit']),
                'Certificate journal belongs to another plan or has unknown phase')
        return record

    def _inactive(self, unit):
        body = self.adapter.runner.run([self.adapter._tool('systemctl'), 'list-units', '--all', '--plain',
            '--no-legend', '--no-pager', unit+'.service'], environment=self.adapter.environment,
            timeout=30, pass_fds=(self.adapter.lock_fd,)).decode().strip()
        if body:
            parts = body.split()
            require(len(parts) >= 4 and parts[0] == unit+'.service' and parts[2] in ('inactive', 'failed'),
                    'Certificate client still running or cannot be classified; preserve journal')

    def _pin_renewal(self, name, record):
        # Certbot can rewrite renewal metadata. Pin the audited current bytes so
        # later retirement checks retain an exact identity. Persist the original
        # filesystem plan before touching the protected frontend profile.
        profile_path = '/etc/develative-host-frontend/profile.json'
        lineage = CONFIG+'/live/'+name
        if lineage not in self.adapter.profile['lineages']: return
        current = self.root.snapshot(CONFIG+'/renewal/'+name+'.conf')
        update = record['profile_update']
        if update is None:
            expected = self.adapter.profile['lineages'][lineage]['renewal']['sha256']
            if expected == current['sha256']: return
            profile = copy.deepcopy(self.adapter.profile)
            profile['lineages'][lineage]['renewal']['sha256'] = current['sha256']
            update = {'before': self.root.snapshot(profile_path), 'after': encoded(profile).decode(),
                      'operation_id': uuid.uuid4().hex}
            record['profile_update'] = update; self._save(name, record)
        before = {'format': 1, 'owner': 'host', 'files': {profile_path: {**update['before'], 'retention': 'managed'}},
                  'directories': {}}
        expected_profile = copy.deepcopy(self.adapter.profile)
        expected_profile['lineages'][lineage]['renewal']['sha256'] = current['sha256']
        require(update['after'] == encoded(expected_profile).decode(), 'Pending renewal pin has unrelated profile changes')
        body = update['after'].encode()
        after = {**before, 'files': {profile_path: {**update['before'], 'sha256': sha(body), 'retention': 'managed'}}}
        self.adapter.engine.reconcile(self.root, operation_id=update['operation_id'], before=before,
            after=after, payloads={profile_path: body}, allowed_paths={profile_path}, inline_payloads={profile_path})
        self.adapter.profile = json.loads(body)

    def _deploy(self, name, record):
        lineage = CONFIG+'/live/'+name
        registry = self.adapter.registry
        item = self.plan['lineages'][name]
        if record['action'] == 'issue' and lineage not in registry['lineages']:
            # The app/IdP frontend must bind and validate this exact certificate
            # separately; issuance alone never fabricates an active consumer.
            return {'status': 'issued-unbound', 'domain': name}
        require(lineage in registry['lineages'] and registry['lineages'][lineage]['domains'] == [name]
                and registry['lineages'][lineage]['consumers'] == [item['consumer']]
                and registry['consumers'][item['consumer']]['status'] == 'active',
                'No exact active isolated consumer; never delegate to legacy hooks')
        result = self.adapter.provider.handle_deploy_hook(registry, lineage=lineage,
                    renewed_domains=name, adapter=self.adapter)
        require(result.get('status') == 'complete', 'Isolated certificate deployment incomplete')
        return result

    def run(self, name, action):
        require(name in self.plan['lineages'] and action in ('issue', 'renew'), 'Unknown isolated certificate')
        self.adapter._admitted(); self.adapter.assert_registry_current(); self.audit()
        require(self.root.read_bytes('/etc/develative-host-frontend/profile.json') == encoded(self.adapter.profile),
                'Frontend profile changed before certificate admission')
        record = self._load(name)
        if action == 'renew' and (record is None or record['phase'] == 'complete'):
            lineage = CONFIG+'/live/'+name
            consumer = self.plan['lineages'][name]['consumer']
            current = self.adapter.registry['consumers'].get(consumer)
            require(current is not None and current['domains'] == [name], 'Isolated consumer is missing or changed')
            if current['status'] == 'retired': return {'status': 'skipped-retired', 'domain': name}
            require(current['status'] == 'active' and current['lineages'] == [lineage],
                    'Bind the exact isolated consumer before scheduling renewal')
        if record is None or record['phase'] == 'complete':
            self.adapter.provider.guard_pending(self.root, engine=self.adapter.engine)
            self._protected(self.plan['lineages'][name]['webroot'], directory=True)
            if action == 'issue':
                for consumer_id, consumer in self.adapter.registry['consumers'].items():
                    if name in consumer['domains']:
                        require(consumer_id == self.plan['lineages'][name]['consumer']
                                and consumer['lineages'] in ([], [CONFIG+'/live/'+name]),
                                'Hostname belongs to a different consumer or certificate store')
            before = self._fingerprint(name, previous=True)
            require(action != 'renew' or before is not None, 'Renewal cannot silently issue an absent lineage')
            record = {'plan_sha256': self.plan_sha, 'domain': name, 'action': action, 'phase': 'requesting',
                      'unit': 'develative-certificates-client-'+uuid.uuid4().hex, 'before': before, 'profile_update': None}
            self._save(name, record)
            # A supervisor retains the frontend lease until the systemd-run
            # client exits; the durable unit name covers detached service loss.
            self.adapter.runner.run(self.command(name, action, record['unit']),
                environment=self.adapter.environment, timeout=650, pass_fds=(self.adapter.lock_fd,))
            self.audit()
            require(self._fingerprint(name) is not None, 'Certificate client returned without a verified lineage')
            record['phase'] = 'deployment-pending'; self._save(name, record)
        elif record['phase'] == 'requesting':
            self._inactive(record['unit'])
            fingerprint = self._fingerprint(name)
            require(fingerprint is not None and fingerprint != record['before'],
                    'Certificate request outcome uncertain; inspect journal, do not blindly reissue')
            record['phase'] = 'deployment-pending'; self._save(name, record)
        require(self._fingerprint(name) is not None, 'Certificate material is absent before deployment')
        self._pin_renewal(name, record)
        result = self._deploy(name, record)
        record['phase'] = 'complete'; self._save(name, record)
        return result


    def run_many(self, names, action):
        """Try independent names; every attempt still rechecks shared admission.

        A network/issuance failure does not starve unrelated lineages. A pending
        frontend receipt or changed shared profile still blocks their effects.
        """
        results = []
        failed = False
        for name in names:
            try:
                results.append({'domain': name, **self.run(name, action)})
            except Exception as error:
                failed = True
                results.append({'domain': name, 'status': 'blocked', 'errorType': type(error).__name__})
        return results, failed


def render_units(generation, source_sha256, plan_path, plan_sha256):
    """Pure local preparation; never installs/enables a service or timer."""
    require(re.fullmatch('/usr/local/lib/develative-host-components/[a-f0-9]{64}', generation)
            and re.fullmatch('[a-f0-9]{64}', source_sha256)
            and re.fullmatch('[a-f0-9]{64}', plan_sha256)
            and plan_path == CONFIG+'/plan.json', 'Use an exact pinned generation and private plan')
    service = ('[Unit]\nDescription=Isolated host certificate renewal\nAfter=network-online.target\n'
        '[Service]\nType=oneshot\nUser=root\nUMask=0077\nKillMode=control-group\nTimeoutStartSec=2400\n'
        'ExecStart=/usr/bin/python3 -I -B '+generation+'/host/frontend/certificates.py renew'
        ' --plan '+plan_path+' --plan-sha256 '+plan_sha256+' --source-manifest '+generation+
        '/certificates-sources.json --source-sha256 '+source_sha256+'\n')
    timer = ('[Unit]\nDescription=Renew only the isolated certificate store\n[Timer]\n'
        'OnCalendar=*-*-* 03,15:15:00\nRandomizedDelaySec=1800\nPersistent=true\n'
        'Unit=develative-isolated-certificates.service\n[Install]\nWantedBy=timers.target\n')
    return {'develative-isolated-certificates.service': service, 'develative-isolated-certificates.timer': timer}


def _bootstrap(manifest_path, expected):
    def read(path):
        path = Path(path).absolute()
        for item in (path, *path.parents):
            info = item.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'Certificate bootstrap requires protected physical source')
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 16*1024*1024, 'Bounded regular certificate source required')
        return path.read_bytes()
    raw = read(manifest_path)
    require(sha(raw) == expected, 'Certificate source manifest differs')
    manifest = json.loads(raw)
    require(set(manifest) == {'format', 'sources'} and manifest['format'] == 1
            and set(manifest['sources']) == set(SOURCES), 'Exact certificate source closure required')
    base = Path(__file__).absolute().parents[2]
    sources = {name: read(base/name) for name in SOURCES}
    require(all(sha(body) == manifest['sources'][name] for name, body in sources.items()), 'Certificate source drift')
    require(sources['host/frontend/certificates.py'] == read(Path(__file__).absolute()), 'Certificate entry differs')
    modules = {}
    for name, relative in (('provider','host/frontend/provider.py'), ('engine','host/lifecycle/filesystem.py'),
                           ('adapter','host/frontend/adapter.py')):
        scope = {'__name__': 'isolated_certificates_'+name, '__file__': str(base/relative)}
        if name == 'adapter': scope['_PINNED_PROVIDER'] = modules['provider']
        exec(compile(sources[relative], str(base/relative), 'exec'), scope)
        modules[name] = type('Module', (), scope)
    return modules


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('issue', 'renew'))
    parser.add_argument('--name')
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--source-manifest', required=True)
    parser.add_argument('--source-sha256', required=True)
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, 'Certificate operations require an existing root administrative context')
    modules = _bootstrap(args.source_manifest, args.source_sha256)
    front, engine = modules['adapter'], modules['engine']
    with engine.Root('/') as root:
        raw = root.read_bytes(args.plan, max_bytes=128*1024)
        require(sha(raw) == args.plan_sha256 and root.snapshot(args.plan)['mode'] == 0o600
                and root.snapshot(args.plan)['uid'] == 0, 'Certificate plan differs or is unprotected')
        plan = validate(json.loads(raw))
        registry = front.load_protected_json(root, front.REGISTRY)
        profile = front.load_protected_json(root, front.PROFILE)
        adapter = front.HostAdapter(root, engine, registry, profile)
        with adapter.lease():
            adapter.assert_registry_current()
            worker = Certificates(adapter, plan)
            names = [args.name] if args.name else sorted(plan['lineages'])
            require(args.action != 'issue' or args.name, 'First issuance requires an explicit single name')
            results, failed = worker.run_many(names, args.action)
        print(json.dumps(results))
        return 1 if failed else 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        raise SystemExit('Isolated certificates stopped: '+type(error).__name__) from None

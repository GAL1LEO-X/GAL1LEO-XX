"""Synthetic host boundary for browser tests of the real UNIX broker."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sqlite3
from threading import Event, Thread
import time

from sally_whatsapp.admin_broker import AdminBrokerClient


class SyntheticAdminHost:
    def __init__(self, root, owner, *, hold=False):
        root.mkdir(mode=0o700)
        source = Path(__file__).resolve().parents[2] / 'plugins/whatsapp/scripts/web_admin_broker.py'
        spec = importlib.util.spec_from_file_location('browser_synthetic_web_broker', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # The fixture's trust root/UID are isolated from the real host; production
        # CLI has no option to alter these constants or the dispatcher.
        module.TRUST_ROOT, module.TRUST_UID = root, os.getuid()
        self.release, self.effects = Event(), []
        self.approval, self.root = secrets.token_hex(16), root
        self.restore_approvals = [
            {'approval': secrets.token_hex(16), 'description': 'Ripristina snapshot sintetico del 20 ottobre: conserva preimmagini.'},
            {'approval': secrets.token_hex(16), 'description': '<img src=x onerror="window.adminDescriptionExecuted=true"> Snapshot sintetico del 21 ottobre.'},
        ]
        state = root / 'host-ledger'
        state.mkdir(mode=0o700)
        self.state = state
        policy = {'format': module.FORMAT, 'enabled': True, 'project': str(root / 'project'),
            'installation_sha256': 'a'*64, 'owner': {'protocol': 1, 'epoch': 'b'*32, 'state': 'dedicated',
                'generation': str(root / 'generation'), 'manifest_sha256': 'c'*64},
            'sources': {'scripts/synthetic.py': 'd'*64}, 'state_directory': str(state),
            'socket': '/run/synthetic-browser-only.sock', 'socket_gid': os.getgid(),
            'principals': [{'uid': os.getuid(), 'owner': owner, 'instance': 'alpha',
                'targets': ['alpha', 'beta'], 'operations': ['release.activate', 'backup.restore'], 'global_admin': True}],
            'approvals': {self.approval: {'uid': os.getuid(), 'operation': 'release.activate',
                'target': 'installation', 'scope': 'installation', 'affected_instances': ['alpha', 'beta'],
                'description': 'Synthetic shared update', 'expires': time.time()+3600,
                'parameters': {'request': {'path': str(root / 'synthetic-request.json'), 'sha256': 'e'*64}}}}}
        for index, proposed in enumerate(self.restore_approvals):
            policy['approvals'][proposed['approval']] = {
                'uid': os.getuid(), 'operation': 'backup.restore', 'target': 'alpha',
                'scope': 'instance', 'affected_instances': ['alpha'], 'description': proposed['description'],
                'expires': time.time()+3600,
                'parameters': {'plan': {'path': str(root / f'synthetic-restore-{index}.json'), 'sha256': str(index)*64}},
            }
        policy_path = root / 'policy.json'
        policy_path.write_bytes(module.encoded(policy))
        policy_path.chmod(0o600)
        def execute(policy, identifier, lease):
            self.effects.append(identifier)
            (root / 'effect').write_text(identifier)
            if hold:
                assert self.release.wait(30)
            approved = policy['approvals'][identifier]
            return {'completed': True, 'operation': approved['operation'], 'target': approved['target']}
        broker = module.Broker(policy_path, executor=execute, preflight=lambda *_: None)
        endpoint = root / 'rpc.sock'
        self.server = module.Server(str(endpoint), module.Handler)
        endpoint.chmod(0o660)
        self.server.broker = broker
        self.thread = Thread(target=self.server.serve_forever, kwargs={'poll_interval': .02})
        self.thread.start()
        self.client = AdminBrokerClient(endpoint, owner, 'alpha', expected_uid=os.getuid())
        self.client._socket_identity = lambda: (endpoint.stat().st_dev, endpoint.stat().st_ino)
        if hold:
            # Force only the held execution to lose its reply. Receipt reads
            # retain the ordinary transport budget while the host commits.
            execution_client = AdminBrokerClient(endpoint, owner, 'alpha', expected_uid=os.getuid(), timeout=.15)
            execution_client._socket_identity = self.client._socket_identity
            self.client.execute = execution_client.execute

    def observation(self):
        path = self.state / 'journal.sqlite'
        if path.exists():
            with sqlite3.connect(path) as db:
                states = {row[0]: json.loads(row[1])['state']
                          for row in db.execute('SELECT id,record FROM requests')}
        else:
            states = {}
        return {'approval': self.approval, 'effects': len(self.effects), 'ids': list(states), 'states': states,
                'restore_approvals': self.restore_approvals, 'executed_approvals': list(self.effects)}

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

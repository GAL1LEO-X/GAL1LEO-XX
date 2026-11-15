"""Real filesystem permission checks; no build accounts or systemd required."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_build as build
import release_admin as admin


@unittest.skipUnless(os.name == 'posix', 'POSIX permission semantics')
class BuildPermissions(unittest.TestCase):
    def check_build(self, existing):
        import pwd
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            (source / 'package.json').write_text('{}')
            releases = root / 'releases'
            releases.mkdir(mode=0o755)
            releases.chmod(0o755)
            if existing:
                (releases / 'whatsapp').mkdir(parents=True)
                (releases / 'whatsapp').chmod(0o700)
            shared_before = releases.stat()
            previous = os.umask(0o077)
            try:
                with patch.object(build, 'RELEASES', releases), \
                     patch.object(admin, '_TRUST_ROOT', root), \
                     patch.object(admin, '_trusted_uid', lambda uid: uid == os.getuid()), \
                     patch.object(pwd, 'getpwnam', return_value=pwd.getpwuid(os.getuid())), \
                     patch.object(build.os, 'chown'):
                    directory = build.create_build('whatsapp', source, ['package.json'])
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(releases.stat().st_mode), 0o755)
            self.assertEqual(releases.stat().st_ino, shared_before.st_ino)
            self.assertEqual(releases.stat().st_uid, shared_before.st_uid)
            self.assertEqual(releases.stat().st_gid, shared_before.st_gid)
            self.assertEqual(stat.S_IMODE(directory.parent.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((directory / 'package.json').stat().st_mode), 0o600)

    def test_fresh_storage_under_private_umask(self):
        self.check_build(False)

    def test_existing_private_storage_is_repaired(self):
        self.check_build(True)

    def test_other_project_refused_before_account_or_storage_access(self):
        with patch('pwd.getpwnam') as account, patch.object(Path, 'mkdir') as mkdir:
            for project in ('box', '../box', '/tmp/elsewhere'):
                with self.assertRaises(build.ReleaseError):
                    build.create_build(project, '/missing-source', [])
            account.assert_not_called()
            mkdir.assert_not_called()

    def test_host_parent_is_not_created_or_repaired(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases = root/'releases'
            with patch.object(build, 'RELEASES', releases), \
                 patch.object(admin, '_TRUST_ROOT', root), \
                 patch.object(admin, '_trusted_uid', lambda uid: uid == os.getuid()), \
                 patch('pwd.getpwnam') as account:
                with self.assertRaises(admin.AdminError):
                    build.create_build('whatsapp', '/missing-source', [])
                self.assertFalse(releases.exists())
                releases.mkdir(mode=0o700)
                with self.assertRaises(build.ReleaseError):
                    build.create_build('whatsapp', '/missing-source', [])
                self.assertEqual(stat.S_IMODE(releases.stat().st_mode), 0o700)
                self.assertFalse((releases/'whatsapp').exists())
                account.assert_not_called()

    def test_sandbox_refuses_other_release_tree_before_systemd(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(build.subprocess, 'run') as run:
            releases = Path(temporary)/'releases'
            with patch.object(build, 'RELEASES', releases):
                for directory in (releases, releases/'box/build', releases/'whatsapp'):
                    with self.assertRaises(build.ReleaseError):
                        build.sandbox(directory, ['true'])
            run.assert_not_called()

    def test_backend_sandbox_does_not_require_browser_or_box_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            releases = Path(temporary) / 'releases'
            directory = releases / 'whatsapp' / 'candidate'
            directory.mkdir(parents=True)
            from types import SimpleNamespace
            commands = []

            def systemd(argv, **kwargs):
                commands.append(argv)
                if argv[:2] == ['systemctl', 'stop']:
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                properties = {argv[i + 1].split('=', 1)[0]: argv[i + 1].split('=', 1)[1]
                              for i, arg in enumerate(argv[:-1]) if arg == '--property'}
                required_mounts = properties['BindReadOnlyPaths'].split()
                for mount in required_mounts:
                    self.assertNotIn(mount, ('/opt/google/chrome', '/etc/X11', '/etc/pulse', '/etc/fonts'))
                self.assertEqual(properties['PrivateNetwork'], 'yes')
                self.assertEqual(properties['BindPaths'], str(directory))
                self.assertEqual(properties['ProtectHome'], 'yes')
                self.assertEqual(properties['TemporaryFileSystem'], '/etc:ro /var:ro /run:ro /srv:ro /opt:ro')
                return SimpleNamespace(returncode=0, stdout='synthetic-probe-ok\n', stderr='')

            with patch.object(build, 'RELEASES', releases), patch.object(build.subprocess, 'run', systemd), \
                 patch.object(build, 'save') as save:
                self.assertEqual(build.sandbox(directory, ['/usr/bin/python3', '-I', '-B', 'probe.py']),
                                 'synthetic-probe-ok')
                save.assert_called_once()
            self.assertEqual(len(commands), 1)


if __name__ == '__main__':
    unittest.main()

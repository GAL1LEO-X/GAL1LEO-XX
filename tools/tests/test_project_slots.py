"""Real offline switching and lock ownership; preserve unrelated environments."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch
from test_project_entrypoint import project, command, wheel, packaging_wheel, ROOT


class SlotTests(unittest.TestCase):
    def test_switch_a_b_a_prunes_and_blocks_mutation_during_command(self):
        runtime='.'.join(map(str,sys.version_info[:2]))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'repo'; (root/'plugins').mkdir(parents=True)
            wheels=Path(temp)/'wheels'; wheels.mkdir()
            version=packaging_wheel(wheels)
            wheel(wheels,'only_alpha'); wheel(wheels,'only_beta')
            for pin in ('1.0.0','2.0.0'):
                info='slot_shared-'+pin+'.dist-info/'
                files={'slot_shared.py':'VERSION = '+repr(pin)+'\n',
                       info+'METADATA':'Metadata-Version: 2.1\nName: slot-shared\nVersion: '+pin+'\n',
                       info+'WHEEL':'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
                files[info+'RECORD']=''.join(name+',,\n' for name in files)+info+'RECORD,,\n'
                with zipfile.ZipFile(wheels/('slot_shared-'+pin+'-py3-none-any.whl'),'w') as archive:
                    for name,content in files.items(): archive.writestr(name,content)
            for name in ('alpha','beta'):
                project.scaffold(root,name)
                (root/'plugins'/name/'requirements-test.lock').write_text(f'packaging=={version}\nonly-{name}==1.0.0\nslot-shared=={1 if name == "alpha" else 2}.0.0\n')
            command('git','init',cwd=root)
            (root/'.gitignore').write_text('.venvs/\nwork/\n__pycache__/\n')
            command('git','add','.',cwd=root)
            command('git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','base',cwd=root)
            (root/'unfinished.txt').write_text('preserve me')
            before=command('git','status','--porcelain',cwd=root).stdout
            env=dict(os.environ,PIP_NO_INDEX='1',PIP_FIND_LINKS=str(wheels))
            alpha=project.select_environment(project.load(root,'alpha'))
            beta=project.select_environment(project.load(root,'beta'))
            python=project.venv_python(root/alpha['venvs'][runtime])
            with patch.dict(os.environ,env):
                for selected,other in ((alpha,beta),(beta,alpha),(alpha,beta)):
                    project.prepare(root,selected,runtime,sys.executable)
                    self.assertFalse(project.status(root,selected,runtime)[-1])
                    self.assertTrue(project.status(root,other,runtime)[-1])
                    names=json.loads(command(python,'-m','pip','list','--format=json').stdout)
                    names={p['name'] for p in names}
                    self.assertIn('only-'+selected['id'],names)
                    self.assertNotIn('only-'+other['id'],names)
                    expected='1.0.0' if selected['id']=='alpha' else '2.0.0'
                    self.assertEqual(command(python,'-c','import slot_shared; print(slot_shared.VERSION)').stdout.strip(),expected)
                stamp=python.parent.parent/'.plugins-dependencies.json'
                old_mtime=stamp.stat().st_mtime_ns
                project.prepare(root,alpha,runtime,sys.executable)
                self.assertEqual(stamp.stat().st_mtime_ns,old_mtime)
                # A real child holds the slot for the whole custom command.
                worker=root/'hold.py'
                worker.write_text('from pathlib import Path\nimport time\nPath("holding").touch()\n'
                                  'while not Path("release").exists(): time.sleep(.02)\n')
                args=[sys.executable,str(ROOT/'tools/project.py'),'--root',str(root),'run','alpha','--runtime',runtime,'--','python',str(worker)]
                child=subprocess.Popen(args,cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    deadline=time.monotonic()+15
                    while not (root/'holding').exists() and child.poll() is None and time.monotonic()<deadline: time.sleep(.02)
                    self.assertTrue((root/'holding').exists())
                    with self.assertRaises(BlockingIOError): project.prepare(root,beta,runtime,sys.executable)
                    self.assertEqual(stamp.stat().st_mtime_ns,old_mtime)
                finally:
                    (root/'release').touch()
                    stdout,stderr=child.communicate(timeout=10)
                self.assertEqual(child.returncode,0,stderr)
                for name in ('hold.py','holding','release'): (root/name).unlink()
            self.assertEqual(command('git','status','--porcelain',cwd=root).stdout,before)
            self.assertEqual((root/'unfinished.txt').read_text(),'preserve me')
            self.assertFalse((root/'.venvs/alpha').exists())
            self.assertFalse((root/'.venvs/beta').exists())

    def test_no_slot_traversal_and_explicit_isolation(self):
        contract=project.load(ROOT,'tesla')
        self.assertEqual(project.select_environment(contract,'isolated'),contract)
        for slot in ('../tesla','/tmp/other','','bad name'):
            with self.assertRaises(ValueError): project.select_environment(contract,'slot',slot)

    def test_existing_editable_must_point_to_selected_checkout(self):
        # Metadata read is executed by the actual test interpreter, no network.
        contract=project.load(ROOT,'whatsapp')
        from unittest.mock import patch
        original=project.run
        def only_editable(args,**kwargs):
            if '-c' in args and 'direct_url.json' in args[2]: return original(args,**kwargs)
            return None
        with patch.object(project,'run',side_effect=only_editable):
            project.inventory(ROOT,contract,sys.executable)
            with tempfile.TemporaryDirectory() as temp:
                fake=Path(temp); target=fake/'plugins/whatsapp'; target.mkdir(parents=True)
                (target/'pyproject.toml').write_bytes((ROOT/'plugins/whatsapp/pyproject.toml').read_bytes())
                with self.assertRaises(subprocess.CalledProcessError): project.inventory(fake,contract,sys.executable)

import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('sync_dependencies',ROOT/'tools/cloud/sync_dependencies.py')
sync=importlib.util.module_from_spec(spec);spec.loader.exec_module(sync)


def wheel(folder,name):
    info=name+'-1.0.0.dist-info/'
    files={name+'.py': 'VALUE = "synthetic"\n',
           info+'METADATA':'Metadata-Version: 2.1\nName: '+name.replace('_','-')+'\nVersion: 1.0.0\n',
           info+'WHEEL':'Wheel-Version: 1.0\nGenerator: synthetic-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    files[info+'RECORD']=''.join(path+',,\n' for path in files)+info+'RECORD,,\n'
    with zipfile.ZipFile(folder/(name+'-1.0.0-py3-none-any.whl'),'w') as archive:
        for name,data in files.items(): archive.writestr(name,data)


class DependencyTests(unittest.TestCase):
    def test_removed_dependency_is_uninstalled_even_when_pip_check_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wheels=root/'wheels';wheels.mkdir()
            for name in ('review_kept','review_removed'): wheel(wheels,name)
            lock=root/'requirements.lock'
            lock.write_text('review-kept==1.0.0\nreview-removed==1.0.0\n')
            venv=root/'venv';python=venv/'bin/python'
            def run(*args): return subprocess.run(list(map(str,args)),check=True,capture_output=True,text=True)
            run(sys.executable,'-m','venv',venv)
            def install(): run(python,'-m','pip','--disable-pip-version-check','install','--no-index','--find-links',wheels,'-r',lock)
            install()
            lock.write_text('review-kept==1.0.0\n')
            run(sys.executable,'-m','venv',venv);install()
            run(python,'-m','pip','check')
            with self.assertRaisesRegex(ValueError,'Unpinned'): sync.synchronize(python,lock)
            sync.synchronize(python,lock,prune=True)
            self.assertNotIn('review-removed',sync.inventory(python)['packages'])
            self.assertEqual(run(python,'-c','import importlib.util; print(importlib.util.find_spec("review_removed"))').stdout.strip(),'None')
            sync.synchronize(python,lock,prune=True)
            run(python,'-m','pip','check')

    def test_missing_lock_dependency_prevents_pruning(self):
        with tempfile.TemporaryDirectory() as directory:
            lock=Path(directory)/'requirements.lock';lock.write_text('required-fixture==1.0.0\n')
            with patch.object(sync,'inventory',return_value={'isolated':True,'python':'3.14.8','packages':{'extra-fixture':'1.0'}}), patch.object(sync.subprocess,'run') as mutate:
                with self.assertRaisesRegex(ValueError,'missing'): sync.synchronize('fixture-python',lock,prune=True)
                mutate.assert_not_called()

    def test_system_python_is_never_pruned(self):
        with patch.object(sync,'inventory',return_value={'isolated':False}),patch.object(sync.subprocess,'run') as mutate:
            with self.assertRaisesRegex(ValueError,'isolated'): sync.synchronize('fixture-python','unused',prune=True)
            mutate.assert_not_called()


class PreparationTests(unittest.TestCase):
    def test_no_selection_does_not_install_or_prefer_a_plugin(self):
        result=subprocess.run(['bash',str(ROOT/'tools/cloud/prepare-environment.sh')],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('tesla',result.stdout)
        self.assertIn('whatsapp',result.stdout)
        self.assertIn('Select:',result.stdout)

    def test_selected_plugin_arguments_are_forwarded_without_installs_in_wrapper(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); folder=root/'tools/cloud'; folder.mkdir(parents=True)
            (folder/'prepare-environment.sh').write_text((ROOT/'tools/cloud/prepare-environment.sh').read_text())
            (root/'tools/project.py').write_text('import json,sys; print(json.dumps(sys.argv[1:]))')
            result=subprocess.run(['bash',str(folder/'prepare-environment.sh'),'future-plugin','--runtime','3.14','--slot','review','--python','selected-python'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout),['prepare','future-plugin','--runtime','3.14','--slot','review','--python','selected-python'])
            (folder/'zz-broken.sh').write_text('if true; then\n')
            result=subprocess.run(['bash',str(folder/'prepare-environment.sh'),'future-plugin'],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,'')

    def test_workflow_checks_later_scripts_before_suites(self):
        workflow=(ROOT/'.github/workflows/ci.yml').read_text()
        step=workflow.split('      - name: Validate development scripts\n',1)[1].split('      - name:',1)[0]
        script='\n'.join(line[10:] for line in step.splitlines() if line.startswith('          '))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);folder=root/'tools/cloud';folder.mkdir(parents=True)
            (folder/'a-valid.sh').write_text('true\n')
            (folder/'check.sh').write_text('touch suite-ran\n')
            (folder/'zz-broken.sh').write_text('if true; then\n')
            result=subprocess.run(['bash','-eu','-c',script],cwd=root,text=True,capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('zz-broken.sh',result.stderr)
            self.assertFalse((root/'suite-ran').exists())


if __name__=='__main__': unittest.main()

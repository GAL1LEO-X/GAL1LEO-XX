#!/usr/bin/env python3
"""Complete only untested Go packages with the already qualified QA163 toolchain."""
from pathlib import Path
import importlib.util
import json
import re
import shutil
import sys

ROOT = Path('/workspace/work/qa174-fixes/recovered-qa163')
OUT = ROOT / 'additional-packages'
spec = importlib.util.spec_from_file_location('qa174_gows_harness', ROOT / 'build_gows_harness.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def prepare():
    OUT.mkdir()
    for name in ('source-inventory.json', 'inputs.json'):
        shutil.copyfile(ROOT / name, OUT / name)
    print(json.dumps({'prepared': str(OUT), 'original_runner_sha256': base.sha(base.__file__)}))


def execute():
    base.require(not (OUT / 'execution-result.json').exists(), 'Already executed; no automatic retry')
    previous = json.loads((ROOT / 'execution-result.json').read_text())
    base.require(previous['passed'], 'Initial qualification must pass')
    test_step = next(step for step in previous['steps'] if step['key'] == 'provider-tests')
    covered = set()
    for line in Path(test_step['stdout']).read_text().splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get('Action') == 'pass' and 'Test' not in event:
            covered.add(event['Package'])
    base.require(len(covered) == 4, 'Unexpected prior package coverage')
    base.EVIDENCE = OUT
    run = base.Execution()
    run.receipt.update(extension_sha256=base.sha(__file__), previous_result_sha256=base.sha(ROOT / 'execution-result.json'),
                       scope='Offline package enumeration and tests of only the packages missing from the initial qualification',
                       already_tested_packages=sorted(covered), binaries_rebuilt=False)
    try:
        run.container('package-list', 'a', ['list', '-mod=vendor', './...'])
        packages = sorted(set(Path(run.receipt['steps'][-1]['stdout']).read_text().splitlines()))
        base.require(packages and all(re.fullmatch(r'[A-Za-z0-9._/-]+', item) for item in packages), 'Unexpected package list')
        base.require(covered <= set(packages), 'Previously covered packages missing from enumeration')
        remaining = sorted(set(packages) - covered)
        run.receipt.update(all_packages=packages, additional_packages=remaining)
        base.write('package-selection.json', {'all_packages': packages, 'already_tested_packages': sorted(covered), 'additional_packages': remaining})
        print(json.dumps({'additional_packages': remaining}), flush=True)
        if remaining:
            run.container('remaining-package-tests', 'a', ['test', '-p=2', '-mod=vendor', '-count=1', '-json', '-timeout=120s', *remaining])
        for key in ('a', 'b'):
            base.require(base.inventory(base.SCRATCH / ('gows-' + key)) == json.loads((OUT / 'source-inventory.json').read_text()), 'Source changed')
        binary = previous['binary']
        base.require(base.sha(binary['first']) == base.sha(binary['second']) == binary['sha256'], 'Previously built binaries changed')
        run.receipt['gows_sha256'] = binary['sha256']
        run.receipt['passed'] = True
    except BaseException as error:
        run.receipt['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        for name in list(run.owned):
            try:
                run.cleanup_one(name)
            except Exception as error:
                run.receipt['cleanup'].append({'name': name, 'removed': False, 'error': str(error)})
                run.receipt['passed'] = False
        run.receipt['finished_at'] = base.now()
        base.write('execution-result.json', run.receipt)
        print(json.dumps(run.receipt), flush=True)


if __name__ == '__main__':
    base.require(sys.argv[1:] in (['prepare'], ['execute', '--authorized-recovered-qa163-execution']), 'Explicit action and authorization required')
    prepare() if sys.argv[1] == 'prepare' else execute()

"""Explicit, bounded selections of the existing synthetic test bank."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


SUITES = {
    'coordinator': ['test_qa_campaign.py'],
    'core': ['test_contracts.py', 'test_delivery_receipts.py', 'test_profile_readonly.py'],
    'catalog': ['test_family_capabilities.py', 'test_catalog_action_contracts.py',
                'test_catalog_remaining_flows.py', 'test_dispatch_outcomes.py',
                'test_group_permission_errors.py', 'test_label_validation.py'],
    'media': ['test_provider_media_flows.py', 'test_media_integrity_formats.py',
              'test_live_attachments.py'],
    'events': ['test_event_catalog_pipeline.py', 'test_provider_events.py',
               'test_callback_chain.py', 'test_event_policies.py',
               'test_event_authorization.py', 'test_event_ttl.py', 'test_event_recovery.py'],
    'history': ['test_history_coverage.py', 'test_recent_message_reads.py',
                'test_verified_message_identity.py'],
    'privacy': ['test_tenancy.py', 'test_revocation_and_live_events.py',
                'test_message_lifetime_privacy.py', 'test_clearchat_coverage.py',
                'test_clearchat_consumers.py'],
}


def suite_plan(plugin_root):
    root = Path(plugin_root)
    rows = []
    for name, files in SUITES.items():
        for filename in files:
            if not (root / 'tests' / filename).is_file():
                raise ValueError('Missing indexed suite: ' + filename)
        rows.append({'suite': name, 'files': ['tests/' + name for name in files],
                     'evidence_level': 'synthetic_functional', 'state': 'NOT_EXECUTED',
                     'limit': 'Uses fake provider/transport boundaries; not live account evidence.'})
    return rows


def prepare_fixtures(plugin_root, destination):
    """Verify and copy versioned synthetic bytes; never copy private input."""
    source = Path(plugin_root) / 'tests/fixtures/media-integrity'
    records = json.loads((source / 'manifest.json').read_text(encoding='utf-8'))
    destination = Path(destination)
    validated = []
    for item in records:
        if Path(item['name']).name != item['name']:
            raise ValueError('Fixture names must not contain paths')
        blob = (source / item['name']).read_bytes()
        if len(blob) != item['size'] or hashlib.sha256(blob).hexdigest() != item['sha256']:
            raise ValueError('Versioned fixture integrity failed: ' + item['name'])
        target = destination / item['name']
        if target.exists() and target.read_bytes() != blob:
            raise FileExistsError('Refusing to replace a different fixture: ' + item['name'])
        validated.append((item, blob))
    destination.mkdir(parents=True, exist_ok=True)
    for item, blob in validated:
        target = destination / item['name']
        if not target.exists():
            with target.open('xb') as stream:
                stream.write(blob)
    # The manifest is generated from exactly the verified versioned sources.
    result = {'fixtures': records, 'synthetic': True,
              'limit': 'Tiny technical samples. Mobile usability needs a separate representative corpus.'}
    (destination / 'verified-manifest.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def run_suites(plugin_root, names, destination):
    if not names or any(name not in SUITES for name in names):
        raise ValueError('Select one or more named suites explicitly')
    root, destination = Path(plugin_root).resolve(), Path(destination).resolve()
    suite_plan(root)
    # Each invocation has its own directory; old evidence is never overwritten.
    destination.mkdir(parents=True, exist_ok=False)
    files = sorted({filename for name in names for filename in SUITES[name]})
    junit = destination / 'junit.xml'
    command = [sys.executable, '-m', 'pytest', '-q', '--tb=short',
               '--junitxml=' + str(junit), *['tests/' + filename for filename in files]]
    with (destination / 'pytest.log').open('w', encoding='utf-8') as log:
        completed = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=False)
    counts = {'tests': 0, 'failures': 0, 'errors': 0, 'skipped': 0}
    if junit.exists():
        for suite in ET.parse(junit).getroot().iter('testsuite'):
            for field in counts:
                counts[field] += int(suite.get(field, 0))
    result = {'suites': list(dict.fromkeys(names)), 'files': files, 'exit_code': completed.returncode,
              'counts': counts, 'evidence_level': 'synthetic_functional', 'live_calls': 0,
              'complete': completed.returncode == 0 and counts['tests'] > 0}
    (destination / 'summary.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result

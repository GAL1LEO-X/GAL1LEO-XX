"""Exercise distributable source boundaries with actual archives and poisoned inputs."""
import json
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import build_source


@pytest.fixture
def source(tmp_path):
    root=tmp_path/'source'
    plugin=root/'plugins/tesla'
    (plugin/'plugin').mkdir(parents=True)
    for file in ('LICENSE','NOTICE','THIRD_PARTY_NOTICES.md','README.md','AGENTS.md','project.json'):
        (plugin/file).write_text('{}' if file.endswith('.json') else 'Synthetic source notice\n')
    (plugin/'plugin/plugin.json').write_text(json.dumps({
        'author':{'name':'GAL1LEO','email':'info@gal1leo.com'},'license':'Apache-2.0',
        'extensions':{'com.openai':{'interface':{'developerName':'GAL1LEO','shortDescription':'Synthetic test'}}}}))
    for file in ('LICENSE','NOTICE','README.md'):(root/file).write_text('Synthetic root notice\n')
    return root


def test_archive_is_deterministic_contains_attribution_and_excludes_generated_work(source,tmp_path):
    (source/'work').mkdir()
    (source/'work/operator-secret.key').write_text('must never be archived')
    outputs=[tmp_path/'first.zip',tmp_path/'second.zip']
    results=[build_source.build('tesla',output,root=source) for output in outputs]
    assert outputs[0].read_bytes()==outputs[1].read_bytes()
    assert results[0]['sha256']==results[1]['sha256']
    with zipfile.ZipFile(outputs[0]) as archive:
        names=set(archive.namelist())
        assert {'LICENSE','NOTICE','plugins/tesla/LICENSE','plugins/tesla/NOTICE'}<=names
        assert not any(name.startswith('work/') for name in names)
        assert b'info@gal1leo.com' in archive.read('README.md')
        assert set(json.loads(archive.read('SHA256SUMS.json')))==names-{'SHA256SUMS.json'}
    with pytest.raises(ValueError,match='new'):build_source.build('tesla',outputs[0],root=source)


@pytest.mark.parametrize('kind',['private-file','source-symlink','source-directory-symlink','credential'])
def test_unreviewed_source_is_rejected_before_creating_an_archive(source,tmp_path,kind):
    if kind=='private-file':
        (source/'private').mkdir();(source/'private/operator.txt').write_text('operator state')
    elif kind=='source-symlink':
        (source/'plugins/tesla/borrowed.py').symlink_to(source/'NOTICE')
    elif kind=='source-directory-symlink':
        (source/'plugins/tesla/borrowed').symlink_to(source/'plugins/tesla/plugin',target_is_directory=True)
    else:
        # Build the synthetic canary at runtime so it cannot be mistaken for a
        # real committed token by source scanners.
        (source/'plugins/tesla/canary.txt').write_text('gh'+'p_'+'A'*36)
    output=tmp_path/'forbidden.zip'
    with pytest.raises(ValueError,match='validation'):build_source.build('tesla',output,root=source)
    assert not output.exists()

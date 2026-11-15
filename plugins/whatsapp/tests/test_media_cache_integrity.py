"""Synthetic cache tampering and descriptor-backed HTTP transfers."""
import os
import stat

import pytest

from conftest import ready_external_media
from sally_whatsapp.media import Media, copy_bounded
from test_media_integrity_formats import FILES, acquire, setup


def test_copy_creates_private_file_and_preserves_existing_paths(tmp_path):
    target=tmp_path/'private.bin'
    copy_bounded([b'synthetic'],target,1024)
    assert stat.S_IMODE(target.stat().st_mode)==0o600
    with pytest.raises(FileExistsError):
        copy_bounded([b'replacement'],target,1024)
    assert target.read_bytes()==b'synthetic'


def test_copy_never_follows_target_or_directory_symlink(tmp_path):
    outside=tmp_path/'outside'
    outside.mkdir()
    victim=outside/'payload'
    victim.write_bytes(b'keep')
    target=tmp_path/'target'
    target.symlink_to(victim)
    with pytest.raises(OSError):
        copy_bounded([b'replacement'],target,1024)
    assert target.is_symlink() and victim.read_bytes()==b'keep'
    parent=tmp_path/'linked-directory'
    parent.symlink_to(outside,target_is_directory=True)
    with pytest.raises(OSError):
        copy_bounded([b'escape'],parent/'new',1024)
    assert not (outside/'new').exists()


@pytest.mark.parametrize('damage',['same_size','truncated','symlink','hardlink'])
def test_signed_download_rejects_changed_cache_and_preserves_other_file(app_client,tmp_path,damage):
    app,client=app_client
    service=app.state.service
    queued=ready_external_media(service,data=b'synthetic original bytes')
    ready=service.media.status(queued['id'],service.settings.owner_subject)
    path=service.media.path(queued['id'])
    victim=tmp_path/'unrelated.bin'
    victim.write_bytes(b'synthetic original bytes')
    if damage=='same_size':
        path.write_bytes(b'x'*ready['size'])
    elif damage=='truncated':
        path.write_bytes(b'x')
    else:
        path.unlink()
        if damage=='symlink':
            path.symlink_to(victim)
        else:
            os.link(victim,path)
    response=client.get(ready['download_url'])
    assert response.status_code==404 and 'synthetic original bytes' not in response.text
    assert victim.read_bytes()==b'synthetic original bytes'
    assert not path.exists()
    failed=service.media.status(queued['id'],service.settings.owner_subject)
    assert failed['state']=='failed' and failed['sha256'] is None
    assert 'download_url' not in failed


@pytest.mark.parametrize('method,range_header,status,expected',[
    ('GET',None,200,b'0123456789'),
    ('HEAD',None,200,b''),
    ('GET','bytes=2-5',206,b'2345'),
    ('HEAD','bytes=2-5',206,b''),
    ('GET','bytes=99-',416,None),
    ('GET','invalid',400,None),
    ('GET','bytes=0-1,8-9',206,None),
])
def test_verified_descriptor_survives_path_swap_and_keeps_http_contract(
    app_client,monkeypatch,method,range_header,status,expected,
):
    app,client=app_client
    media=app.state.service.media
    queued=ready_external_media(app.state.service,data=b'0123456789')
    ready=media.status(queued['id'],app.state.service.settings.owner_subject)
    original=media.download_response
    responses=[]

    def swap_after_verification(grant):
        response=original(grant)
        responses.append((response,response.descriptor))
        path=media.path(queued['id'])
        path.unlink()
        path.write_bytes(b'SECRET REPLACEMENT')
        return response

    monkeypatch.setattr(media,'download_response',swap_after_verification)
    response=client.request(method,ready['download_url'],headers={'Range':range_header} if range_header else {})
    assert response.status_code==status
    assert b'SECRET REPLACEMENT' not in response.content
    if expected is not None:
        assert response.content==expected
    if range_header=='bytes=0-1,8-9':
        assert b'bytes 0-1/10' in response.content and b'bytes 8-9/10' in response.content
        assert b'\r\n01\r\n' in response.content and b'\r\n89\r\n' in response.content
    if status in (200,206):
        assert response.headers['cache-control']=='private, no-store'
        assert response.headers['accept-ranges']=='bytes'
        assert response.headers['x-content-type-options']=='nosniff'
    assert responses[0][0].descriptor is None
    with pytest.raises(OSError):
        os.fstat(responses[0][1])


def test_media_rejects_cache_root_symlink(app_client,tmp_path):
    app,_=app_client
    service=app.state.service
    root=service.media.root
    root.rmdir()
    outside=tmp_path/'outside-cache'
    outside.mkdir(mode=0o700)
    root.symlink_to(outside,target_is_directory=True)
    with pytest.raises(ValueError,match='physical directory'):
        Media(service.store,service.settings,service.gateway)
    assert list(outside.iterdir())==[]


@pytest.mark.parametrize('seconds',[None,0,12])
@pytest.mark.parametrize('source',['archive','live'])
def test_audio_duration_preserves_unknown_and_explicit_zero(environment,seconds,source):
    item=next(value for value in FILES if value['name']=='sample.ogg')
    app,gateway,_=setup(environment,item)
    service=app.state.service
    if seconds is not None:
        gateway.observation['_data']['Message']['audioMessage']['seconds']=seconds
    if source=='archive':
        acquire(service,gateway)
    from sally_whatsapp.live_attachments import read_source
    observed=read_source(service.store,service.settings,gateway,gateway.observation['id'])
    metadata=observed.pop('media')
    if source=='archive':
        observed['provenance']='archive_gateway'
    queued=service.media.enqueue(service.settings.owner_subject,observed,metadata['filename'],metadata['mimetype'])
    assert service.media.process_one()
    status=service.media.status(queued['id'],service.settings.owner_subject)
    assert status['state']=='ready' and status['duration_seconds']==seconds
    assert service.media.path(queued['id']).read_bytes()==gateway.media_bytes
    assert not gateway.sent


@pytest.mark.parametrize('seconds',[True,-1,1.5,'0',2**32])
def test_malformed_audio_duration_is_not_reported_as_zero(environment,seconds):
    item=next(value for value in FILES if value['name']=='sample.ogg')
    app,gateway,_=setup(environment,item)
    gateway.observation['_data']['Message']['audioMessage']['seconds']=seconds
    from sally_whatsapp.live_attachments import read_source
    with pytest.raises(ValueError,match='duration'):
        read_source(app.state.service.store,app.state.service.settings,gateway,gateway.observation['id'])


def test_restart_replaces_only_owned_incomplete_transfer(environment,monkeypatch):
    from sally_whatsapp.server import Service
    settings,receiver,gateway,_=environment
    service=Service(settings,gateway=gateway,event_transport=receiver)
    source={'kind':'external','file_id':'file-crash-synthetic','download_url':'https://files.example/synthetic'}
    queued=service.media.enqueue(settings.owner_subject,source,'crash.bin','application/octet-stream')
    path=service.media.path(queued['id'])
    path.write_bytes(b'partial')
    unrelated=service.media.root/'unrelated'
    unrelated.write_bytes(b'preserved')
    with service.store.db() as db:
        db.execute("UPDATE media_jobs SET state='downloading' WHERE id=?",(queued['id'],))
    service.diagnostics.close()
    resumed=Service(settings,gateway=gateway,event_transport=receiver)
    try:
        monkeypatch.setattr('sally_whatsapp.media.download_public',
                            lambda url,target,maximum:copy_bounded([b'complete'],target,maximum))
        assert resumed.media.process_one()
        assert resumed.media.row(queued['id'],settings.owner_subject)['state']=='ready'
        assert path.read_bytes()==b'complete' and unrelated.read_bytes()==b'preserved'
    finally:
        resumed.diagnostics.close()


@pytest.mark.parametrize('already_expired',[False,True])
def test_expiry_removes_file_and_unneeded_content_metadata(app_client,already_expired):
    app,_=app_client
    service=app.state.service
    queued=ready_external_media(service,name='synthetic-private-name.pdf',data=b'synthetic-content')
    path=service.media.path(queued['id'])
    with service.store.db() as db:
        db.execute("UPDATE media_jobs SET expires=0,state=? WHERE id=?",
                   ('expired' if already_expired else 'ready',queued['id']))
    service.media.clean()
    with service.store.db() as db:
        row=dict(db.execute('SELECT * FROM media_jobs WHERE id=?',(queued['id'],)).fetchone())
    assert row['state']=='expired' and row['source']==b''
    assert row['filename']==row['mimetype']==''
    assert row['size'] is row['sha256'] is row['error'] is None
    assert not path.exists()

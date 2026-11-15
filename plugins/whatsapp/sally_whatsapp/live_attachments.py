"""Read and verify one provider attachment without importing its message."""
import base64
import binascii
import json
import math
from urllib.parse import quote

from . import lifetime, visibility
from .account_events import message_chat
from .forwarding import source_state


class SourceChanged(ValueError):
    """A verified source no longer names the attachment this job prepared."""


def _media_payload(content):
    types=('imageMessage','audioMessage','videoMessage','documentMessage','stickerMessage','ptvMessage')
    selected=[]
    def collect(value,depth=0):
        if not isinstance(value,dict) or depth>8:
            raise ValueError('Attachment media type could not be verified')
        selected.extend((kind,value[kind]) for kind in types if value.get(kind) is not None)
        # Match the pinned WAHA extractMediaContent paths, never a quoted
        # message or an arbitrary nested hash unrelated to this attachment.
        template=value.get('templateMessage')
        if isinstance(template,dict):
            hydrated=template.get('hydratedTemplate')
            interactive=template.get('interactiveMessageTemplate')
            header=interactive.get('header') if isinstance(interactive,dict) else None
            for container,kinds in ((hydrated,('imageMessage','videoMessage')),
                                    (header,('imageMessage','videoMessage','documentMessage'))):
                if isinstance(container,dict):
                    selected.extend((kind,container[kind]) for kind in kinds if container.get(kind) is not None)
        child=value.get('associatedChildMessage')
        if isinstance(child,dict) and child.get('message') is not None:
            collect(child['message'],depth+1)
        document=value.get('documentWithCaptionMessage')
        if isinstance(document,dict) and document.get('message') is not None:
            collect(document['message'],depth+1)
    collect(content)
    if len(selected)!=1 or not isinstance(selected[0][1],dict):
        raise ValueError('Attachment media type could not be verified')
    return selected[0]


def _media_identity(content):
    kind,payload=_media_payload(content)
    encoded=payload.get('fileSHA256')
    try:
        if not isinstance(encoded,str) or len(encoded)!=44: raise ValueError()
        digest=base64.b64decode(encoded,validate=True)
        if len(digest)!=32 or base64.b64encode(digest).decode()!=encoded: raise ValueError()
    except (ValueError,binascii.Error):
        raise ValueError('Attachment content hash could not be verified') from None
    return {'type':kind,'sha256':digest.hex()}


def archive_media_identity(payload):
    """Keep only the original typed digest, never provider blobs or secrets."""
    try:
        return _media_identity(payload['_data']['Message'])
    except (KeyError,TypeError,ValueError):
        return None


def _media_metadata(content, media):
    """Reconcile the public summary with metadata from the same typed source."""
    from .media import filename, mime
    kind,payload=_media_payload(content)
    result={key:value for key,value in (media or {}).items()
            if key in ('url','filename','mimetype') and isinstance(value,str)}
    declared_type=payload.get('mimetype')
    summary_type=result.get('mimetype')
    if declared_type is not None:
        if not isinstance(declared_type,str) or not declared_type.strip():
            raise ValueError('Invalid source attachment MIME')
        typed=mime(declared_type,'')
        if typed=='application/octet-stream' and declared_type.strip().lower()!='application/octet-stream':
            raise ValueError('Invalid source attachment MIME')
        summary=mime(summary_type,'') if summary_type else None
        if summary and summary!='application/octet-stream' and typed!='application/octet-stream' and summary.split(';',1)[0]!=typed.split(';',1)[0]:
            raise ValueError('Provider attachment MIME conflicts with its source')
        # A typed source can carry the codec while WAHA's summary omits it.
        result['mimetype']=(summary if typed=='audio/ogg' and summary=='audio/ogg; codecs=opus' else typed)
    declared_name=payload.get('fileName')
    if declared_name is not None:
        if not isinstance(declared_name,str) or not declared_name.strip():
            raise ValueError('Invalid source attachment filename')
        normalized=filename(declared_name)
        if result.get('filename') and filename(result['filename'])!=normalized:
            raise ValueError('Provider attachment filename conflicts with its source')
        result['filename']=normalized
    declared_size=payload.get('fileLength')
    if declared_size is not None:
        if isinstance(declared_size,str) and declared_size.isascii() and declared_size.isdigit() and len(declared_size)<=20:
            declared_size=int(declared_size)
        if type(declared_size) is not int or not 0<=declared_size<2**64:
            raise ValueError('Invalid source attachment size')
        result['size']=declared_size
    if kind in ('audioMessage','videoMessage','ptvMessage'):
        seconds=payload.get('seconds')
        if seconds is not None and (type(seconds) is not int or not 0<=seconds<2**32):
            raise ValueError('Invalid source attachment duration')
        # Missing is unknown. An explicit protocol zero is a known value;
        # never infer duration from file length or silently convert the audio.
        result['duration_seconds']=seconds
    return result


def acquired_source_visible(store, db, identifier, timestamp, expected_media):
    """Prove a complete acquired key, including only verified alias variants."""
    if timestamp is None or visibility.message_identity(identifier) is None:
        return False
    variants=visibility.identifier_variants(db,identifier,store._canonical_chat)
    acquired=db.execute('''SELECT timestamp,media FROM messages
        WHERE id IN (SELECT value FROM json_each(?)) AND deleted=0
        ORDER BY rowid LIMIT 1''',(json.dumps(variants),)).fetchone()
    if not acquired or acquired['timestamp']!=timestamp or not acquired['media']:
        return False
    if store._message_state(db,identifier)['state']!='unknown':
        return False
    metadata=json.loads(acquired['media'])
    identity=metadata.get('identity')
    return not identity or identity==expected_media


def _available(store, identifier, chat, timestamp=None, *, before_read=False,
               acquired_source=False, expected_media=None):
    with store.db() as db, visibility.read_snapshot(db):
        state=source_state(lambda identifier,**context:store._message_state(db,identifier,**context),
            identifier,chat_id=chat,timestamp=timestamp,defer_unknown_time=before_read)
        uncertain=state.get('clear_chat_coverage',{}).get('boundary_unknown')
        acquired=(acquired_source and acquired_source_visible(store,db,identifier,timestamp,expected_media))
        if state['state']!='unknown' or uncertain and not acquired:
            raise ValueError('Attachment source is removed, expired or its visibility cannot be established')


def read_source(store, settings, gateway, identifier, *, download_media=False, expected_timestamp=None, expected_media=None,
                acquired_source=False):
    identity=visibility.message_identity(identifier)
    if (identity is None or not identity[2] or len(identifier)>512
            or len(identifier.split('_')) not in (3,4)):
        raise ValueError('Live attachments require the complete provider message ID, including source chat')
    chat=identity[0]
    _available(store,identifier,chat,expected_timestamp,before_read=True,
               acquired_source=acquired_source,expected_media=expected_media)
    path='/api/'+quote(settings.session,safe='')+'/chats/'+quote(chat,safe='')+'/messages/'+quote(identifier,safe='')
    observation=gateway.request('GET',path,params={'downloadMedia':str(download_media).lower()},timeout=15)
    observed_id=observation.get('id') if isinstance(observation,dict) else None
    with store.db() as db, visibility.read_snapshot(db):
        if (visibility.message_identity(observed_id) is None
                or visibility.canonical_identifier(db,identifier,store._canonical_chat)!=
                   visibility.canonical_identifier(db,observed_id,store._canonical_chat)
                or store._canonical_chat(db,message_chat(observation))!=store._canonical_chat(db,chat)
                or observation.get('fromMe') is not identity[1]
                or not store._identity_context_matches(db,observed_id,message_chat(observation),
                    observation.get('fromMe'),observation.get('participant'))):
            raise ValueError('Attachment source identity could not be verified')
    timestamp=observation.get('timestamp')
    if (type(timestamp) not in (int,float) or not math.isfinite(timestamp)
            or not 0<=timestamp<=253402300799 or expected_timestamp is not None and timestamp!=expected_timestamp):
        raise ValueError('Attachment source time could not be verified')
    raw=observation.get('_data')
    flags=('IsViewOnce','IsViewOnceV2','IsViewOnceV2Extension','IsEphemeral')
    if (not isinstance(raw,dict) or any(type(raw.get(flag)) is not bool for flag in flags)
            or not isinstance(raw.get('Message'),dict) or not raw['Message']):
        raise ValueError('Attachment source lifetime could not be verified')
    duration=lifetime.metadata(observation)
    store.observe_message_lifetime(identifier,chat,duration,
        from_me=observation.get('fromMe'),participant=observation.get('participant'))
    if lifetime.state(duration)!='unknown':
        raise ValueError('Attachment source is view-once, expired or its lifetime cannot be verified')
    _available(store,identifier,chat,timestamp,acquired_source=acquired_source,expected_media=expected_media)
    if observation.get('hasMedia') is not True:
        raise ValueError('No attachment is available on this provider message')
    try:
        media_identity=_media_identity(raw['Message'])
    except ValueError:
        if expected_media is not None: raise SourceChanged('Attachment source content changed or became unverifiable') from None
        raise
    if expected_media is not None and media_identity!=expected_media:
        raise SourceChanged('Attachment source content changed')
    media=observation.get('media')
    if media is not None and not isinstance(media,dict):
        raise ValueError('Invalid provider attachment metadata')
    media=_media_metadata(raw['Message'],media)
    if download_media and not media.get('url'):
        raise ValueError('Provider attachment is not available for download')
    result={'kind':'gateway','provenance':'live_gateway','message_id':identifier,
            'chat_id':chat,'timestamp':timestamp,'lifetime':duration,'media_identity':media_identity,'media':media}
    if 'duration_seconds' in media:
        result['duration_seconds']=media['duration_seconds']
    return result

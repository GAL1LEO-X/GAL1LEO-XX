"""Bounded streamed file transfers, encrypted source URLs and expiring download grants."""
import hashlib
import base64
import asyncio
import http.client
import io
import json
import mimetypes
import os
from pathlib import Path
import re
import socket
import stat
import time
import uuid
import zlib
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from starlette.responses import FileResponse, JSONResponse
from .config import secret
from .events import PinnedHTTPS, public_addresses
from .store import canonical
from . import lifetime
from . import media_diagnostics
from .media_diagnostics import CacheCapacityExceeded, TransferLimitExceeded

TRANSFER_CHUNK_BYTES=64*1024
TRANSFER_TIMEOUT_SECONDS=1800


class _DownloadExpired(TimeoutError):
    # HTTPResponse interprets ValueError from a chunk-size read as malformed
    # framing. Keep expiry distinct until the public download/copy boundary.
    pass


class _DownloadDeadline:
    """One elapsed-time budget; socket timeouts alone only limit inactivity."""
    def __init__(self):
        self.end=time.monotonic()+TRANSFER_TIMEOUT_SECONDS

    def remaining(self):
        remaining=self.end-time.monotonic()
        if remaining<=0:
            raise _DownloadExpired('Transfer time limit exceeded')
        return remaining

    def arm(self,sock):
        sock.settimeout(min(60,self.remaining()))


class _DeadlineReader(io.RawIOBase):
    """Re-arm the deadline at each recv, including readline/chunk framing.

    HTTPResponse.read/readline may perform many underlying reads before they
    return. A buffered wrapper above this raw reader cannot hide a slow trickle
    from the absolute budget. No timer thread or abandoned I/O is needed.
    """
    def __init__(self,raw,sock,deadline):
        self.raw,self.sock,self.deadline=raw,sock,deadline

    def readable(self):
        return True

    def readinto(self,buffer):
        self.deadline.arm(self.sock)
        try:
            count=self.raw.readinto(buffer)
        except TimeoutError:
            self.deadline.remaining()
            raise
        self.deadline.remaining()
        return count

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()


class _ResponseSocket:
    def __init__(self,sock,deadline):
        self.sock,self.deadline=sock,deadline

    def makefile(self,mode):
        raw=self.sock.makefile(mode,buffering=0)
        return io.BufferedReader(_DeadlineReader(raw,self.sock,self.deadline))


class _DownloadHTTPS(PinnedHTTPS):
    """Pinned HTTPS with a shared deadline for connect, TLS, headers and body."""
    def __init__(self,host,deadline):
        self.deadline=deadline
        super().__init__(host,443,timeout=min(60,deadline.remaining()))
        self.response_class=lambda sock,**kwargs: http.client.HTTPResponse(
            _ResponseSocket(sock,deadline),**kwargs)

    def connect(self):
        # Keep the public-address validation and one DNS resolution of
        # PinnedHTTPS. The OS resolver is synchronous: reject an over-budget
        # result before opening any socket, without leaving a resolver thread.
        self.deadline.remaining()
        addresses=public_addresses(self.host)
        self.deadline.remaining()
        last=None
        for family,kind,proto,_,address in addresses:
            self.deadline.remaining()
            sock=socket.socket(family,kind,proto)
            try:
                self.deadline.arm(sock)
                sock.connect(address)
                self.deadline.arm(sock)
                sock=self._context.wrap_socket(sock,server_hostname=self.host)
                self.deadline.remaining()
                self.sock=sock
                return
            except OSError as exc:
                last=exc
            finally:
                if sock is not self.sock:
                    sock.close()
        self.deadline.remaining()
        raise last or OSError('Source connection failed')

    def send(self,data):
        if self.sock is None:
            self.connect()
        self.deadline.arm(self.sock)
        super().send(data)
        self.deadline.remaining()


class LegacyUnverified(ValueError):
    """A previous cache has no trustworthy source identity yet."""


class DescriptorFileResponse(FileResponse):
    """Use Starlette's HEAD/range contract on one verified Linux descriptor.

    The supported runtime is Linux/WSL. /proc/self/fd pins the already-open
    inode even when its cache name is removed or replaced before transmission.
    Disable pathsend: an ASGI server must not defer opening until after close.
    """
    def __init__(self, descriptor, *, available, **kwargs):
        self.descriptor=descriptor
        self.available=available
        try:
            super().__init__(f'/proc/self/fd/{descriptor}',stat_result=os.fstat(descriptor),**kwargs)
        except BaseException:
            os.close(descriptor)
            self.descriptor=None
            raise

    async def __call__(self, scope, receive, send):
        scope={**scope,'extensions':{key:value for key,value in scope.get('extensions',{}).items()
                                    if key!='http.response.pathsend'}}
        try:
            try:
                await asyncio.to_thread(self.available)
            except (ValueError,OSError):
                return await JSONResponse({'error':'file_unavailable_or_expired'},status_code=404)(scope,receive,send)
            await super().__call__(scope,receive,send)
        finally:
            if self.descriptor is not None:
                os.close(self.descriptor)
                self.descriptor=None

    def __del__(self):
        # Also release a response abandoned before ASGI calls it.
        descriptor=getattr(self,'descriptor',None)
        if descriptor is not None:
            os.close(descriptor)
            self.descriptor=None


def _transfer_length(content_length, maximum, *, basis='file'):
    if content_length is None:
        return None
    try:
        declared=int(content_length)
    except (ValueError,TypeError):
        raise ValueError('Invalid Content-Length') from None
    if declared<0:
        raise ValueError('Invalid Content-Length')
    if declared>maximum:
        raise TransferLimitExceeded(declared,basis=basis)
    return declared


def decoded_gateway_chunks(chunks, maximum, *, content_length=None, content_encoding='identity', deadline=None):
    """Bound wire and decoded bytes separately; accept one complete gzip member.

    Content-Length describes the wire. SHA256, file size and cache accounting
    describe decoded bytes. Reject concatenated gzip members and all trailing
    bytes, including zero padding. Never use an unbounded decoder flush.
    """
    encoding=content_encoding.strip().lower()
    if encoding not in ('','identity','gzip'):
        raise ValueError('Unsupported gateway Content-Encoding')
    declared=_transfer_length(content_length,maximum,basis='wire')
    decoder=zlib.decompressobj(zlib.MAX_WBITS|16) if encoding=='gzip' else None
    wire=decoded=0
    deadline=deadline or _DownloadDeadline()

    def check_time():
        try:
            deadline.remaining()
        except _DownloadExpired:
            raise ValueError('Transfer time limit exceeded')

    for chunk in chunks:
        check_time()
        wire+=len(chunk)
        if wire>maximum:
            raise TransferLimitExceeded(wire,basis='wire')
        if declared is not None and wire>declared:
            raise ValueError('Incomplete file transfer')
        for offset in range(0,len(chunk),TRANSFER_CHUNK_BYTES):
            block=chunk[offset:offset+TRANSFER_CHUNK_BYTES]
            if decoder is None:
                decoded+=len(block)
                if decoded>maximum:
                    raise TransferLimitExceeded(decoded,basis='decoded')
                yield block
                continue
            if decoder.eof:
                raise ValueError('Concatenated gzip members or trailing data are not accepted')
            while True:
                check_time()
                try:
                    output=decoder.decompress(block,min(TRANSFER_CHUNK_BYTES,maximum-decoded+1))
                except zlib.error:
                    raise ValueError('Invalid gzip attachment') from None
                block=decoder.unconsumed_tail
                decoded+=len(output)
                if decoded>maximum:
                    raise TransferLimitExceeded(decoded,basis='decoded')
                if decoder.unused_data:
                    raise ValueError('Concatenated gzip members or trailing data are not accepted')
                if output:
                    yield output
                if decoder.eof or not block and not output:
                    break
                # Drain buffered output with a bounded decompress(b'', limit)
                # if all input was consumed; flush() does not bound its output.
    check_time()
    if declared is not None and wire!=declared:
        raise ValueError('Incomplete file transfer')
    if decoder is not None and not decoder.eof:
        raise ValueError('Incomplete gzip attachment')


def filename(value):
    name=re.sub(r'[\x00-\x1f\x7f/\\<>:"|?*]','_',str(value or 'attachment'))[:180].strip(' .')
    return name or 'attachment'


def mime(value, name):
    value=value or mimetypes.guess_type(name)[0] or 'application/octet-stream'
    if not isinstance(value,str) or len(value)>512 or any(ord(c)<32 or ord(c)==127 for c in value):
        return 'application/octet-stream'
    parts=value.split(';')
    value=parts[0].strip().lower()
    if not re.fullmatch(r'[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+',value):
        return 'application/octet-stream'
    # WAHA preserves a nonempty input MIME when convert=false. This parameter
    # is part of its Opus voice contract; arbitrary header parameters are not.
    codecs=[part.split('=',1)[1].strip().lower() for part in parts[1:]
            if '=' in part and part.split('=',1)[0].strip().lower()=='codecs']
    if value=='audio/ogg' and codecs in (['opus'],['"opus"']):
        return value+'; codecs=opus'
    return value


def copy_bounded(chunks, target, maximum, content_length=None, *, deadline=None):
    total=0
    digest=hashlib.sha256()
    deadline=deadline or _DownloadDeadline()
    target=Path(target)
    created=False
    directory=None
    try:
        declared=_transfer_length(content_length,maximum)
        # Never truncate an existing path or follow a link left in a cache.
        # Only this invocation's newly created partial file is cleaned up.
        directory=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        descriptor=os.open(target.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        created=True
        with os.fdopen(descriptor,'wb') as output:
            for chunk in chunks:
                total+=len(chunk)
                if total>maximum: raise TransferLimitExceeded(total)
                deadline.remaining()
                output.write(chunk)
                digest.update(chunk)
        deadline.remaining()
        if declared is not None and total!=declared:
            raise ValueError('Incomplete file transfer')
        return total,digest.hexdigest()
    except BaseException as exc:
        if created:
            try:
                os.unlink(target.name,dir_fd=directory)
            except FileNotFoundError:
                pass
        if isinstance(exc,_DownloadExpired):
            raise ValueError('Transfer time limit exceeded') from None
        raise
    finally:
        if directory is not None:
            os.close(directory)


def download_public(url,target,maximum):
    try:
        parts=urlsplit(url)
        if parts.scheme!='https' or not parts.hostname or parts.username or parts.password or parts.fragment or parts.port not in (None,443):
            raise ValueError('Source file requires a public HTTPS URL')
        if len(url)>16384 or any(ord(c)<33 for c in url): raise ValueError('Invalid source URL')
        deadline=_DownloadDeadline()
        connection=_DownloadHTTPS(parts.hostname,deadline)
        response=None
        try:
            connection.request('GET',(parts.path or '/')+('?' + parts.query if parts.query else ''),
                               headers={'Accept-Encoding':'identity','User-Agent':'WhatsAppPersonalBridge/0.2'})
            response=connection.getresponse()
            deadline.remaining()
            if response.status!=200:
                raise ValueError('Source download failed or redirected; request a fresh file reference')
            if response.getheader('Content-Encoding','identity').lower() not in ('','identity'):
                raise ValueError('Encoded download is not accepted')
            return copy_bounded(iter(lambda:response.read1(TRANSFER_CHUNK_BYTES),b''),target,maximum,
                                response.getheader('Content-Length'),deadline=deadline)
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                connection.close()
    except _DownloadExpired:
        raise ValueError('Transfer time limit exceeded') from None
    except ValueError: raise
    except Exception:
        raise ValueError('File source is unreachable or is not a public HTTPS endpoint') from None


class Media:
    REVOKED = 'Source message revoked'
    UNAVAILABLE = 'Source message unavailable on linked device'
    LIFETIME_UNAVAILABLE = 'Source attachment lifetime no longer permits access'
    SOURCE_CHANGED = 'Source attachment changed; request it again'
    LEGACY_INVALIDATED = 'Transfer invalidated by schema upgrade; request the file again'
    LEGACY_UNAVAILABLE = 'Source unavailable after upgrade; request the file again'

    def __init__(self,store,settings,gateway):
        self.store,self.settings,self.gateway=store,settings,gateway
        self.cipher=Fernet(secret(settings.encryption_key_file).encode())
        self.root=settings.database.parent/'media-cache'
        self.root.mkdir(exist_ok=True,mode=0o700)
        self._cache_directory()

    def _cache_directory(self):
        info=self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise ValueError('Media cache must be a physical directory without group or public write access')

    def backfill_sources(self):
        # Legacy queued downloads still have encrypted provenance. Recover it
        # before any worker starts; v6 ready files were invalidated by migration.
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute("SELECT id,source FROM media_jobs WHERE source_message_id='' AND state IN ('queued','downloading')").fetchall():
                try:
                    source=json.loads(self.cipher.decrypt(row['source']))
                    if source.get('kind')=='gateway':
                        identifier=source.get('message_id')
                        if not isinstance(identifier,str) or not identifier: raise ValueError('Missing source message')
                        db.execute('UPDATE media_jobs SET source_message_id=? WHERE id=?',(identifier,row['id']))
                        if self.store.is_revoked(db,identifier):
                            self.store.redact_media_job(db,row['id'])
                    elif source.get('kind')=='external':
                        db.execute('UPDATE media_jobs SET source_message_id=NULL WHERE id=?',(row['id'],))
                    else: raise ValueError('Unknown transfer source')
                except (InvalidToken,ValueError,TypeError,AttributeError):
                    self.store.redact_media_job(db,row['id'],self.LEGACY_UNAVAILABLE)
            for row in db.execute("SELECT source_message_id,source FROM media_jobs WHERE source_message_id IS NOT NULL AND source<>X''").fetchall():
                try:
                    source=json.loads(self.cipher.decrypt(row['source']))
                    if source.get('kind')=='gateway':
                        self.store.remember_message_context(db,row['source_message_id'],source.get('chat_id'),source.get('timestamp'))
                except (InvalidToken,ValueError,TypeError,AttributeError):
                    # No trustworthy provenance can be inferred from a broken
                    # encrypted source. Existing transfer handling owns errors.
                    pass

    @classmethod
    def _redaction_error(cls,row):
        # Exact internal markers repair old v7 cancellations whose provenance
        # was lost. Arbitrarily cancelled external uploads keep their metadata.
        if row['state']!='cancelled': return None
        error=row['error']
        if error in (cls.REVOKED,cls.LIFETIME_UNAVAILABLE,cls.SOURCE_CHANGED): return error
        if row['source_message_id'] is None and error==cls.LEGACY_INVALIDATED: return error
        if row['source_message_id']=='' and error==cls.LEGACY_UNAVAILABLE: return error
        return None

    def path(self,identifier):
        if not re.fullmatch(r'media_[0-9a-f]{32}',identifier): raise ValueError('Invalid transfer ID')
        self._cache_directory()
        return self.root/(identifier+'.bin')

    def _remove(self,identifier):
        name=self.path(identifier).name
        directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            try:
                os.unlink(name,dir_fd=directory)
            except FileNotFoundError:
                pass
        finally:
            os.close(directory)

    def _verify_cache(self,row,*,keep_open=False):
        """Check the bytes actually present, not only persisted digest metadata."""
        target=self.path(row['id'])
        directory=None
        try:
            directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            descriptor=os.open(target.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            with os.fdopen(descriptor,'rb') as cached:
                info=os.fstat(cached.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode & 0o022
                        or info.st_size!=row['size'] or info.st_size>self.settings.max_attachment_bytes):
                    raise ValueError('Invalid cached attachment')
                digest=hashlib.sha256()
                size=0
                while chunk:=cached.read(TRANSFER_CHUNK_BYTES):
                    size+=len(chunk)
                    if size>self.settings.max_attachment_bytes:
                        raise ValueError('Invalid cached attachment')
                    digest.update(chunk)
                if size!=row['size'] or digest.hexdigest()!=row['sha256']:
                    raise ValueError('Invalid cached attachment')
                if keep_open:
                    cached.seek(0)
                    return os.dup(cached.fileno())
        except (OSError,ValueError):
            with self.store.db() as db:
                db.execute("UPDATE media_jobs SET state='failed',size=NULL,sha256=NULL,source=X'',error=? WHERE id=? AND state='ready'",
                           ('Cached attachment failed integrity verification; request the file again',row['id']))
            # unlink removes a link itself, never the object it points to.
            if directory is not None:
                try:
                    os.unlink(target.name,dir_fd=directory)
                except FileNotFoundError:
                    pass
            raise ValueError('Cached attachment failed integrity verification; request the file again') from None
        finally:
            if directory is not None:
                os.close(directory)

    def _lifetime_blocked(self,db,row):
        if not row['source_message_id']: return False
        if self.store._message_state(db,row['source_message_id'])['state'] in lifetime.BLOCKED:
            return True
        if row['source']:
            try:
                source=json.loads(self.cipher.decrypt(row['source']))
                return lifetime.state(source.get('lifetime')) in lifetime.BLOCKED
            except (InvalidToken,ValueError,TypeError,AttributeError):
                # A damaged encrypted source must never enable an old cache.
                return True
        return False

    def _verify_live(self,row):
        if row['source_message_id'] is None:
            return
        from .live_attachments import read_source, SourceChanged
        legacy=False
        try:
            source=json.loads(self.cipher.decrypt(row['source'])) if row['source'] else {}
            legacy=source.get('provenance') not in ('live_gateway','archive_gateway')
            if legacy:
                # Old archive caches discarded their provenance after download.
                # Rebind this same transfer only after checking the exact source
                # and the actual cache bytes. Never create or repeat a send.
                identifier=row['source_message_id']
                if not identifier:
                    raise LegacyUnverified('Legacy attachment is unverified; request the file again')
                message=self.store.message(identifier)
                expected_time=source.get('timestamp')
                if expected_time is None and message:
                    expected_time=message['timestamp']
                expected_media=source.get('media_identity')
                if expected_media is None and message and message.get('media'):
                    expected_media=json.loads(message['media']).get('identity')
                refreshed=read_source(self.store,self.settings,self.gateway,identifier,
                                     expected_timestamp=expected_time,expected_media=expected_media,acquired_source=True)
                metadata=refreshed.pop('media')
                self._verify_cache(row)
                size=row['size']
                if row['sha256']!=refreshed['media_identity']['sha256']:
                    raise SourceChanged('Legacy attachment cache differs from its source')
                if metadata.get('size',size)!=size:
                    raise SourceChanged('Legacy attachment size differs from its source')
                refreshed['provenance']='archive_gateway'
                name=filename(metadata.get('filename') or row['filename'])
                mimetype=mime(metadata.get('mimetype') or row['mimetype'],name)
                with self.store.db() as db:
                    db.execute('BEGIN IMMEDIATE')
                    if self.store.is_revoked(db,identifier) or self.store.is_unavailable(db,identifier):
                        raise ValueError(self.UNAVAILABLE)
                    db.execute("UPDATE media_jobs SET source=?,filename=?,mimetype=?,expires=min(expires,?) WHERE id=? AND state='ready'",
                               (self.cipher.encrypt(canonical(refreshed).encode()),name,mimetype,
                                (refreshed.get('lifetime') or {}).get('expires_at',row['expires']),row['id']))
                return
            if row['sha256']!=source['media_identity']['sha256']:
                raise SourceChanged('Attachment content differs from its source')
            if source['provenance']=='archive_gateway':
                return
            refreshed=read_source(self.store,self.settings,self.gateway,source['message_id'],
                        expected_timestamp=source['timestamp'],expected_media=source['media_identity'])
            if refreshed['lifetime'] and 'expires_at' in refreshed['lifetime']:
                with self.store.db() as db:
                    db.execute('UPDATE media_jobs SET expires=min(expires,?) WHERE id=?',
                               (refreshed['lifetime']['expires_at'],row['id']))
        except SourceChanged:
            with self.store.db() as db:
                self.store.redact_media_job(db,row['id'],self.SOURCE_CHANGED)
            self._remove(row['id'])
            raise ValueError(self.SOURCE_CHANGED) from None
        except Exception:
            # Provider errors may contain private URLs or response bodies. A
            # signed URL fails closed without leaking them to its bearer.
            try:
                self.row(row['id'],row['owner'])
            except ValueError:
                pass
            if legacy:
                raise LegacyUnverified('Legacy attachment is unverified; request the file again') from None
            raise ValueError('Live attachment source could not be reverified') from None

    def _equivalent_archive_job(self,db,owner,source,now):
        """Reuse only a verified archive identity; live transfers stay separate."""
        from . import visibility
        from .live_attachments import acquired_source_visible
        identifier=source.get('message_id')
        expected=source.get('media_identity')
        timestamp=source.get('timestamp')
        if (source.get('kind')!='gateway' or source.get('provenance')=='live_gateway'
                or visibility.message_identity(identifier) is None
                or not isinstance(expected,dict)
                or not acquired_source_visible(self.store,db,identifier,timestamp,expected)):
            return None
        target=visibility.canonical_identifier(db,identifier,self.store._canonical_chat)
        variants=visibility.identifier_variants(db,identifier,self.store._canonical_chat)
        rows=db.execute('''SELECT * FROM media_jobs WHERE owner=? AND expires>?
            AND source_message_id IN (SELECT value FROM json_each(?))
            AND state IN ('queued','downloading','ready') ORDER BY created DESC''',
            (owner,now,canonical(variants)))
        for row in rows:
            if row['source']:
                try:
                    saved=json.loads(self.cipher.decrypt(row['source']))
                except (InvalidToken,ValueError,TypeError):
                    continue
                if not isinstance(saved,dict): continue
                prior_media=saved.get('media')
                prior_identity=saved.get('media_identity') or (
                    prior_media.get('identity') if isinstance(prior_media,dict) else None)
                if (saved.get('kind')!='gateway' or saved.get('provenance') not in (None,'archive_gateway')
                        or visibility.message_identity(saved.get('message_id')) is None
                        or visibility.canonical_identifier(db,saved['message_id'],self.store._canonical_chat)!=target
                        or self.store._canonical_chat(db,saved.get('chat_id'))!=self.store._canonical_chat(db,source.get('chat_id'))
                        or saved.get('timestamp')!=timestamp
                        or prior_identity is not None and prior_identity!=expected
                        or prior_identity is None and saved.get('provenance') is not None):
                    continue
                # Legacy queued sources can lack the original digest. Their
                # full key and timestamp still bind the acquired row proven
                # above; the worker obtains its digest before any download.
            elif row['state']!='ready':
                continue
            # A legacy ready job may have discarded its encrypted source. Its
            # verified cache digest must match; ready()/ _verify_live then binds
            # that same job to the provider and checks the actual cached bytes.
            if row['state']=='ready' and (row['sha256']!=expected.get('sha256') or not self.path(row['id']).is_file()):
                continue
            return row
        return None

    def enqueue(self,owner,source,name='',mimetype=''):
        if source['kind']=='external':
            u=urlsplit(source['download_url'])
            if u.scheme!='https' or not u.hostname or u.username or u.fragment:
                raise ValueError('Source file requires HTTPS')
        now=time.time()
        # Native file IDs remain stable when ChatGPT refreshes an expiring download URL.
        stable={k:v for k,v in source.items() if k!='download_url'}
        identity=hashlib.sha256(canonical([stable,name,mimetype]).encode()).hexdigest()
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            message_id=source.get('message_id') if source.get('kind')=='gateway' else None
            if message_id:
                self.store.remember_message_context(db,message_id,source.get('chat_id'),source.get('timestamp'))
                self.store.observe_message_lifetime(message_id,source.get('chat_id'),source.get('lifetime'),db=db)
            if self.store.is_revoked(db,message_id): raise ValueError(self.REVOKED)
            if self.store.is_unavailable(db,message_id,chat_id=source.get('chat_id')):
                raise ValueError(self.UNAVAILABLE)
            previous=db.execute("SELECT id FROM media_jobs WHERE owner=? AND identity=? AND expires>? AND state IN ('queued','downloading','ready') ORDER BY created DESC LIMIT 1",(owner,identity,now)).fetchone()
            if previous is None:
                previous=self._equivalent_archive_job(db,owner,source,now)
            if previous:
                identifier=previous[0]
                # A caller may refresh an expiring URL while its download is still queued.
                if source['kind']=='external':
                    db.execute("UPDATE media_jobs SET source=? WHERE id=? AND state='queued'",(self.cipher.encrypt(canonical(source).encode()),identifier))
            else:
                count=db.execute("SELECT count(*) FROM media_jobs WHERE state IN ('queued','downloading') AND expires>?",(now,)).fetchone()[0]
                if count>=100: raise ValueError('File transfer queue is full; wait for current transfers')
                identifier='media_'+uuid.uuid4().hex
                name=filename(name)
                expires=now+self.settings.media_ttl_seconds
                if source.get('lifetime',{}):
                    expires=min(expires,source['lifetime'].get('expires_at',expires))
                db.execute('INSERT INTO media_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (identifier,owner,identity,'queued',self.cipher.encrypt(canonical(source).encode()),name,mime(mimetype,name),None,None,
                     now,expires,None,message_id))
        return self.status(identifier,owner)

    def row(self,identifier,owner=None):
        self.path(identifier)
        self.backfill_sources()
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            r=db.execute('SELECT * FROM media_jobs WHERE id=?',(identifier,)).fetchone()
            if r and owner is not None and r['owner']!=owner: raise ValueError('Transfer not found')
            if r:
                revoked=self.store.is_revoked(db,r['source_message_id'])
                error=(self.REVOKED if revoked else self.LIFETIME_UNAVAILABLE if self._lifetime_blocked(db,r)
                       else self._redaction_error(r))
                if error:
                    self.store.redact_media_job(db,identifier,error)
                    r=db.execute('SELECT * FROM media_jobs WHERE id=?',(identifier,)).fetchone()
                unavailable=self.store.is_unavailable(db,r['source_message_id'])
                if not unavailable and r['source'] and r['source_message_id']:
                    source=json.loads(self.cipher.decrypt(r['source']))
                    if source.get('provenance') in ('live_gateway','archive_gateway'):
                        from .live_attachments import acquired_source_visible
                        uncertain=bool(self.store._message_state(db,r['source_message_id']).get(
                            'clear_chat_coverage',{}).get('boundary_unknown'))
                        preserved=(source['provenance']=='archive_gateway' and acquired_source_visible(
                            self.store,db,r['source_message_id'],source.get('timestamp'),source.get('media_identity')))
                        unavailable=uncertain and not preserved
        if not r or owner is not None and r['owner']!=owner: raise ValueError('Transfer not found')
        if r['state']=='cancelled': self._remove(identifier)
        if r['expires']<=time.time(): raise ValueError('Transfer expired; request the file again')
        value=dict(r)
        if unavailable and not revoked and r['state']!='cancelled':
            # Local deletion is a visibility decision, not revocation. Keep
            # the private job/cache intact so a later trusted restore can work.
            value.update(state='unavailable',error=self.UNAVAILABLE,
                         filename='',mimetype='',size=None,sha256=None)
        return value

    def status(self,identifier,owner):
        row=self.row(identifier,owner)
        value={k:row[k] for k in ('id','state','filename','mimetype','size','sha256','expires','error')}
        value['duration_seconds']=None
        with self.store.db() as db:
            db.execute('BEGIN')
            value['cache']=media_diagnostics.quota_snapshot(db,self.settings)
            failure=media_diagnostics.read_failure(db,identifier) if row['state']=='failed' else None
        if self._redaction_error(row):
            # The public projection independently enforces the redaction contract.
            value.update(filename='',mimetype='',size=None,sha256=None)
        if row['state']=='ready':
            try:
                download_url=self.url(identifier,owner)
            except LegacyUnverified as exc:
                value.update(state='legacy_unverified',sha256=None,error=str(exc),
                             limit_bytes=self.settings.max_attachment_bytes,
                             recovery='The existing cache is preserved. Retry source verification when available or request the attachment again; do not repeat a send.')
                return value
            row=self.row(identifier,owner)
            value.update({k:row[k] for k in ('state','filename','mimetype','size','sha256','expires','error')})
            if row['state']=='ready':
                value['download_url']=download_url
                if row['source']:
                    source=json.loads(self.cipher.decrypt(row['source']))
                    value['duration_seconds']=source.get('duration_seconds')
        elif row['state'] in ('queued','downloading'):
            value['next_tool']='get_transfer_status'
        elif row['state']=='failed':
            value['recovery']='This transfer cannot resume. Request the attachment again with get_attachment, or provide a fresh file with prepare_file.'
            if failure:
                value.update(error_code='TRANSFER_FAILED',failure=failure,
                             recovery=media_diagnostics.RECOVERY[failure['reason']])
        value['limit_bytes']=self.settings.max_attachment_bytes
        return value

    def ready(self,identifier,owner):
        row=self.row(identifier,owner)
        if row['state']!='ready' or not self.path(identifier).is_file(): raise ValueError('Transfer is not ready')
        self._verify_cache(row)
        self._verify_live(row)
        # The provider read can overlap a local removal or expiry.
        row=self.row(identifier,owner)
        if row['state']!='ready': raise ValueError('Transfer is not ready')
        return row

    def url(self,identifier,owner,*,internal=False):
        row=self.ready(identifier,owner)
        grant=self.cipher.encrypt(canonical({'purpose':'media-download','id':identifier,'owner':owner,'expires':row['expires']}).encode()).decode()
        origin=self.settings.media_gateway_origin if internal else self.settings.public_url
        return origin+'/files/'+grant

    def resolve(self,grant,*,owner=None,maximum=None):
        if len(grant)>4096: raise ValueError('Invalid download grant')
        try:
            decoded=base64.b64decode(grant,altchars=b'-_',validate=True)
            if base64.urlsafe_b64encode(decoded).decode()!=grant: raise ValueError('Invalid download grant')
            data=json.loads(self.cipher.decrypt(grant.encode(),ttl=self.settings.media_ttl_seconds))
            if data['purpose']!='media-download' or data['expires']<=time.time(): raise ValueError('Expired download grant')
            row=self.row(data['id'],owner)
            if row['state']!='ready': raise ValueError('File not ready')
            if data.get('owner',row['owner'])!=row['owner']: raise ValueError('Invalid download grant')
            if row['source'] and 'owner' not in data: raise ValueError('Invalid download grant')
            if maximum is not None and (type(row['size']) is not int or not 0<=row['size']<=maximum):
                raise ValueError('Attachment exceeds the bounded resource read limit')
            row=self.ready(data['id'],row['owner'])
            return self.path(data['id']),row
        except (InvalidToken,KeyError,TypeError,UnicodeError):
            raise ValueError('Invalid download grant') from None

    def download_response(self,grant):
        _,row=self.resolve(grant)
        descriptor=self._verify_cache(row,keep_open=True)
        def available():
            # Recheck revocation/expiry after the potentially large hash read.
            current=self.row(row['id'],row['owner'])
            if current['state']!='ready' or current['sha256']!=row['sha256'] or current['size']!=row['size']:
                raise ValueError('File not ready')
        try:
            available()
        except BaseException:
            os.close(descriptor)
            raise
        return DescriptorFileResponse(descriptor,available=available,media_type=row['mimetype'],filename=row['filename'],
            headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'})

    def clean(self):
        self.backfill_sources()
        now=time.time()
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            rows=db.execute("""SELECT * FROM media_jobs WHERE
                source_message_id IN (SELECT message_id FROM message_mutations WHERE kind='revoked')
                OR source_message_id IN (SELECT id FROM messages WHERE deleted=1)
                OR (state='cancelled' AND error IN (?,?,?))""",
                (self.REVOKED,self.LEGACY_INVALIDATED,self.LEGACY_UNAVAILABLE)).fetchall()
            for row in rows:
                error=self.REVOKED if self.store.is_revoked(db,row['source_message_id']) else self._redaction_error(row)
                if error: self.store.redact_media_job(db,row['id'],error)
            for row in db.execute("SELECT * FROM media_jobs WHERE source_message_id IS NOT NULL AND state NOT IN ('cancelled','expired')").fetchall():
                if self._lifetime_blocked(db,row):
                    self.store.redact_media_job(db,row['id'],self.LIFETIME_UNAVAILABLE)
            expired=[r[0] for r in db.execute("""SELECT id FROM media_jobs WHERE
                (expires<=? AND (state!='expired' OR filename<>'' OR mimetype<>'' OR size IS NOT NULL
                                OR sha256 IS NOT NULL OR source<>X'')) OR state='cancelled'""",(now,))]
            for identifier in expired:
                self._remove(identifier)
            # Keep the transfer ledger identity/state, not content metadata
            # after its availability window. Older expired rows are scrubbed
            # by the same pass; backups remain a separate retention boundary.
            db.execute("UPDATE media_jobs SET state='expired',source=X'',filename='',mimetype='',size=NULL,sha256=NULL,error=NULL WHERE expires<=? AND state!='cancelled'",(now,))
            media_diagnostics.clean_failures(db,now)

    def process_one(self):
        from .diagnostics import reference
        self.clean()
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=next((item for item in db.execute("SELECT * FROM media_jobs WHERE state='queued' AND expires>? ORDER BY created",(time.time(),)).fetchall()
                      if not self.store.is_unavailable(db,item['source_message_id'])),None)
            if not row: return False
            row=dict(row)
            db.execute("UPDATE media_jobs SET state='downloading' WHERE id=?",(row['id'],))
            media_diagnostics.forget_failure(db,row['id'])
            quota=media_diagnostics.quota_snapshot(db,self.settings)
        target=self.path(row['id'])
        def still_downloading():
            if self.row(row['id'])['state']!='downloading':
                raise ValueError('Transfer cancelled')
        try:
            maximum=quota['effective_limit_bytes']
            if maximum<=0: raise CacheCapacityExceeded()
            # A crash may leave an incomplete file belonging to this job.
            # A claimed transfer owns this UUID path; remove only that entry.
            self._remove(row['id'])
            source=json.loads(self.cipher.decrypt(row['source']))
            still_downloading()
            if source['kind']=='external':
                size,sha=download_public(source['download_url'],target,maximum)
                name,mimetype=row['filename'],row['mimetype']
            else:
                from .live_attachments import read_source
                live=source.get('provenance')=='live_gateway'
                acquired=self.store.message(source['message_id']) if not live else None
                if acquired:
                    source.setdefault('timestamp',acquired['timestamp'])
                    if acquired.get('media'):
                        stored_identity=json.loads(acquired['media']).get('identity')
                        if stored_identity:
                            source.setdefault('media_identity',stored_identity)
                # Both archive and live retrieval bind the exact source before
                # asking WAHA to regenerate its attachment. An old cache URL is
                # not evidence of message identity or file integrity.
                initial=read_source(self.store,self.settings,self.gateway,source['message_id'],
                                    expected_timestamp=source.get('timestamp'),
                                    expected_media=source.get('media_identity'),acquired_source=not live)
                still_downloading()
                refreshed=read_source(self.store,self.settings,self.gateway,source['message_id'],
                                     download_media=True,expected_timestamp=initial['timestamp'],
                                     expected_media=initial['media_identity'],acquired_source=not live)
                media=refreshed.pop('media')
                source={**refreshed,'provenance':'live_gateway' if live else 'archive_gateway'}
                still_downloading()
                try:
                    size,sha=self.gateway.attachment_to_file(media,target,maximum)
                except Exception as exc:
                    from .gateway import GatewayUnavailable
                    if not isinstance(exc,GatewayUnavailable) or exc.status_code not in (404,410):
                        raise
                    # A gateway cache may expire even after regeneration. Retry
                    # this download once, binding the refreshed URL to the same
                    # message, timestamp and digest; never retry an outbound send.
                    still_downloading()
                    refreshed=read_source(self.store,self.settings,self.gateway,source['message_id'],
                                         download_media=True,expected_timestamp=source['timestamp'],
                                         expected_media=source['media_identity'],acquired_source=not live)
                    media=refreshed.pop('media')
                    source={**refreshed,'provenance':source['provenance']}
                    still_downloading()
                    size,sha=self.gateway.attachment_to_file(media,target,maximum)
                if sha!=source['media_identity']['sha256']:
                    raise ValueError('Downloaded attachment content differs from its verified source')
                if media.get('size',size)!=size:
                    raise ValueError('Downloaded attachment size differs from its verified source')
                name=filename(media.get('filename') or row['filename'])
                mimetype=mime(media.get('mimetype') or row['mimetype'],name)
                if name=='attachment':
                    base_mime=mimetype.split(';',1)[0]
                    extension={'audio/ogg':'.ogg','image/jpeg':'.jpg'}.get(base_mime) or mimetypes.guess_extension(base_mime) or ''
                    name+=extension
            with self.store.db() as db:
                db.execute('BEGIN IMMEDIATE')
                revoked=self.store.is_revoked(db,row['source_message_id'])
                unavailable=self.store.is_unavailable(db,row['source_message_id'])
                if source.get('provenance') in ('live_gateway','archive_gateway'):
                    from .live_attachments import acquired_source_visible
                    uncertain=bool(self.store._message_state(db,row['source_message_id']).get(
                        'clear_chat_coverage',{}).get('boundary_unknown'))
                    preserved=(source['provenance']=='archive_gateway' and acquired_source_visible(
                        self.store,db,row['source_message_id'],source.get('timestamp'),source.get('media_identity')))
                    unavailable=unavailable or uncertain and not preserved
                if lifetime.state(source.get('lifetime')) in lifetime.BLOCKED:
                    self.store.redact_media_job(db,row['id'],self.LIFETIME_UNAVAILABLE)
                    unavailable=True
                if revoked:
                    self.store.redact_media_job(db,row['id'])
                elif unavailable:
                    db.execute("UPDATE media_jobs SET state='queued' WHERE id=? AND state='downloading'",(row['id'],))
                # Gateway jobs retain only encrypted, content-free provenance.
                # Archive caches remain usable without another provider read.
                retained=self.cipher.encrypt(canonical(source).encode()) if source.get('provenance') in ('live_gateway','archive_gateway') else b''
                expires=(source.get('lifetime') or {}).get('expires_at',row['expires'])
                completed=not unavailable and db.execute("UPDATE media_jobs SET state='ready',size=?,sha256=?,filename=?,mimetype=?,source=?,expires=min(expires,?) WHERE id=? AND state='downloading'",(size,sha,name,mimetype,retained,expires,row['id'])).rowcount
                final_state=db.execute('SELECT state FROM media_jobs WHERE id=?',(row['id'],)).fetchone()[0]
            if not completed:
                self._remove(row['id'])
                if getattr(self,'diagnostics',None):
                    self.diagnostics.emit('transfer.finished',state=final_state,job_ref=reference(row['id']))
                return True
            if getattr(self,'diagnostics',None):
                self.diagnostics.emit('transfer.finished',state='ready',bytes=size,job_ref=reference(row['id']))
        except Exception as exc:
            self._remove(row['id'])
            failure=media_diagnostics.limit_failure(exc,quota)
            reason=(media_diagnostics.MESSAGES[failure['reason']] if failure else
                    str(exc) if isinstance(exc,ValueError) else 'File transfer failed; request a fresh transfer')
            recorded_failure=None
            with self.store.db() as db:
                db.execute('BEGIN IMMEDIATE')
                if self.store.is_revoked(db,row['source_message_id']):
                    self.store.redact_media_job(db,row['id'])
                elif self.store.is_unavailable(db,row['source_message_id']):
                    db.execute("UPDATE media_jobs SET state='queued' WHERE id=? AND state='downloading'",(row['id'],))
                else:
                    updated=db.execute("UPDATE media_jobs SET state='failed',error=?,source=X'' WHERE id=? AND state='downloading'",(reason[:250],row['id'])).rowcount
                    if updated and failure:
                        media_diagnostics.save_failure(db,row['id'],failure)
                        recorded_failure=failure
                final_state=db.execute('SELECT state FROM media_jobs WHERE id=?',(row['id'],)).fetchone()[0]
            if getattr(self,'diagnostics',None):
                self.diagnostics.emit('transfer.finished','error' if final_state=='failed' else 'info',
                    state=final_state,job_ref=reference(row['id']),exception=type(exc).__name__,
                    **({'error_code':'TRANSFER_FAILED'} if final_state=='failed' else {}),
                    **(media_diagnostics.log_fields(recorded_failure) if recorded_failure else {}))
        return True

"""Restartable import of all history actually supplied by the linked WhatsApp device."""
from contextlib import nullcontext
import hashlib
import json
import time
import uuid

from .store import canonical,utc
from .history_coverage import commit_page,skip_chat,job_coverage


class HistorySync:
    def __init__(self,store,settings,gateway):
        self.store,self.settings,self.gateway=store,settings,gateway
        self.resolve_chat=store.canonical_chat

    def start(self,owner,key,chat_ids=None,since=0,until=None):
        requested_until=until
        until=int(time.time()) if until is None else until
        if not 0<=since<=until<=time.time()+60: raise ValueError('Invalid history interval')
        chats=sorted(set(chat_ids or []))
        payload={'chat_ids':chats,'since':since,'until':until}
        # A missing until means the creation-time snapshot; retries must find that original job.
        digest=hashlib.sha256(canonical({'chat_ids':chats,'since':since,'until':requested_until}).encode()).hexdigest()
        now=time.time()
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT * FROM history_jobs WHERE request_key=?',(key,)).fetchone()
            if old:
                if old['owner']!=owner or old['request_hash']!=digest: raise ValueError('History key already used for another request')
                identifier=old['id']
            else:
                identifier='history_'+uuid.uuid4().hex
                progress={**payload,'chat_index':0,'message_offset':0,'discovery_offset':0,'discovery_complete':bool(chats),
                          'messages_scanned':0,'messages_inserted':0,'completed_chats':0,'skipped_chats':[],'current_chat':None,
                          'coverage':'available_linked_device_history','history_complete':False,'error':None,
                          'coverage_version':1,'chat_coverage':{}}
                db.execute('INSERT INTO history_jobs VALUES(?,?,?,?,?,?,?,?)',(identifier,owner,key,digest,'running',canonical(progress),now,now))
        return self.status(identifier,owner)

    def status(self,identifier,owner,*,chat_id=None,chat_limit=50,chat_offset=0):
        with self.store.db() as db:
            db.execute('BEGIN')
            row=db.execute('SELECT * FROM history_jobs WHERE id=? AND owner=?',(identifier,owner)).fetchone()
            if not row: raise ValueError('History import not found')
            progress=json.loads(row['progress'])
            detail=job_coverage(self.store,db,row,progress,chat_id=chat_id,chat_limit=chat_limit,chat_offset=chat_offset)
        count=len(progress.pop('chat_ids'))
        progress.pop('chat_coverage',None)
        return {'id':row['id'],'state':row['state'],'created_at':utc(row['created']),'updated_at':utc(row['updated']),
                'chats_discovered':count,**progress,**detail}

    def control(self,identifier,owner,action):
        if action not in ('pause','resume','cancel'): raise ValueError('Invalid history control')
        with self.store.db() as db:
            # Serialize the state check and update with cancel, completion and other controls.
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM history_jobs WHERE id=? AND owner=?',(identifier,owner)).fetchone()
            if not row: raise ValueError('History import not found')
            state={'pause':'paused','resume':'running','cancel':'cancelled'}[action]
            if row['state'] in ('cancelled','completed'):
                if action!='cancel': raise ValueError('A terminal history import cannot pause or resume')
            elif state!=row['state']:
                if action=='pause' and row['state']!='running':
                    raise ValueError('Only a running import can pause')
                if action=='resume' and row['state'] not in ('paused','failed'):
                    raise ValueError('Only a paused or failed import can resume')
                progress=json.loads(row['progress'])
                progress['error']=None
                db.execute('UPDATE history_jobs SET state=?,progress=?,updated=? WHERE id=? AND owner=? AND state=?',
                           (state,canonical(progress),time.time(),identifier,owner,row['state']))
        return self.status(identifier,owner)

    @staticmethod
    def _current(db,row):
        return db.execute("SELECT 1 FROM history_jobs WHERE id=? AND state='running' AND updated=? AND progress=?",
                          (row['id'],row['updated'],row['progress'])).fetchone() is not None

    def _save(self,row,p,state='running',*,db=None):
        with self.store.db() if db is None else nullcontext(db) as db:
            # A paused/cancelled job or a page advanced by another worker wins.
            return db.execute("UPDATE history_jobs SET state=?,progress=?,updated=? WHERE id=? AND state='running' AND updated=? AND progress=?",
                              (state,canonical(p),time.time(),row['id'],row['updated'],row['progress'])).rowcount==1

    def process_one(self):
        from .diagnostics import reference
        with self.store.db() as db:
            row=db.execute("SELECT * FROM history_jobs WHERE state='running' ORDER BY created LIMIT 1").fetchone()
        if not row: return False
        p=json.loads(row['progress'])
        try:
            if not p['discovery_complete']:
                requested_at=time.time()
                page=self.gateway.history_chats(p['discovery_offset'])
                for chat in page:
                    identifier=chat.get('id')
                    if isinstance(identifier,dict): identifier=identifier.get('_serialized')
                    if not isinstance(identifier,str) or not identifier or len(identifier)>200:
                        raise ValueError('History source returned an invalid chat identifier')
                    if identifier not in p['chat_ids']: p['chat_ids'].append(identifier)
                p['discovery_offset']+=len(page)
                p['discovery_complete']=len(page)<100
                with self.store.db() as db:
                    db.execute('BEGIN IMMEDIATE')
                    if not self._current(db,row): return True
                    self.store.cache_chat_names(page,'history_directory',observed_at=requested_at,db=db)
                    self._save(row,p,db=db)
                return True
            if p['chat_index']>=len(p['chat_ids']):
                p['current_chat']=None
                p['available_source_exhausted']=True
                saved=self._save(row,p,'completed')
                if saved and getattr(self,'diagnostics',None):
                    self.diagnostics.emit('history.finished',state='completed',job_ref=reference(row['id']),count=p['messages_inserted'])
                return True
            chat=p['chat_ids'][p['chat_index']]
            p['current_chat']=chat
            if chat.endswith('@newsletter') or chat=='status@broadcast':
                p.setdefault('skipped_chats',[]).append({'chat_id':chat,'reason':'History is not supported for this chat type by the GOWS engine'})
                skip_chat(p,chat)
                p['chat_index']+=1
                p['message_offset']=0
                self._save(row,p)
                return True
            requested_at=time.time()
            messages=self.gateway.messages(chat,p['since'],p['until'],p['message_offset'])
            with self.store.db() as db:
                if not self._current(db,row): return True
            if len(messages)>100: raise ValueError('History provider exceeded page size')
            # Resolving aliases can call the gateway; keep network I/O outside the write lock.
            for message in messages:
                from .account_events import message_chat
                destination=self.resolve_chat(message_chat(message))
                if destination!=self.store.canonical_chat(chat) or not p['since']<=message.get('timestamp',-1)<=p['until']:
                    raise ValueError('History source returned a message outside the requested chat/interval')
            with self.store.db() as db:
                db.execute('BEGIN IMMEDIATE')
                # Serialize the entire page with control(), including receipts and counters.
                if not self._current(db,row): return True
                inserted=0
                for message in messages:
                    outcome=self.store.ingest({'event':'message.any','session':self.settings.session,'payload':message},historical=True,db=db)
                    if outcome.get('recorded') is False:
                        raise ValueError('History source returned a contradictory message identity')
                    p['messages_scanned']+=1
                    # An ignored lifetime or contradictory identity is not an
                    # insertion. Store reports an actual acquired row with an
                    # explicit duplicate=False; missing flags are not success.
                    acquired=int(outcome.get('duplicate') is False)
                    p['messages_inserted']+=acquired
                    inserted+=acquired
                commit_page(p,chat,messages,inserted,requested_at,time.time())
                db.execute('INSERT OR IGNORE INTO chats VALUES(?,NULL)',(self.store._canonical_chat(db,chat),))
                p['message_offset']+=len(messages)
                if len(messages)<100:
                    p['chat_index']+=1
                    p['completed_chats']+=1
                    p['message_offset']=0
                if not self._save(row,p,db=db): raise RuntimeError('History job changed during page commit')
        except Exception as exc:
            # A failed page rolls back its messages; preserve the last committed counters.
            p=json.loads(row['progress'])
            p['error']='History source unavailable or returned inconsistent data. Resume retries the saved page without duplicate messages.'
            saved=self._save(row,p,'failed')
            if saved and getattr(self,'diagnostics',None):
                self.diagnostics.emit('history.finished','error',state='failed',job_ref=reference(row['id']),exception=type(exc).__name__,error_code='HISTORY_FAILED')
        return True

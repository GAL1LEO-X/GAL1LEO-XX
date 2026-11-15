"""Explicit local recovery of retained transiently failed deliveries, without HTTP."""
from datetime import datetime
import hashlib
import hmac
import json
import re
import time

from .store import canonical,utc

MAX_DELIVERIES=20
MAX_REQUESTS=1000
PREFIX='private:event_recovery:'
DELIVERY_PREFIX='private:event_recovery_delivery:'
EVENT_NAMES=('message.received','whatsapp.event')


def capability():
    return {'available':True,'interface':'local_administrative_cli','automatic':False,
            'event_names':list(EVENT_NAMES),'states':['failed'],'max_deliveries':MAX_DELIVERIES,
            'max_audit_requests':MAX_REQUESTS,'protocol_replay':False}


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def attempt_limit(db,delivery_id):
    """The worker enforces this durable limit before claiming and after a failure."""
    row=db.execute('SELECT value FROM state WHERE key=?',(DELIVERY_PREFIX+str(delivery_id),)).fetchone()
    if not row: return None
    value=json.loads(row[0])['attempt_limit']
    if type(value) is not int or value<1: raise ValueError('Invalid administrative delivery attempt limit')
    return value


def supported_filters(value):
    try:
        filters=json.loads(value)
        return isinstance(filters,dict) and not set(filters)-{'chat_ids','all_chats','contains','event_types','quiet_hours'}
    except (ValueError,TypeError): return False


class EventRecovery:
    def __init__(self,store,settings):
        self.store,self.settings=store,settings

    def _context(self):
        return [str(self.store.path.resolve()),self.settings.owner_subject,self.settings.public_url]

    @staticmethod
    def _selection(subscription,delivery_ids):
        if not isinstance(subscription,str) or not re.fullmatch(r'sub_[0-9a-f]{64}',subscription):
            raise ValueError('An explicit subscription ID is required')
        if not isinstance(delivery_ids,(list,tuple)) or not 1<=len(delivery_ids)<=MAX_DELIVERIES:
            raise ValueError('Select between 1 and 20 delivery IDs')
        if any(type(value) is not int or not 1<=value<=9223372036854775807 for value in delivery_ids):
            raise ValueError('Invalid delivery ID')
        if len(set(delivery_ids))!=len(delivery_ids): raise ValueError('Duplicate delivery IDs')
        return sorted(delivery_ids)

    @staticmethod
    def _request_key(request_id):
        if not isinstance(request_id,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{7,127}',request_id):
            raise ValueError('Request ID must contain 8..128 ASCII letters, digits, dots, underscores, colons or dashes')
        return PREFIX+hashlib.sha256(request_id.encode()).hexdigest()

    def _event_reason(self,db,row,subscription,now):
        try:
            if not supported_filters(subscription['filters']): return 'unsupported_filters'
            if len(row['body'].encode())>262144: return 'payload_too_large'
            event=json.loads(row['body'])
            data=event['data']
            if event['name'] not in EVENT_NAMES or event['name']!=subscription['name']: return 'unsupported_event'
            if event['eventId']!=row['event_id']: return 'event_identity_changed'
            timestamp=datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'))
            if timestamp.tzinfo is None: return 'invalid_event'
            epoch=timestamp.timestamp()
            if not 0<=now-epoch<self.settings.event_max_age_seconds: return 'event_expired'
            filters=json.loads(subscription['filters'])
            if event['name']=='message.received':
                identifier=data['message_id']
                if row['event_id']!='evt_'+hashlib.sha256(identifier.encode()).hexdigest(): return 'event_identity_changed'
                source=db.execute('SELECT m.*,c.data AS content FROM messages m LEFT JOIN message_content c ON c.message_id=m.id WHERE m.id=?',(identifier,)).fetchone()
                if not source: return 'source_missing'
                if self.store.is_revoked(db,identifier): return 'source_revoked'
                if self.store.is_unavailable(db,identifier): return 'source_unavailable'
                if source['from_me']: return 'outgoing_message'
                content=json.loads(source['content']) if source['content'] else {}
                preview=source['body'][:250] or ('[Location]' if 'location' in content else '[Contatto]' if 'vCards' in content else '[Allegato]' if source['media'] else '')
                if (data['preview']!=preview or self.store._canonical_chat(db,data['chat_id'])!=source['chat_id'] or
                    data['has_media']!=bool(source['media']) or epoch!=source['timestamp']): return 'source_changed'
                chat=source['chat_id']
                searchable=source['body'].casefold()
            else:
                source=db.execute('SELECT * FROM account_events WHERE id=?',(data['event_id'],)).fetchone()
                if not source: return 'source_missing'
                content=json.loads(source['data'])
                # Resolve legacy reactions like the getter, without repairing
                # their persisted source during an administrative preview.
                identifier=self.store._event_source(source,content)
                if source['event_type']=='message.reaction' and not identifier: return 'invalid_event'
                reason=self.store.event_source_reason(db,source,content)
                if reason: return reason
                if (row['event_id']!=source['id'] or data['event_type']!=source['event_type'] or
                    self.store._canonical_chat(db,data['chat_id'])!=source['chat_id'] or abs(epoch-source['timestamp'])>0.000001): return 'source_changed'
                if ('message_id' in data and data['message_id'] !=
                    self.store._account_event_message_id(db,source,content)):
                    return 'source_changed'
                if source['event_type'] not in filters.get('event_types',[]): return 'filter_mismatch'
                chat=source['chat_id']
                content=self.store._event_projection(db,source,content)
                searchable=canonical(content).casefold()
            if not filters.get('all_chats') and chat not in [self.store._canonical_chat(db,value) for value in filters.get('chat_ids',[])]:
                return 'filter_mismatch'
            if filters.get('contains') and filters['contains'].casefold() not in searchable: return 'filter_mismatch'
        except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
            return 'invalid_event'
        return None

    def _preview(self,db,subscription_id,delivery_ids,now):
        subscription=db.execute('SELECT * FROM subscriptions WHERE id=?',(subscription_id,)).fetchone()
        reason=None
        if not subscription or subscription['owner']!=self.settings.owner_subject: reason='subscription_unavailable'
        elif not subscription['active'] or subscription['expires']<=now: reason='subscription_inactive_or_expired'
        elif subscription['name'] not in EVENT_NAMES: reason='unsupported_event'
        if not reason and not supported_filters(subscription['filters']): reason='unsupported_filters'
        count=db.execute('SELECT count(*) FROM state WHERE key GLOB ?',(PREFIX+'*',)).fetchone()[0]
        if not reason and count>=MAX_REQUESTS: reason='audit_capacity_reached'
        rows=[]
        snapshots=[]
        for identifier in delivery_ids:
            row=db.execute('SELECT * FROM deliveries WHERE id=? AND subscription=?',(identifier,subscription_id)).fetchone() if subscription and subscription['owner']==self.settings.owner_subject else None
            item={'delivery_id':identifier,'eligible':False}
            blocked=reason
            if not row: blocked=blocked or 'delivery_unavailable'
            else:
                item.update(event_id=row['event_id'],state=row['state'],attempts=row['attempts'],last_status=row['last_status'])
                if not blocked and row['state']!='failed': blocked='state_not_recoverable'
                status=row['last_status']
                if not blocked and (status not in (0,408,429) and not (isinstance(status,int) and 500<=status<600)):
                    blocked='terminal_status'
                limit=attempt_limit(db,identifier)
                if not blocked and row['attempts']<self.settings.max_callback_attempts and (limit is None or row['attempts']<limit):
                    blocked='attempts_not_exhausted'
                if not blocked: blocked=self._event_reason(db,row,subscription,now)
                snapshots.append({**dict(row),'body':digest(row['body']),'recovery_attempt_limit':limit})
            item.update(eligible=blocked is None,reason=blocked)
            rows.append(item)
        eligible=all(item['eligible'] for item in rows)
        result={'subscription_id':subscription_id,'eligible':eligible,'deliveries':rows,
                'fingerprint':None,'extra_attempts_per_delivery':1,'audit_requests_remaining':max(0,MAX_REQUESTS-count)}
        if reason=='audit_capacity_reached':
            result['operator_action']='Stop recovery and arrange a reviewed audit-capacity change; do not delete retained request keys or reuse request IDs'
        if eligible:
            binding={**dict(subscription),'secret':hashlib.sha256(subscription['secret']).hexdigest()}
            result['fingerprint']=digest([self._context(),self.settings.event_max_age_seconds,
                                          self.settings.max_callback_attempts,binding,snapshots])
        return result

    def preview(self,subscription,delivery_ids):
        delivery_ids=self._selection(subscription,delivery_ids)
        with self.store.db() as db:
            db.execute('BEGIN')
            return self._preview(db,subscription,delivery_ids,time.time())

    def execute(self,subscription,delivery_ids,*,fingerprint,request_id):
        delivery_ids=self._selection(subscription,delivery_ids)
        key=self._request_key(request_id)
        if not isinstance(fingerprint,str) or not re.fullmatch(r'[0-9a-f]{64}',fingerprint):
            raise ValueError('A fingerprint from an eligible preview is required')
        request=digest([self._context(),subscription,delivery_ids,fingerprint])
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
            if old:
                record=json.loads(old[0])
                if not hmac.compare_digest(record['request_hash'],request): raise ValueError('Request ID already used for a different recovery')
                return record['result']
            now=time.time()
            preview=self._preview(db,subscription,delivery_ids,now)
            if not preview['eligible']:
                raise ValueError(preview.get('operator_action','Selection is no longer eligible; obtain a new preview'))
            if not hmac.compare_digest(preview['fingerprint'],fingerprint): raise ValueError('Preview changed; inspect a new preview before execution')
            result={'subscription_id':subscription,'queued_at':utc(now),'deliveries':[
                {'delivery_id':item['delivery_id'],'event_id':item['event_id'],'attempts_before':item['attempts'],
                 'next_attempt_number':item['attempts']+1,'last_status_before':item['last_status']}
                for item in preview['deliveries']],'delivery_confirmed':False}
            for item in result['deliveries']:
                identifier=item['delivery_id']
                db.execute("UPDATE deliveries SET state='pending',next_attempt=?,lease_until=0 WHERE id=? AND state='failed'",(now,identifier))
                self.store._state(db,DELIVERY_PREFIX+str(identifier),{'attempt_limit':item['next_attempt_number'],'request_hash':request})
            self.store._state(db,key,{'context_hash':digest(self._context()),'request_hash':request,'result':result})
            return result

    def audit(self,request_id):
        key=self._request_key(request_id)
        with self.store.db() as db:
            db.execute('BEGIN')
            row=db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
            record=json.loads(row[0]) if row else None
            if not record or record['context_hash']!=digest(self._context()): raise ValueError('Unknown recovery request')
            result=record['result']
            states=[]
            for item in result['deliveries']:
                current=db.execute('SELECT state,attempts,last_status FROM deliveries WHERE id=? AND subscription=?',
                                   (item['delivery_id'],result['subscription_id'])).fetchone()
                states.append({'delivery_id':item['delivery_id'],**dict(current)} if current else {'delivery_id':item['delivery_id'],'state':'unavailable'})
        return {'execution':result,'current_deliveries':states}


def source_reason(store,settings,db,row,now):
    """Recheck a recovered delivery before its one authorized worker attempt."""
    subscription=db.execute('SELECT * FROM subscriptions WHERE id=?',(row['subscription'],)).fetchone()
    if not subscription or subscription['owner']!=settings.owner_subject: return 'subscription_unavailable'
    if not subscription['active'] or subscription['expires']<=now: return 'subscription_inactive_or_expired'
    return EventRecovery(store,settings)._event_reason(db,row,subscription,now)

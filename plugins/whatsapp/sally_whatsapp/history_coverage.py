"""Evidence from committed history pages; observed bounds never imply continuity."""
import json

from .store import utc


LIMITATIONS = [
    'available_linked_device_history_only',
    'offset_source_is_not_a_snapshot',
    'observed_bounds_do_not_prove_continuity',
    'unavailable_or_deleted_messages_not_guaranteed',
]


def evidence(progress, offset):
    return {'tracking_scope':'job_start' if progress.get('coverage_version')==1 else 'legacy_suffix',
            'tracking_started_offset':offset,'acquisition_state':'pending',
            'observed_interval':None,'pages_committed':0,'messages_scanned':0,'messages_inserted':0,
            'first_request_at':None,'last_page_at':None,'source_exhausted':None,'exhausted_at':None}


def commit_page(progress, chat, messages, inserted, requested_at, committed_at):
    record=progress.setdefault('chat_coverage',{}).setdefault(chat,evidence(progress,progress['message_offset']))
    record['first_request_at']=record['first_request_at'] or utc(requested_at)
    record['last_page_at']=utc(committed_at)
    record['pages_committed']+=1
    record['messages_scanned']+=len(messages)
    record['messages_inserted']+=inserted
    if messages:
        dates=[message['timestamp'] for message in messages]
        previous=record['observed_interval']
        record['observed_interval']={'since':min(min(dates),previous['since'] if previous else min(dates)),
                                     'until':max(max(dates),previous['until'] if previous else max(dates))}
    record['source_exhausted']=len(messages)<100
    record['acquisition_state']='source_exhausted' if record['source_exhausted'] else 'acquiring'
    if record['source_exhausted']: record['exhausted_at']=utc(committed_at)


def skip_chat(progress,chat):
    record=progress.setdefault('chat_coverage',{}).setdefault(chat,evidence(progress,progress['message_offset']))
    record['acquisition_state']='unsupported'


def describe(store,db,row,progress,chat):
    record=progress.get('chat_coverage',{}).get(chat)
    if record is None:
        if progress.get('coverage_version')==1:
            record=evidence(progress,0)
        else:
            record={'tracking_scope':'legacy_unknown','tracking_started_offset':None,'acquisition_state':'unknown',
                    'observed_interval':None,'pages_committed':None,'messages_scanned':None,'messages_inserted':None,
                    'first_request_at':None,'last_page_at':None,'source_exhausted':None,'exhausted_at':None}
    return {'job_id':row['id'],'job_state':row['state'],'requested_chat_id':chat,
            'chat_id':store._canonical_chat(db,chat),'requested_interval':{'since':progress['since'],'until':progress['until']},
            'job_created_at':utc(row['created']),'job_updated_at':utc(row['updated']),
            'provenance':'waha_history_job','history_complete':False,'gap_status':'unknown',
            'limitations':list(LIMITATIONS),**record}


def job_coverage(store,db,row,progress,*,chat_id=None,chat_limit=50,chat_offset=0):
    if not 1<=chat_limit<=100 or chat_offset<0: raise ValueError('Invalid history coverage pagination')
    wanted=store._canonical_chat(db,chat_id)
    chats=[chat for chat in progress['chat_ids'] if wanted is None or store._canonical_chat(db,chat)==wanted]
    selected=chats[chat_offset:chat_offset+chat_limit]
    return {'chat_coverage':[describe(store,db,row,progress,chat) for chat in selected],
            'chat_coverage_total':len(chats),
            'chat_coverage_next_offset':chat_offset+chat_limit if len(chats)>chat_offset+chat_limit else None,
            'gap_status':'unknown','limitations':list(LIMITATIONS)}


def chat_summaries(store,db,chat_ids,*,owner=None,limit=10):
    result={chat:{'scope':'tracked_history_jobs_only','history_complete':False,'gap_status':'unknown',
                  'limitations':list(LIMITATIONS),'attempts':[],'total_attempts':0,'truncated':False}
            for chat in chat_ids}
    if not result: return result
    sql='SELECT id,state,progress,created,updated FROM history_jobs'
    rows=db.execute(sql+(' WHERE owner=?' if owner is not None else '')+' ORDER BY updated DESC,id',
                    (owner,) if owner is not None else ())
    for row in rows:
        progress=json.loads(row['progress'])
        for chat in progress['chat_ids']:
            canonical=store._canonical_chat(db,chat)
            if canonical not in result: continue
            summary=result[canonical]
            summary['total_attempts']+=1
            if len(summary['attempts'])<limit:
                record=describe(store,db,row,progress,chat)
                # Shared qualifications sit on the summary; full evidence is available by job ID.
                for key in ('limitations','history_complete','gap_status'):
                    record.pop(key)
                summary['attempts'].append(record)
            else:
                summary['truncated']=True
    return result

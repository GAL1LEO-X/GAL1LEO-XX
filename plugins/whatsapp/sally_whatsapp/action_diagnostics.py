"""Read-only action ledger projections; no payload/result contents or retries."""
import json

from .operation_outcomes import provider_outcome
from .uncertain_review import status as review_status


def reconciliation_requirement(operation):
    """Missing historical proof is not replaced by today's phone/profile state."""
    needed = {
        'messages_send_list': 'operation_correlated_message_identity_and_receipt',
        'profile_set_profile_status': 'operation_correlated_provider_acknowledgment',
        'messages_set_star': 'operation_correlated_provider_acknowledgment',
        'groups_get_invite_code': 'original_operation_response',
        'groups_revoke_invite_code': 'original_revocation_acknowledgment',
    }
    return {'classification': 'unresolved', 'original_outcome_preserved': True,
            'pending_retry': False, 'current_state_proves_historical_effect': False,
            'required_evidence': needed.get(operation, 'operation_correlated_evidence')}


def list_uncertain(db, owner, *, limit=50, offset=0):
    if not isinstance(owner, str) or not owner:
        raise ValueError('An authenticated owner is required')
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 1000000:
        raise ValueError('Invalid action pagination')
    total = db.execute("SELECT count(*) FROM sends WHERE owner=? AND state='uncertain'", (owner,)).fetchone()[0]
    rows = db.execute("""SELECT s.key,s.state,s.created,s.updated,s.provider_id,j.operation,
        m.destination_state,m.destination_chat_id,m.metadata_state,r.result
        FROM sends s LEFT JOIN action_jobs j USING(key)
        LEFT JOIN action_job_metadata m USING(key) LEFT JOIN operation_results r USING(key)
        WHERE s.owner=? AND s.state='uncertain' ORDER BY s.created,s.key LIMIT ? OFFSET ?""", (owner, limit, offset))
    actions = []
    for row in rows:
        try: result = json.loads(row['result']) if row['result'] else None
        except (ValueError, TypeError): result = None
        actions.append({key: row[key] for key in ('key','state','created','updated')} | {
            'operation': row['operation'] or 'send_text',
            'provider_id_present': bool(row['provider_id']),
            'result_recorded': row['result'] is not None,
            'provider_outcome': provider_outcome(result),
            'metadata_state': row['metadata_state'] or 'legacy_unknown',
            'destination_state': row['destination_state'] or 'legacy_unknown',
            'destination_chat_id': row['destination_chat_id'] if row['destination_state'] == 'present' else None,
            'reconciliation': reconciliation_requirement(row['operation']),
            'diagnostic_review': review_status(db, owner, row['key']),
        })
    return {'mode': 'uncertain', 'source': 'persisted_action_ledger', 'actions': actions,
            'total': total, 'next_offset': offset + len(actions) if offset + len(actions) < total else None,
            'uncertain_are_pending_retries': False, 'historical_outcomes_rewritten': False}


def summary(db, *, owner=None):
    where, params = (' WHERE owner=?', (owner,)) if owner is not None else ('', ())
    counts = dict(db.execute('SELECT state,count(*) FROM sends' + where + ' GROUP BY state', params))
    uncertain = where + (' AND' if where else ' WHERE') + " state='uncertain'"
    by_operation = dict(db.execute("""SELECT coalesce(j.operation,'send_text'),count(*) FROM sends s
        LEFT JOIN action_jobs j USING(key)""" + uncertain + ' GROUP BY j.operation', params))
    oldest, newest = db.execute('SELECT min(created),max(created) FROM sends' + uncertain, params).fetchone()
    reviews = [review_status(db, row['owner'], row['key']) for row in
               db.execute('SELECT owner,key FROM sends' + uncertain, params)]
    active = sum(item['requires_attention'] for item in reviews)
    result = {'uncertain_total': counts.get('uncertain', 0), 'uncertain_by_operation': by_operation,
              'uncertain_active': active, 'uncertain_known_history': len(reviews)-active,
              'repeat_alert_eligible': active > 0,
              'historical_acknowledgment_does_not_verify_outcome': True,
              'oldest_uncertain_created': oldest, 'newest_uncertain_created': newest,
              'queued': counts.get('queued', 0), 'sending': counts.get('sending', 0),
              'uncertain_are_pending_retries': False, 'scope': 'action_ledger_not_message_delivery'}
    if owner is not None:
        preview = list_uncertain(db, owner, limit=10)
        result.update(uncertain_actions_preview=preview['actions'], uncertain_preview_next_offset=preview['next_offset'])
    return result

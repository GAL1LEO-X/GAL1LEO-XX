"""Synthetic identity, edit and outbox regressions; no provider or callback I/O."""
from concurrent.futures import ThreadPoolExecutor
import json
import time

import pytest

from sally_whatsapp.linked_state_reads import project_live_read
from sally_whatsapp.store import Store


PN = '15550001000@c.us'
LID = '15550009999@lid'
OTHER = '15550002000@c.us'
GROUP = '15550001000-123@g.us'
SELF = '15550000000@c.us'


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / 'synthetic.sqlite')


def identifier(chat=PN, *, outgoing=False, raw='STANZA', participant=None):
    return f'{str(outgoing).lower()}_{chat}_{raw}' + (f'_{participant}' if participant else '')


def message(chat=PN, *, raw='STANZA', outgoing=False, participant=None, text='original', at=None):
    return {'id': identifier(chat, outgoing=outgoing, raw=raw, participant=participant),
            'from': chat, 'to': None if outgoing else SELF, 'fromMe': outgoing,
            'timestamp': int(time.time()) if at is None else at,
            'body': text, **({'participant': participant} if participant else {})}


def ingest(store, payload, *, historical=False, envelope=None):
    return store.ingest({'event': 'message.any', 'id': envelope or 'event-' + payload['id'],
                         'payload': payload}, historical=historical)


def subscribe(store, name='message.received'):
    filters = {'all_chats': True, 'chat_ids': [], 'contains': '', 'event_types': []}
    if name == 'message.digest':
        filters['digest_window_seconds'] = 60
    with store.db() as db:
        db.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)',
                   ('synthetic-sub', 'owner', name, json.dumps(filters), 'https://receiver.example',
                    b'never-dispatched', time.time() + 3600, 1))


def submit(store, key='synthetic-send-key', *, chat=PN, provider=None, operation='messages_send_text'):
    store.queue_action(key, 'owner', operation, {'body': {'chatId': chat, 'text': 'synthetic'}})
    store.finish_send(key, 'submitted', provider or identifier(chat, outgoing=True))
    return key


def receipt(store, chat=LID, *, provider=None, envelope='synthetic-receipt', ack=3):
    payload = message(chat, outgoing=True)
    payload.update(id=provider or payload['id'], ack=ack, ackName={2:'DEVICE',3:'READ',4:'PLAYED'}[ack])
    return store.ingest({'id': envelope, 'event': 'message.ack',
                         'timestamp': int(time.time() * 1000), 'payload': payload})


def edit(store, target, body='updated', *, at=None, envelope='synthetic-edit', chat=PN):
    return store.ingest({'event': 'message.edited', 'id': envelope,
                         'timestamp': int(time.time()) if at is None else at,
                         'payload': {'editedMessageId': target, 'from': chat, 'fromMe': False,
                                     'body': body}})


def revoke(store, target):
    store.ingest({'event': 'message.revoked', 'id': 'synthetic-revoke',
                  'payload': {'revokedMessageId': target}})


@pytest.mark.parametrize('bind_before', [False, True])
def test_receipt_equivalence_requires_verified_alias_and_survives_restart(store, bind_before):
    if bind_before:
        store.bind_chat_alias(LID, PN)
    key = submit(store)
    receipt(store)
    if not bind_before:
        assert store.send_status(key)['delivery']['status'] == 'not_observed'
        store.bind_chat_alias(LID, PN)
    status = store.send_status(key)
    assert status['delivery']['status'] == 'observed'
    assert set(status['delivery']['evidence']) == {'read'}
    assert status['provider_id'] == identifier(PN, outgoing=True)
    assert Store(store.path).send_status(key) == status


@pytest.mark.parametrize('variant', ['chat', 'direction', 'suffix', 'participant'])
def test_receipt_does_not_guess_from_short_id(store, variant):
    store.bind_chat_alias(LID, PN)
    provider = identifier(PN, outgoing=True)
    key = submit(store, provider=provider)
    value = {'chat': identifier(OTHER, outgoing=True),
             'direction': identifier(LID),
             'suffix': identifier(LID, outgoing=True, raw='OTHER'),
             'participant': identifier(LID, outgoing=True, participant=PN)}[variant]
    receipt(store, provider=value)
    assert store.send_status(key)['delivery']['status'] == 'not_observed'


def test_receipt_group_participant_alias_preserves_complete_key(store):
    store.bind_chat_alias(LID, PN)
    key = submit(store, chat=GROUP, provider=identifier(GROUP, outgoing=True, participant=PN))
    receipt(store, GROUP, provider=identifier(GROUP, outgoing=True, participant=LID))
    assert store.send_status(key)['delivery']['scope'] == 'group_partial'
    key2 = submit(store, key='another-synthetic-key', chat=GROUP,
                  provider=identifier(GROUP, outgoing=True, participant=OTHER))
    assert store.send_status(key2)['delivery']['status'] == 'not_observed'


def test_alias_equivalent_provider_reuse_is_ambiguous(store):
    first = submit(store)
    second = submit(store, 'synthetic-send-alias', chat=LID)
    receipt(store)
    store.bind_chat_alias(LID, PN)
    for key in (first, second):
        assert store.send_status(key)['delivery']['reason'] == 'provider_id_reused'


def test_alias_receipt_revocation_wins_and_legacy_poll_receipts_remain_readable(store):
    store.bind_chat_alias(LID, PN)
    # Direct storage models an old submitted poll, not a new allowed operation.
    key = submit(store, operation='messages_send_poll')
    receipt(store)
    assert store.send_status(key)['delivery']['status'] == 'observed'
    revoke(store, identifier(LID, outgoing=True))
    assert store.send_status(key)['delivery']['reason'] == 'message_revoked'


def test_receipt_payload_and_index_cannot_disagree_about_identity(store):
    store.bind_chat_alias(LID, PN)
    key = submit(store)
    receipt(store, OTHER)
    with store.db() as db:
        db.execute('UPDATE account_events SET source_message_id=?',
                   (identifier(LID, outgoing=True),))
    assert store.send_status(key)['delivery']['status'] == 'not_observed'


@pytest.mark.parametrize('operation', ['chats_get_chat_message', 'chats_get_chat_messages',
                                       'chats_get_chats_overview'])
def test_live_edit_conflict_replaces_only_body_with_explicit_acquired_provenance(store, operation):
    original = message()
    ingest(store, original)
    edit(store, original['id'])
    stale = {**original, 'replyTo': {'body': 'obsolete quote'},
             'media': {'filename': 'obsolete caption.txt'}, 'location': {'name': 'obsolete'},
             'vCards': ['obsolete'], 'ack': 3}
    supplied = (stale if operation == 'chats_get_chat_message' else
                [{'id': PN, 'lastMessage': stale}] if operation == 'chats_get_chats_overview' else [stale])
    result = project_live_read(store, operation, {'path': {'chatId': PN}}, supplied)['result']
    value = result if isinstance(result, dict) else result[0]
    if operation == 'chats_get_chats_overview':
        value = value['lastMessage']
    assert value['body'] == 'updated'
    assert value['body_source'] == 'acquired_edit'
    assert value['current_state'] == value['content_state'] == 'edit_conflict'
    assert value['provider_body_matches_observed_edit'] is False
    assert not {'replyTo', 'media', 'location', 'vCards', 'ack'} & value.keys()
    assert 'obsolete' not in str(result)


def test_live_edit_uses_latest_observed_order_and_verified_alias(store):
    store.bind_chat_alias(LID, PN)
    original = message(PN)
    edit(store, identifier(LID), 'newest', at=2000)
    edit(store, identifier(PN), 'older', at=1000, envelope='older-edit')
    ingest(store, original, historical=True)
    result = project_live_read(store, 'chats_get_chat_messages', {}, [original])['result'][0]
    assert result['body'] == 'newest'
    same = project_live_read(store, 'chats_get_chat_messages', {}, [{**original, 'body': 'newest'}])['result'][0]
    assert same['provider_body_matches_observed_edit'] is True
    assert 'content_state' not in same
    revoke(store, identifier(LID))
    assert project_live_read(store, 'chats_get_chat_messages', {}, [original])['result'] == [
        {'id': original['id'], 'content_state': 'revoked'}]


def test_revocation_between_initial_visibility_and_edit_lookup_never_exposes_body(store, monkeypatch):
    original = message()
    edit(store, original['id'])
    real = store.message_state
    def state(*args, **kwargs):
        value = real(*args, **kwargs)
        revoke(store, original['id'])
        return value
    monkeypatch.setattr(store, 'message_state', state)
    value = project_live_read(store, 'chats_get_chat_messages', {}, [original])['result'][0]
    assert value == {'id': original['id'], 'content_state': 'revoked'}


@pytest.mark.parametrize('history_first', [False, True])
@pytest.mark.parametrize('group', [False, True])
def test_new_alias_arrival_has_one_archive_row_and_one_live_notification(store, history_first, group):
    store.bind_chat_alias(LID, PN)
    subscribe(store)
    a = message(GROUP, participant=PN) if group else message(PN)
    b = message(GROUP, participant=LID) if group else message(LID)
    ingest(store, a, historical=history_first)
    outcome = ingest(store, b)
    assert outcome['duplicate'] is True
    assert store.message(b['id'])['id'] == a['id']
    assert len(store.search()['messages']) == 1
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM messages').fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM deliveries WHERE state='pending'").fetchone()[0] == 1


def test_alias_binding_keeps_old_rows_but_projects_one_message_before_pagination(store):
    subscribe(store)
    ingest(store, message(PN))
    ingest(store, message(LID))
    ingest(store, message(PN, raw='SECOND', text='second'))
    cursor = store.search(limit=1)['next_cursor']
    store.bind_chat_alias(LID, PN)
    with pytest.raises(ValueError, match='cursor'):
        store.search(limit=1, cursor=cursor)
    first = store.search(limit=1)
    second = store.search(limit=1, cursor=first['next_cursor'])
    assert len(first['messages']) == len(second['messages']) == 1
    assert first['messages'][0]['id'] != second['messages'][0]['id']
    assert second['next_cursor'] is None
    assert store.chats()['chats'][0]['archived_messages'] == 2
    assert len(store.search(query='original')['messages']) == 1
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM messages').fetchone()[0] == 3
        assert db.execute("SELECT count(*) FROM deliveries WHERE state='pending'").fetchone()[0] == 2
    assert store.message(identifier(PN))['id'] == store.message(identifier(LID))['id']


@pytest.mark.parametrize('first_state,attempts', [('accepted',1), ('pending',1), ('sending',1)])
def test_late_alias_never_replaces_attempted_callback_or_retries_unattempted_duplicate(store, first_state, attempts):
    subscribe(store)
    ingest(store, message(PN))
    ingest(store, message(LID))
    with store.db() as db:
        rows = db.execute('SELECT id,body FROM deliveries ORDER BY id').fetchall()
        db.execute('UPDATE deliveries SET state=?,attempts=? WHERE id=?',
                   (first_state, attempts, rows[0]['id']))
        original = rows[0]['body']
    store.bind_chat_alias(LID, PN)
    with store.db() as db:
        rows = db.execute('SELECT state,attempts,body FROM deliveries ORDER BY id').fetchall()
        assert rows[0]['state'] == first_state and rows[0]['attempts'] == attempts
        assert rows[0]['body'] == original
        assert rows[1]['state'] == 'cancelled' and rows[1]['attempts'] == 0


def test_both_attempted_alias_callbacks_stop_retry_without_rewriting_bytes(store):
    subscribe(store)
    ingest(store, message(PN))
    ingest(store, message(LID))
    with store.db() as db:
        db.execute("UPDATE deliveries SET state='pending',attempts=1")
        before = [row[0] for row in db.execute('SELECT body FROM deliveries ORDER BY id')]
    store.bind_chat_alias(LID, PN)
    with store.db() as db:
        after = db.execute('SELECT state,attempts,body FROM deliveries ORDER BY id').fetchall()
    assert [row['body'] for row in after] == before
    assert all(row['state'] == 'cancelled' and row['attempts'] == 1 for row in after)
    assert 'message_alias_callback_overlap' in store.state()['recovery_reasons']


@pytest.mark.parametrize('attempted', [False, True])
def test_digest_alias_duplicates_trim_only_before_first_attempt(store, attempted):
    subscribe(store, 'message.digest')
    ingest(store, message(PN))
    ingest(store, message(LID))
    with store.db() as db:
        original = db.execute('SELECT body FROM deliveries').fetchone()[0]
        if attempted:
            db.execute("UPDATE deliveries SET state='pending',attempts=1")
    store.bind_chat_alias(LID, PN)
    with store.db() as db:
        row = db.execute('SELECT state,attempts,body FROM deliveries').fetchone()
    if attempted:
        assert row['body'] == original and row['state'] == 'cancelled'
    else:
        assert len(json.loads(row['body'])['data']['message_ids']) == 1
        assert row['state'] == 'collecting'


def test_concurrent_alias_ingests_commit_once_and_restart_does_not_requeue(store):
    store.bind_chat_alias(LID, PN)
    subscribe(store)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda payload: ingest(store, payload), [message(PN), message(LID)]))
    assert sum(not result['duplicate'] for result in results) == 1
    reopened = Store(store.path)
    with reopened.db() as db:
        assert db.execute('SELECT count(*) FROM messages').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0] == 1
    assert len(reopened.search()['messages']) == 1


def test_alias_dedup_does_not_merge_other_chat_direction_or_group_participant(store):
    store.bind_chat_alias(LID, PN)
    values = [message(PN), message(OTHER), message(PN, outgoing=True),
              message(GROUP, participant=PN), message(GROUP, participant=OTHER)]
    for value in values:
        assert ingest(store, value)['duplicate'] is False
    assert len(store.search()['messages']) == len(values)


def test_dedup_preserves_revocation_and_does_not_restore_from_old_alias_payload(store):
    ingest(store, message(LID))
    revoke(store, identifier(LID))
    store.bind_chat_alias(LID, PN)
    ingest(store, message(PN, text='must stay hidden'))
    assert store.message(identifier(PN)) is None
    assert store.message(identifier(LID)) is None
    assert store.search()['messages'] == []


@pytest.mark.parametrize('quoted', [False, True])
def test_raw_edit_context_cannot_supply_body_to_another_chat(store, quoted):
    edit(store, 'RAW', 'private edit in first chat', chat=PN)
    other = {**message(OTHER), 'id': 'RAW', 'body': 'body in second chat'}
    value = {**message(OTHER, raw='PARENT'), 'replyTo': other} if quoted else other
    projected = project_live_read(store, 'chats_get_chat_messages', {}, [value])['result'][0]
    projected = projected['replyTo'] if quoted else projected
    assert projected['body'] == 'body in second chat'
    assert 'body_source' not in projected
    assert 'private edit' not in str(projected)


@pytest.mark.parametrize('mismatch', ['chat', 'direction', 'participant'])
def test_full_edit_identity_rejects_conflicting_event_and_live_context(store, mismatch):
    original = message(GROUP, participant=PN) if mismatch == 'participant' else message()
    ingest(store, original)
    bad = {**original, 'editedMessageId': original['id'], 'body': 'wrong context'}
    if mismatch == 'chat':
        bad['from'] = OTHER
    elif mismatch == 'direction':
        bad['fromMe'] = True
        bad['to'] = PN
    else:
        bad['participant'] = OTHER
    result = store.ingest({'event': 'message.edited', 'id': 'bad-edit', 'payload': bad})
    assert result['recorded'] is False
    assert result['reason'] == 'ambiguous_edit_identity'
    assert store.message(original['id'])['body'] == 'original'
    projected = project_live_read(store, 'chats_get_chat_messages', {}, [bad])['result'][0]
    assert projected == {'id': original['id'], 'content_state': 'unverified_reference'}
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM message_mutations').fetchone()[0] == 0
        assert 'wrong context' not in db.execute('SELECT data FROM account_events').fetchone()[0]


@pytest.mark.parametrize('late_original', [False, True])
def test_raw_edit_context_and_latest_body_survive_conflicting_or_older_events(store, late_original):
    edit(store, 'RAW', 'latest edit', at=2000, chat=PN)
    edit(store, 'RAW', 'older edit', at=1000, envelope='older', chat=PN)
    outcome = edit(store, 'RAW', 'other chat edit', at=3000, envelope='other', chat=OTHER)
    assert outcome['recorded'] is False
    chat = OTHER if late_original else PN
    original = {**message(chat, at=1000), 'id': 'RAW', 'body': 'original'}
    ingest(store, original, historical=True)
    assert store.message('RAW')['body'] == ('original' if late_original else 'latest edit')
    projected = project_live_read(store, 'chats_get_chat_messages', {}, [original])['result'][0]
    assert projected['body'] == ('original' if late_original else 'latest edit')


def test_alias_live_timestamp_cannot_override_acquired_deletion_boundary(store):
    from test_linked_device_visibility import event
    ingest(store, message(PN, at=1000), historical=True)
    store.ingest(event(chat=PN, when=1500))
    store.bind_chat_alias(LID, PN)
    newer_claim = message(LID, at=2000, text='must stay hidden')
    assert store.message_state(newer_claim['id'], chat_id=LID, timestamp=2000)['state'] == 'chat_deleted'
    assert project_live_read(store, 'chats_get_chat_messages', {}, [newer_claim])['result'] == [
        {'id': newer_claim['id'], 'content_state': 'chat_deleted'}]


def test_structured_enrichment_only_fills_absent_content_without_an_edit(store):
    original = {**message(), 'body': ''}
    ingest(store, original)
    card = 'BEGIN:VCARD\nFN:Synthetic\nEND:VCARD'
    enriched = {**original, 'vCards': [card]}
    ingest(store, enriched, historical=True, envelope='enriched')
    assert store.public_message(store.message(original['id']))['vCards'] == [card]
    ingest(store, {**enriched, 'vCards': ['replacement']}, historical=True, envelope='changed')
    assert store.public_message(store.message(original['id']))['vCards'] == [card]

    other = message(raw='EDITED')
    edit(store, other['id'], 'edited before acquisition', envelope='edit-before')
    ingest(store, {**other, 'vCards': ['stale card']}, historical=True)
    assert 'vCards' not in store.public_message(store.message(other['id']))
    assert store.message(other['id'])['body'] == 'edited before acquisition'


def test_old_duplicate_outbox_after_checkpoint_is_repaired_in_bounded_batches(store):
    subscribe(store)
    ingest(store, message())
    store.bind_chat_alias(LID, PN)
    with store.db() as db:
        row = db.execute('SELECT subscription,body FROM deliveries').fetchone()
        for index in range(35):
            db.execute('INSERT INTO deliveries(subscription,event_id,body) VALUES(?,?,?)',
                       (row['subscription'], f'legacy-{index}', row['body']))
    reopened = Store(store.path)
    with reopened.db() as db:
        assert db.execute("SELECT count(*) FROM deliveries WHERE state='pending'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM deliveries WHERE state='cancelled'").fetchone()[0] == 35
        reopened._reconcile_alias_callbacks(db)
        assert not db.execute("SELECT name FROM sqlite_temp_master WHERE name='alias_callback_seen'").fetchone()


def test_archive_media_identity_is_bound_at_ingest_without_retaining_keys(store):
    payload = {**message(), '_data': {'Message': {'documentMessage': {
        'fileSHA256': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'mediaKey': 'must not persist', 'directPath': '/private/source'}}}}
    ingest(store, payload)
    with store.db() as db:
        media = json.loads(db.execute('SELECT media FROM messages').fetchone()[0])
        assert media == {'has_media': True, 'identity': {'type': 'documentMessage', 'sha256': '0' * 64}}
        assert 'must not persist' not in str(media)


@pytest.mark.parametrize('times', [(1000, 2000), (2000, 1000)])
def test_historical_alias_duplicate_with_newer_timestamp_cannot_revive_deleted_content(store, times):
    from test_linked_device_visibility import event
    for chat, at in zip((PN, LID), times):
        ingest(store, message(chat, at=at), historical=True)
    store.bind_chat_alias(LID, PN)
    store.ingest(event(chat=PN, when=1500))
    assert store.search()['messages'] == []
    assert all(chat['archived_messages'] == 0 for chat in store.chats()['chats'])
    for chat in (PN, LID):
        assert store.message(identifier(chat)) is None
        assert store.message_state(identifier(chat), chat_id=chat, timestamp=2000)['state'] == 'chat_deleted'


@pytest.mark.parametrize('operation', ['groups_create_group', 'groups_join_group'])
@pytest.mark.parametrize('state', ['submitted', 'uncertain'])
@pytest.mark.parametrize('provider', [None, 'invalid-provider-id', GROUP])
def test_group_identity_uncertainty_is_derived_without_mutating_historical_action(store, operation, state, provider):
    key = 'synthetic-existing-group'
    store.queue_action(key, 'owner', operation, {'body': {}})
    store.finish_send(key, state, provider)
    with store.db() as db:
        before = dict(db.execute('SELECT * FROM sends WHERE key=?', (key,)).fetchone())
    result = store.send_status(key, owner='owner')
    if provider == GROUP:
        assert 'group_identity' not in result
    else:
        assert result['group_identity']['state'] == 'unknown'
        assert 'do not recreate or retry with a new key' in result['group_identity']['recovery']
    assert result['state'] == state
    assert store.send_status(key, owner='another-owner') is None
    with store.db() as db:
        assert dict(db.execute('SELECT * FROM sends WHERE key=?', (key,)).fetchone()) == before


def test_alias_binding_preserves_legacy_deleted_flag_even_without_mutation(store):
    ingest(store, message(PN), historical=True)
    ingest(store, message(LID), historical=True)
    with store.db() as db:
        db.execute("UPDATE messages SET deleted=1,body='' WHERE id=?", (identifier(LID),))
    store.bind_chat_alias(LID, PN)
    for chat in (PN, LID):
        assert store.message_state(identifier(chat))['state'] == 'revoked'
        assert store.message(identifier(chat)) is None
    assert store.search()['messages'] == []


def test_full_edit_without_optional_chat_uses_complete_identity_to_find_alias_row(store):
    ingest(store, message(LID), historical=True)
    store.bind_chat_alias(LID, PN)
    result = store.ingest({'event': 'message.edited', 'id': 'complete-edit',
                          'payload': {'editedMessageId': identifier(PN), 'body': 'updated'}})
    assert result['recorded'] is True
    assert store.message(identifier(LID))['body'] == 'updated'


def test_raw_edit_before_original_without_context_cannot_be_applied_globally(store):
    result = store.ingest({'event': 'message.edited', 'id': 'raw-edit',
                          'payload': {'editedMessageId': 'RAW', 'body': 'unattributed edit'}})
    assert result['recorded'] is False
    original = {**message(OTHER), 'id': 'RAW', 'body': 'original'}
    ingest(store, original, historical=True)
    assert store.message('RAW')['body'] == 'original'
    assert project_live_read(store, 'chats_get_chat_messages', {}, [original])['result'][0]['body'] == 'original'
    # Legacy unscoped mutations are retained as evidence, not assigned to a
    # future message merely because its raw stanza string is equal.
    with store.db() as db:
        db.execute("INSERT INTO message_mutations VALUES('LEGACY','edited','unattributed legacy',1000)")
    ingest(store, {**original, 'id': 'LEGACY'}, historical=True)
    assert store.message('LEGACY')['body'] == 'original'
    projected = project_live_read(store, 'chats_get_chat_messages', {}, [{**original, 'id': 'LEGACY'}])
    assert projected['result'][0]['body'] == 'original'

"""Archive admission and history accounting with synthetic provider observations."""
import json
import time

import pytest

from sally_whatsapp.history_sync import HistorySync
from sally_whatsapp.server import Service, SyncChat
from sally_whatsapp.store import Store
from test_verified_message_identity import PN, OTHER, GROUP, message, ingest, subscribe


@pytest.mark.parametrize('conflict', ['chat', 'direction', 'participant'])
def test_raw_identity_conflict_cannot_consume_live_receipt_or_wake_subscription(tmp_path, conflict):
    store = Store(tmp_path / 'archive.sqlite')
    original = {**message(GROUP if conflict == 'participant' else PN,
                           participant=PN if conflict == 'participant' else None), 'id': 'LEGACY'}
    ingest(store, original, historical=True)
    subscribe(store)
    conflicting = {**original, 'body': 'different observation'}
    if conflict == 'chat':
        conflicting['from'] = OTHER
    elif conflict == 'direction':
        conflicting.update(fromMe=True, to=PN)
    else:
        conflicting['participant'] = OTHER
    result = ingest(store, conflicting, envelope='conflicting-live')
    assert result == {'event': 'message.any', 'recorded': False,
                      'reason': 'ambiguous_message_identity'}
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM message_live_receipts').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0] == 0
        assert not db.execute('SELECT 1 FROM receipts WHERE id=?', ('conflicting-live',)).fetchone()
    assert store.message('LEGACY')['body'] == original['body']
    # The real first live observation must remain admissible after reopening.
    store = Store(store.path)
    assert ingest(store, original, envelope='valid-live')['duplicate']
    with store.db() as db:
        delivery = json.loads(db.execute('SELECT body FROM deliveries').fetchone()[0])
        assert delivery['data']['chat_id'] == original['from']
        assert delivery['data']['preview'] == original['body']


@pytest.mark.parametrize('arguments', [
    {'after': 200, 'before': 100}, {'after': -1}, {'before': 253402300800},
    {'after': float('nan')}, {'before': float('inf')}, {'after': True},
])
def test_archive_invalid_interval_is_an_error_without_cursor_side_effect(tmp_path, arguments):
    store = Store(tmp_path / 'archive.sqlite')
    with pytest.raises(ValueError, match='time window'):
        store.search(**arguments)
    with store.db() as db:
        assert not db.execute("SELECT 1 FROM state WHERE key='private:archive_cursor_key'").fetchone()


def test_equal_time_bounds_are_inclusive_and_empty_page_is_not_a_total(tmp_path):
    store = Store(tmp_path / 'archive.sqlite')
    for at in (99, 100, 101):
        ingest(store, message(raw=str(at), at=at), historical=True)
    page = store.search(after=100, before=100)
    assert [item['timestamp'] for item in page['messages']] == [100]
    assert page['coverage'] == 'acquired_archive_only'
    assert page['mirror_complete'] is False


def test_group_key_without_participant_cannot_be_reassigned_to_other_author(tmp_path):
    store = Store(tmp_path / 'archive.sqlite')
    original = message(GROUP)
    original['participant'] = PN
    ingest(store, original, historical=True)
    assert ingest(store, {**original, 'participant': OTHER}, envelope='wrong-author') == {
        'event': 'message.any', 'recorded': False, 'reason': 'ambiguous_message_identity'}
    assert store.message(original['id'])['sender'] == PN


@pytest.mark.parametrize('kind', ['view_once', 'expired', 'conflicting_identity'])
def test_history_counts_only_committed_message_rows(environment, kind):
    settings, _, gateway, _ = environment
    store = Store(settings.database)
    history = HistorySync(store, settings, gateway)
    payload = message(at=int(time.time()) - 2)
    if kind == 'view_once':
        payload['_data'] = {'IsViewOnce': True}
    elif kind == 'expired':
        payload['content_expires_at'] = int(time.time()) - 1
    else:
        payload['from'] = OTHER
    gateway.pages = [[payload]]
    chat = payload['from']
    job = history.start('owner', 'synthetic-history', [chat])
    assert history.process_one()
    status = history.status(job['id'], 'owner')
    assert status['state'] == ('failed' if kind == 'conflicting_identity' else 'running')
    assert status['messages_scanned'] == (0 if kind == 'conflicting_identity' else 1)
    assert status['messages_inserted'] == 0
    assert status['chat_coverage'][0]['messages_inserted'] == 0
    assert store.search()['messages'] == []
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM messages').fetchone()[0] == 0


def test_history_rejected_identity_rolls_back_page_and_resumes_after_restart(environment):
    settings, _, gateway, _ = environment
    store = Store(settings.database)
    history = HistorySync(store, settings, gateway)
    good = message(raw='FIRST', at=int(time.time()) - 3)
    invalid = {**message(OTHER, raw='SECOND', at=good['timestamp']), 'from': PN}
    gateway.pages = [[good, invalid]]
    job = history.start('owner', 'synthetic-history-rollback', [PN])
    history.process_one()
    assert history.status(job['id'], 'owner')['state'] == 'failed'
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM messages').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM receipts').fetchone()[0] == 0
    restored = HistorySync(Store(settings.database), settings, gateway)
    restored.control(job['id'], 'owner', 'resume')
    gateway.pages = [[good, message(raw='SECOND', at=good['timestamp'])]]
    restored.process_one()
    result = restored.status(job['id'], 'owner')
    assert result['messages_inserted'] == result['messages_scanned'] == 2
    assert len(restored.store.search()['messages']) == 2


def test_opaque_id_is_independent_between_instance_databases(tmp_path):
    first = Store(tmp_path / 'first.sqlite')
    second = Store(tmp_path / 'second.sqlite')
    for store, chat in ((first, PN), (second, OTHER)):
        assert ingest(store, {**message(chat), 'id': 'LEGACY'}, historical=True)['duplicate'] is False
        assert store.message('LEGACY')['chat_id'] == chat


@pytest.mark.parametrize('invalid', ['chat', 'identity'])
def test_sync_chat_commits_no_partial_page_on_invalid_source(environment, invalid):
    settings, receiver, gateway, _ = environment
    service = Service(settings, gateway=gateway, event_transport=receiver)
    good = message(raw='FIRST', at=int(time.time()) - 3)
    bad = message(OTHER, raw='SECOND', at=good['timestamp'])
    if invalid == 'identity':
        bad['from'] = PN
    gateway.pages = [[good, bad]]
    args = SyncChat(chat_id=PN, since=0, until=int(time.time()))
    with pytest.raises(ValueError):
        service.sync(args)
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM messages').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM receipts').fetchone()[0] == 0
    gateway.pages = [[good]]
    assert service.sync(args)['inserted'] == 1


def test_sync_chat_ignored_lifetime_is_not_reported_as_inserted(environment):
    settings, receiver, gateway, _ = environment
    service = Service(settings, gateway=gateway, event_transport=receiver)
    payload = {**message(at=int(time.time()) - 3), '_data': {'IsViewOnce': True}}
    gateway.pages = [[payload]]
    result = service.sync(SyncChat(chat_id=PN, since=0, until=int(time.time())))
    assert result['inserted'] == 0
    assert result['history_complete'] is False
    assert service.store.search()['messages'] == []

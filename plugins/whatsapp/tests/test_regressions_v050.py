"""Cross-component acceptance of 0.5.0 with signed local input and fake I/O.

These tests preserve independent positive controls in a second synthetic tenant.
They do not contact WAHA, a callback server, or any real WhatsApp account.
"""
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import sqlite3
import time

import pytest
from starlette.testclient import TestClient

from conftest import attachment_payload, install_attachment_readback, call, environment as environment_fixture, message, subscribe
from sally_whatsapp.server import Service, create_app
from sally_whatsapp.state_continuity import StateContinuityError, register_external_identity
from sally_whatsapp.store import SCHEMA_7, Store, canonical


PN = '393331112222@c.us'
LID = '555001@lid'
MID = f'false_{PN}_COMBINED_SOURCE'
PRODUCED = f'true_{PN}_COMBINED_PRODUCED'
TEXT = 'synthetic source content only'
REPLY = 'independently authored synthetic reply'
KEY = 'combined-submitted-action'
QUEUED = 'combined-pending-reply'
SOURCE_AT = int(time.time())


@contextmanager
def tenant(root, owner):
    root.mkdir()
    settings, receiver, gateway, token = environment_fixture.__wrapped__(root)
    settings = replace(settings, owner_subject=owner, public_url=f'https://{owner}.example',
                       live_account_enabled=True, send_enabled=True, send_chat_ids=[PN])
    requests = []
    gateway.request = lambda *args, **kwargs: requests.append((args, kwargs)) or {'id': PRODUCED}
    install_attachment_readback(gateway,original()['payload'])
    gateway.phone_for_lid = lambda _: PN
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization': 'Bearer ' + token(sub=owner, aud=settings.public_url),
                               'Accept': 'application/json, text/event-stream',
                               'MCP-Protocol-Version': '2026-07-28'})
        yield app.state.service, client, receiver, gateway, requests


def webhook(service, client, envelope):
    body = canonical({'session': 'default', **envelope}).encode()
    result = client.post('/webhooks/waha', content=body, headers={
        'Content-Type': 'application/json', 'x-webhook-hmac-algorithm': 'sha512',
        'x-webhook-hmac': hmac.digest(service.webhook_key, body, 'sha512').hex()})
    assert result.status_code == 200, result.text
    return result.json()


def result(client, tool, arguments=None):
    value = call(client, tool, arguments)['result']
    assert not value.get('isError'), value
    return value['structuredContent']


def original():
    item = message(MID, PN, text=TEXT, timestamp=SOURCE_AT)
    item['payload'].update(attachment_payload(MID,PN,b'synthetic attachment',
        name='synthetic.txt',mimetype='text/plain',timestamp=item['payload']['timestamp']))
    item['payload']['body']=TEXT
    return item


def deletion():
    return {'id': 'combined-delete-lid', 'event': 'engine.event', 'engine': 'GOWS',
            'payload': {'event': 'events.DeleteForMe', 'session': 'default', 'data': {
                'ChatJID': LID, 'MessageID': 'COMBINED_SOURCE', 'IsFromMe': False,
                'SenderJID': '', 'Timestamp': datetime.now(timezone.utc).isoformat(),
                'FromFullSync': False, 'Action': {}}}}


def revoke(identifier=MID):
    return {'id': 'combined-revoke-' + identifier, 'event': 'message.revoked',
            'timestamp': int(time.time() * 1000), 'payload': {'revokedMessageId': identifier}}


def derivatives():
    # Source-derived WAHA90ba445a: toPollVotePayload / toEventResponsePayload.
    target = {'id': MID, 'from': PN, 'fromMe': False}
    return [
        {'id': 'combined-poll', 'event': 'poll.vote', 'timestamp': int(time.time() * 1000),
         'payload': {'poll': target, 'vote': {'id': f'false_{PN}_VOTE', 'from': PN,
                     'fromMe': False, 'to': None, 'participant': None,
                     'selectedOptions': [TEXT], 'timestamp': int(time.time() * 1000)}}},
        {'id': 'combined-rsvp', 'event': 'event.response', 'timestamp': int(time.time() * 1000),
         'payload': {'id': f'false_{PN}_RSVP', 'from': PN, 'fromMe': False, 'to': None,
                     'timestamp': int(time.time()), 'participant': None, 'body': None,
                     'hasMedia': False, 'media': None, 'eventCreationKey': target,
                     'eventResponse': {'response': 'GOING', 'extraGuestCount': 3,
                                       'timestampMs': int(time.time() * 1000)}}},
    ]


def event_id(envelope):
    return 'change_' + hashlib.sha256(envelope['id'].encode()).hexdigest()


def action(key=KEY, text=TEXT, reply=False):
    body = {'chatId': PN, 'text': text}
    if reply:
        body['reply_to'] = MID
    return {'idempotency_key': key, 'operation': 'messages_send_text', 'arguments': {'body': body}}


def callbacks(receiver):
    return [json.loads(body) for _, body, _ in receiver.requests if json.loads(body).get('type') != 'verification']


def action_row(store, key):
    with store.db() as db:
        return dict(db.execute('SELECT s.*,j.arguments FROM sends s JOIN action_jobs j USING(key) WHERE key=?', (key,)).fetchone())


@pytest.mark.parametrize('late_alias', [False, True])
@pytest.mark.parametrize('derivative_after_delete', [False, True])
def test_signed_combination_preserves_state_and_isolates_other_tenant(tmp_path, late_alias, derivative_after_delete):
    with tenant(tmp_path/'owner-synthetic', 'owner-synthetic') as first, tenant(tmp_path/'secondary-synthetic', 'secondary-synthetic') as second:
        a, client, receiver, gateway, calls = first
        b, other, other_receiver, _, other_calls = second
        data = derivatives()
        transfer = {}
        download = {}
        for service, connection in ((a, client), (b, other)):
            subscribe(connection, name='whatsapp.event', arguments={
                'all_chats': True, 'event_types': ['message.revoked', 'poll.vote', 'event.response']})
            webhook(service, connection, original())
            transfer[service] = result(connection, 'get_attachment', {'message_id': MID})['id']
            assert service.media.process_one()
            download[service] = result(connection, 'get_transfer_status', {'transfer_id': transfer[service]})['download_url']
            assert connection.get(download[service]).content == b'synthetic attachment'
            assert result(connection, 'write_whatsapp', action())['state'] == 'queued'
            assert service.process_action()
            assert result(connection, 'write_whatsapp', action(QUEUED, REPLY, True))['state'] == 'queued'
        before = action_row(a.store, KEY)
        other_before = action_row(b.store, KEY)
        if not derivative_after_delete:
            for item in data:
                webhook(a, client, item)
        for item in data:
            webhook(b, other, item)
        if late_alias:
            gateway.phone_for_lid = lambda _: None
        erased = deletion()
        webhook(a, client, erased)
        if late_alias:
            assert result(client, 'get_message', {'message_id': MID})['message'] is not None
            # Restart clears only the bounded failed-lookup cooldown. The verified
            # binding is acquired through Service, not invented in SQLite.
            gateway.phone_for_lid = lambda _: PN
            restarted = Service(a.settings, gateway=gateway, event_transport=receiver)
            assert restarted.resolve_chat(LID) == PN
        assert webhook(a, client, erased) == {'duplicate': True}
        assert result(client, 'get_message', {'message_id': MID})['message'] is None
        assert result(client, 'get_transfer_status', {'transfer_id': transfer[a]})['state'] == 'unavailable'
        assert client.get(download[a]).status_code == 404
        assert a.media.path(transfer[a]).is_file()  # DeleteForMe remains reversible.
        if derivative_after_delete:
            for item in data:
                webhook(a, client, item)
        for item in data:
            assert result(client, 'get_account_event', {'event_id': event_id(item)})['event']['data'] == {
                'message_id': MID, 'unavailable': True}
            # Local hiding is reversible. Its private acquired payload remains
            # intact even when the derivative arrived after DeleteForMe.
            with a.store.db() as db:
                stored = db.execute('SELECT data FROM account_events WHERE id=?', (event_id(item),)).fetchone()[0]
                assert json.loads(stored) == item['payload']
        for identifier in (MID, PRODUCED):
            envelope = revoke(identifier)
            webhook(a, client, envelope)
            assert webhook(a, client, envelope) == {'duplicate': True}
        for item in data:
            assert webhook(a, client, item) == {'duplicate': True}
            value = result(client, 'get_account_event', {'event_id': event_id(item)})['event']['data']
            assert value == {'message_id': MID, 'revoked': True}
            with a.store.db() as db:
                stored = db.execute('SELECT data FROM account_events WHERE id=?', (event_id(item),)).fetchone()[0]
                assert json.loads(stored) == value
        assert a.process_action()
        queued = action_row(a.store, QUEUED)
        assert queued['state'] == 'failed_before_send' and REPLY in queued['arguments']
        after = action_row(a.store, KEY)
        assert after['arguments'] == '{}' and after['payload_hash'] == before['payload_hash']
        assert after['state'] == 'submitted'
        status = result(client, 'get_transfer_status', {'transfer_id': transfer[a]})
        assert status['state'] == 'cancelled' and status['filename'] == '' and status['sha256'] is None
        assert not a.media.path(transfer[a]).exists()
        assert not result(client, 'search_messages', {'query': TEXT})['messages']
        assert not result(client, 'read_conversation', {'chat_id': PN})['messages']
        while a.events.dispatch_one():
            pass
        delivered = callbacks(receiver)
        assert len(delivered) == 2
        assert all(v['data']['event_type'] == 'message.revoked' for v in delivered)
        expected_sources = {event_id(revoke(identifier)): identifier for identifier in (MID, PRODUCED)}
        assert {v['data']['event_id'] for v in delivered} == set(expected_sources)
        for callback in delivered:
            identifier = expected_sources[callback['eventId']]
            assert callback['data'] == {'event_id': callback['eventId'],
                'event_type': 'message.revoked', 'chat_id': PN, 'message_id': identifier}
            assert result(client, 'get_message', {'message_id': identifier})['message'] is None
        assert TEXT not in canonical(delivered)
        restarted = Service(a.settings, gateway=gateway, event_transport=receiver)
        replay = original()
        replay['id'] = 'late-historical-original'
        restarted.ingest(replay, historical=True)
        assert restarted.store.message_state(MID)['state'] == 'revoked'
        assert not restarted.process_action() and not restarted.events.dispatch_one()
        assert result(client, 'write_whatsapp', action())['state'] == 'submitted'
        assert len(calls) == 1
        # Same provider IDs and keys in the independent tenant remain usable.
        assert action_row(b.store, KEY) == other_before
        assert action_row(b.store, QUEUED)['state'] == 'queued'
        assert result(other, 'get_message', {'message_id': MID})['message'] is not None
        assert other.get(download[b]).content == b'synthetic attachment'
        assert b.store.send_status(KEY, owner=a.settings.owner_subject) is None
        assert len(other_calls) == 1
        while b.events.dispatch_one():
            pass
        assert {v['data']['event_type'] for v in callbacks(other_receiver)} == {'poll.vote', 'event.response'}
        for item in data:
            assert result(other, 'get_account_event', {'event_id': event_id(item)})['event']['data'] == item['payload']


def test_revocation_during_callback_prevents_replay_of_attempted_content(tmp_path):
    with tenant(tmp_path/'callback-race', 'callback-race') as (service, client, receiver, gateway, calls):
        subscribe(client, arguments={'chat_ids': [PN]})
        subscribe(client, name='whatsapp.event', arguments={'all_chats': True, 'event_types': ['message.revoked']})
        webhook(service, client, original())
        post = receiver.post
        raced = False
        def in_flight(url, body, headers):
            nonlocal raced
            event = json.loads(body)
            if event.get('name') == 'message.received' and not raced:
                raced = True
                post(url, body, headers)  # Content has already left the dispatcher.
                webhook(service, client, revoke())
                return 503, b''  # Acceptance cannot be inferred from this response.
            return post(url, body, headers)
        receiver.post = in_flight
        assert service.events.dispatch_one()
        assert raced
        with service.store.db() as db:
            row = db.execute("SELECT d.* FROM deliveries d JOIN subscriptions s ON s.id=d.subscription WHERE s.name='message.received'").fetchone()
            assert row['state'] == 'cancelled' and row['attempts'] == 1
            assert TEXT not in row['body']
        restarted = Service(service.settings, gateway=gateway, event_transport=receiver)
        while restarted.events.dispatch_one():
            pass
        posted = callbacks(receiver)
        assert [v['name'] for v in posted] == ['message.received', 'whatsapp.event']
        assert posted[1]['data']['event_type'] == 'message.revoked'
        assert TEXT not in canonical(posted[1])
        assert not calls  # Callback retry is unrelated to WhatsApp action retry.


def test_legacy_null_and_payload_backfills_match_fresh_observables(tmp_path):
    path = tmp_path/'legacy.sqlite'
    item = derivatives()[0]
    args = action()['arguments']
    digest = hashlib.sha256(canonical({'operation': 'messages_send_text', 'arguments': args, 'transfer_id': None}).encode()).hexdigest()
    now = time.time()
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA_7)
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,NULL)',
                   (event_id(item), item['event'], PN, now-90*86400, canonical(item['payload'])))
        db.executemany("INSERT INTO message_mutations VALUES(?,'revoked',NULL,?)", [(MID, now), (PRODUCED, now)])
        db.execute('INSERT INTO sends VALUES(?,?,?,?,?,?,?)', (KEY, 'owner', digest, 'submitted', PRODUCED, now, now))
        db.execute('INSERT INTO action_jobs VALUES(?,?,?,NULL)', (KEY, 'messages_send_text', canonical(args)))
        db.execute('INSERT INTO state VALUES(?,?)', ('private:revocation_derivatives_repair:v1', 'true'))
    upgraded = Store(path, recover_inflight=True)
    fresh = Store(tmp_path/'fresh.sqlite')
    fresh.ingest(item)
    fresh.queue_action(KEY, 'owner', 'messages_send_text', args)
    fresh.finish_send(KEY, 'submitted', PRODUCED)
    fresh.ingest(revoke(MID))
    fresh.ingest(revoke(PRODUCED))
    for store in (upgraded, fresh):
        assert store.account_event(event_id(item))['data'] == {'message_id': MID, 'revoked': True}
        row = action_row(store, KEY)
        assert row['arguments'] == '{}' and row['payload_hash'] == digest
        assert store.queue_action(KEY, 'owner', 'messages_send_text', args)['state'] == 'submitted'
        assert store.send_status(KEY)['delivery']['reason'] == 'message_revoked'
        with store.db() as db:
            assert db.execute('PRAGMA user_version').fetchone()[0] == 8
            assert [tuple(r) for r in db.execute('SELECT role,resolution FROM event_source_refs WHERE event_id=? ORDER BY role', (event_id(item),))] == [('self', 'resolved'), ('target', 'resolved')]
        restarted = Store(store.path, recover_inflight=True)
        assert restarted.account_event(event_id(item))['data'] == store.account_event(event_id(item))['data']
        assert action_row(restarted, KEY)['payload_hash'] == digest


@pytest.mark.parametrize('loss', ['missing', 'corrupt', 'replaced'])
def test_external_state_loss_blocks_pending_actions_callbacks_and_files(tmp_path, loss):
    with tenant(tmp_path/'continuity', 'continuity') as (old, client, receiver, gateway, calls):
        settings = replace(old.settings, state_identity_file=tmp_path/'configuration'/'identity.json')
        register_external_identity(settings)
        service = Service(settings, gateway=gateway, event_transport=receiver)
        subscribe(client, arguments={'chat_ids': [PN]})
        webhook(old, client, original())
        transfer = result(client, 'get_attachment', {'message_id': MID})['id']
        assert service.media.process_one()
        service.store.queue_action(KEY, settings.owner_subject, 'messages_send_text', action()['arguments'])
        marker = settings.state_identity_file.read_bytes()
        if loss == 'missing':
            settings.database.unlink()
        elif loss == 'corrupt':
            settings.database.write_bytes(b'synthetic corrupt database')
        else:
            # Replace a coherent SQLite file, not a new main file combined with
            # the previous database's WAL (which can legitimately recover rows).
            with closing(sqlite3.connect(settings.database)) as checkpoint:
                assert checkpoint.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
            replacement = Store(tmp_path/'replacement.sqlite')
            os.replace(replacement.path, settings.database)
        count = len(callbacks(receiver))
        for operation in (service.process_action, service.events.dispatch_one,
                          lambda: service.media.status(transfer, settings.owner_subject)):
            with pytest.raises(StateContinuityError):
                operation()
        with pytest.raises(StateContinuityError):
            Service(settings, gateway=gateway, event_transport=receiver)
        assert settings.state_identity_file.read_bytes() == marker
        assert not calls and len(callbacks(receiver)) == count
        if loss == 'missing':
            assert not settings.database.exists()


def test_new_state_initialization_never_mutates_a_replaced_destination(environment, tmp_path, monkeypatch):
    """Even a swap after exclusive creation must not redirect root SQLite writes."""
    from sally_whatsapp import state_initialization

    data, configuration = tmp_path/'data', tmp_path/'config'
    data.mkdir()
    configuration.mkdir()
    settings = replace(environment[0], database=data/'new.sqlite',
                       state_identity_file=configuration/'technical-state.json')
    victim = tmp_path/'unrelated-existing.sqlite'
    with closing(sqlite3.connect(victim)) as db, db:
        db.executescript(SCHEMA_7)
        db.execute("INSERT INTO state VALUES('synthetic-sentinel','preserve')")
    before = victim.read_bytes()
    real_store = state_initialization.Store
    opened = []

    def replace_destination_before_sqlite(path, *args, **kwargs):
        opened.append(path)
        settings.database.unlink()
        settings.database.symlink_to(victim)
        return real_store(path, *args, **kwargs)

    monkeypatch.setattr(state_initialization, 'Store', replace_destination_before_sqlite)
    # CI can run without root; ownership is covered separately by the owner's
    # mocked provisioning tests. No real users or service paths are touched.
    monkeypatch.setattr(state_initialization.os, 'chown', lambda *args, **kwargs: None)
    monkeypatch.setattr(state_initialization, '_administrative_directory', lambda path: True)
    with pytest.raises(StateContinuityError):
        state_initialization.initialize_new(settings, os.geteuid(), os.getegid())
    assert len(opened) == 1 and opened[0] != settings.database
    assert victim.read_bytes() == before
    assert settings.database.is_symlink()  # Do not erase the concurrent change.


def test_bootstrap_final_check_cannot_create_admin_sidecars_after_handoff(environment, tmp_path, monkeypatch):
    from sally_whatsapp import state_initialization

    data, configuration = tmp_path/'handoff-data', tmp_path/'handoff-config'
    data.mkdir()
    configuration.mkdir()
    settings = replace(environment[0], database=data/'new.sqlite',
                       state_identity_file=configuration/'technical-state.json')
    monkeypatch.setattr(state_initialization, '_administrative_directory', lambda path: True)
    monkeypatch.setattr(state_initialization.os, 'chown', lambda *args, **kwargs: None)
    real_fchown = state_initialization.os.fchown
    real_guard = state_initialization.StateContinuity
    handed_off = []
    checked = []

    def administrative_guard(staged_settings, **kwargs):
        assert staged_settings.database != settings.database
        assert staged_settings.database.is_relative_to(configuration)
        assert not handed_off
        checked.append(staged_settings.database)
        return real_guard(staged_settings, **kwargs)

    def writer_after_handoff(descriptor, uid, gid):
        real_fchown(descriptor, uid, gid)
        # The newly assigned owner can change its DB before the administrative
        # function returns. No concurrent services or processes are needed here.
        with closing(sqlite3.connect(settings.database)) as db:
            assert db.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',)
        handed_off.append(True)
        assert not settings.database.with_name(settings.database.name+'-wal').exists()
        assert not settings.database.with_name(settings.database.name+'-shm').exists()

    monkeypatch.setattr(state_initialization.os, 'fchown', writer_after_handoff)
    monkeypatch.setattr(state_initialization, 'StateContinuity', administrative_guard)
    state_initialization.initialize_new(settings, os.geteuid(), os.getegid())
    assert handed_off == [True] and len(checked) == 1
    assert not settings.database.with_name(settings.database.name+'-wal').exists()
    assert not settings.database.with_name(settings.database.name+'-shm').exists()

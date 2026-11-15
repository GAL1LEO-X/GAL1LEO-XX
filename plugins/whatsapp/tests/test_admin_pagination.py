import base64
import json
import time

import pytest

from test_admin_panel import admin
from sally_whatsapp.event_policies import normalize_filters
from sally_whatsapp.store import canonical


def test_cursor_pages_are_bounded_complete_owner_scoped_and_stable_on_ties(admin):
    app, client, login = admin
    service = app.state.service
    owner = service.settings.owner_subject
    filters = normalize_filters('message.received', {'all_chats': True})
    expected_history, expected_subscriptions = set(), set()
    for index in range(205):
        job = service.history.start(owner, 'page-'+str(index), ['synthetic@c.us'])
        expected_history.add(job['id'])
        url = 'https://callback.invalid/' + str(index)
        identifier = service.events.identity(owner, 'message.received', filters, url)
        expected_subscriptions.add(identifier)
        with service.store.db() as db:
            db.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)',
                (identifier, owner, 'message.received', canonical(filters), url, b'synthetic-unused', time.time()+3600, 1))
    foreign = service.history.start('other-owner', 'foreign-page', ['private@c.us'])
    with service.store.db() as db:
        db.execute('UPDATE history_jobs SET created=1000')
        db.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)',
            ('sub_'+'f'*64, 'other-owner', 'message.received', canonical(filters), 'https://callback.invalid/private', b'unused', time.time()+3600, 1))
    assert client.get('/admin/api/status?history_cursor=invalid').status_code == 401
    login()
    query, history, subscriptions, sizes = {}, [], [], []
    while True:
        response = client.get('/admin/api/status', params=query)
        assert response.status_code == 200
        value = response.json()
        sizes.append((len(value['history']), len(value['subscriptions'])))
        history.extend(row['id'] for row in value['history'])
        subscriptions.extend(row['id'] for row in value['subscriptions'])
        for kind in ('history', 'subscriptions'):
            page = value[kind+'_page']
            assert page['limit'] == 100 and len(value[kind]) <= 100
            assert value[kind+'_truncated'] == (page['next_cursor'] is not None)
        if not value['history_page']['next_cursor']:
            break
        query = {kind+'_cursor': value[kind+'_page']['next_cursor'] for kind in ('history', 'subscriptions')}
    assert sizes == [(100, 100), (100, 100), (5, 5)]
    assert len(history) == len(set(history)) == 205 and set(history) == expected_history
    assert len(subscriptions) == len(set(subscriptions)) == 205 and set(subscriptions) == expected_subscriptions
    assert foreign['id'] not in history
    # The first page is repeatable, and the independent list cursor does not
    # advance the other list or expand the owner's visibility.
    first = client.get('/admin/api/status').json()
    separate = client.get('/admin/api/status', params={'history_cursor': first['history_page']['next_cursor']}).json()
    assert separate['subscriptions'] == first['subscriptions']
    assert separate['history'][0]['id'] == history[100]


@pytest.mark.parametrize('query', [
    'history_cursor=bad', 'history_cursor=', 'subscriptions_cursor=sub_short',
    'subscriptions_cursor=' + 'x'*257, 'limit=100000',
    'history_cursor=a&history_cursor=b',
    'history_cursor='+base64.urlsafe_b64encode(json.dumps([float('nan'), 'history_'+'a'*32]).encode()).decode(),
    'history_cursor='+base64.urlsafe_b64encode(json.dumps([True, 'history_'+'a'*32]).encode()).decode(),
    'history_cursor='+base64.urlsafe_b64encode(json.dumps([1, 'foreign']).encode()).decode(),
])
def test_invalid_pagination_is_controlled_and_never_removes_owner_auth(admin, query):
    _, client, login = admin
    login()
    response = client.get('/admin/api/status?' + query)
    assert response.status_code == 400
    assert response.json()['error_code'] == 'ADMIN_INVALID_INPUT'

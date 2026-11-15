"""Primary metadata is independent of the retained quote recursion budget."""
from copy import deepcopy

import pytest

from sally_whatsapp.linked_state_reads import project_live_read
from sally_whatsapp.store import Store


@pytest.mark.parametrize('retain_unavailable', [False, True])
def test_primary_type_does_not_annotate_retained_quotes_or_consume_depth(tmp_path, retain_unavailable):
    store = Store(tmp_path / 'archive.sqlite')
    chat = '15550900001@c.us'
    quote = {'id': 'LEAF', 'body': 'Synthetic beyond the recursion limit'}
    for index in reversed(range(12)):
        quote = {'id': f'SYNTHETIC{index}', 'body': f'Synthetic level {index}', 'replyTo': quote}
    original = deepcopy(quote)
    with store.db() as db:
        retained = store._visible_event_data(db, 'message.edited', {'replyTo': quote}, chat,
                                            retain_unavailable=retain_unavailable)['replyTo']
    live = project_live_read(store, 'chats_get_chat_message', {'path': {'chatId': chat}}, quote)['result']
    assert live.pop('chat_type') == 'private'
    assert 'chat_type' not in retained
    assert live == retained
    current = retained
    for index in range(9):
        assert current['id'] == f'SYNTHETIC{index}'
        assert current['body'] == f'Synthetic level {index}'
        assert 'chat_type' not in current
        current = current['replyTo']
    assert current == {'content_state': 'unknown', 'content_omitted': 'nested_reply_limit'}
    assert quote == original

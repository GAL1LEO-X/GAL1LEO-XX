"""Seven synthetic historical actions remain uncertain without exact proof."""
import json

from sally_whatsapp.action_diagnostics import list_uncertain
from sally_whatsapp.store import Store


def test_seven_cards_preserve_original_outcomes_and_owner_boundary(tmp_path):
    store = Store(tmp_path/'actions.db')
    operations = ['messages_send_list', 'profile_set_profile_status', 'profile_set_profile_status',
                  'messages_set_star', 'messages_set_star', 'groups_get_invite_code', 'groups_revoke_invite_code']
    for index, operation in enumerate(operations):
        key = f'synthetic-uncertain-{index}'
        store.queue_action(key,'owner-one',operation,{'body':{}})
        store.finish_send(key,'uncertain',result={'success':True} if index == 0 else {'error':500})
    with store.db() as db:
        before = [tuple(r) for r in db.execute('SELECT * FROM sends ORDER BY key')]
        changes = db.total_changes
        value = list_uncertain(db,'owner-one')
        assert value['total'] == 7
        assert list_uncertain(db,'owner-two')['actions'] == []
        assert not value['uncertain_are_pending_retries']
        for row in value['actions']:
            card = row['reconciliation']
            assert card['classification'] == 'unresolved'
            assert not card['pending_retry'] and not card['current_state_proves_historical_effect']
            assert card['original_outcome_preserved'] and card['required_evidence']
        assert [tuple(r) for r in db.execute('SELECT * FROM sends ORDER BY key')] == before
        assert db.total_changes == changes
    # An acknowledgment-shaped historical response is not proof of the effect.
    assert value['actions'][0]['state'] == 'uncertain'

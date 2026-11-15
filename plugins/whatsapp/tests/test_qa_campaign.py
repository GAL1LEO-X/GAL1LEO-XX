"""Adversarial tests for the QA coordinator, with no real accounts or I/O."""

import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qa.campaign import Journal, assertions, validate_manifest
from qa.recipes import smoke_manifest
from qa.schema_cases import Surface, generate, sample


def manifest():
    return {'version': 1, 'steps': [{
        'id': 'send', 'executor': 'native', 'tool': 'send_text', 'effect': 'write',
        'arguments': {'chat_id': '199999998@c.us', 'text': 'Synthetic QA'},
        'destinations': ['199999998@c.us'], 'assertions': [{'path': '/state', 'op': 'equals', 'value': 'submitted'}],
        'capture': {'message_id': '/provider_id'},
    }]}


def create(tmp_path, specification=None):
    return Journal.create(tmp_path / 'campaign.sqlite', specification or manifest(),
                          {'allowed_chat_ids': ['199999998@c.us']}, run_id='qa-synthetic-20261023')


def test_preparation_never_issues_mutations(tmp_path):
    journal = create(tmp_path)
    assert journal.next()['reason'] == 'live_scope_not_enabled'
    assert journal.report()['steps'][0]['state'] == 'PENDING'
    assert journal.report()['all_passed'] is False
    journal.close()


def test_enabling_live_retains_the_user_mandate_in_the_same_transaction(tmp_path):
    journal = create(tmp_path)
    journal.enable_live('Synthetic mandate for this isolated test')
    row = journal.db.execute("SELECT detail FROM audit WHERE action='live_scope_enabled'").fetchone()
    assert json.loads(row['detail'])['user_mandate'] == 'Synthetic mandate for this isolated test'
    assert journal.report()['live_enabled'] is True
    journal.close()


@pytest.mark.parametrize('malformed', [{'structuredContent': []}, {'content': [{'type': 'text', 'text': 'null'}]}])
def test_malformed_tool_evidence_is_a_recorded_failure(tmp_path, malformed):
    journal = create(tmp_path)
    journal.enable_live('Synthetic test only')
    journal.next()
    assert journal.record('send', malformed)['state'] == 'FAIL'
    assert journal.report()['all_passed'] is False
    journal.close()


def test_restart_after_issue_returns_status_lookup_never_duplicate_send(tmp_path):
    journal = create(tmp_path)
    journal.enable_live('Synthetic test only')
    instruction = journal.next()
    assert instruction['tool'] == 'send_text'
    key = instruction['arguments']['idempotency_key']
    journal.close()
    reopened = Journal(tmp_path / 'campaign.sqlite')
    recovery = reopened.next()
    assert recovery['tool'] == 'get_send_status'
    assert recovery['arguments']['idempotency_key'] == key
    assert recovery['resend'] is False
    reopened.record('send', {'state': 'submitted', 'provider_id': 'synthetic-message', 'delivery': {'status': 'not_observed'}})
    assert reopened.report()['all_passed']
    assert reopened.context()['steps']['send']['message_id'] == 'synthetic-message'
    assert reopened.next()['status'] == 'complete'
    reopened.close()


def test_queued_and_uncertain_are_not_success(tmp_path):
    journal = create(tmp_path)
    journal.enable_live('Synthetic test only')
    journal.next()
    assert journal.record('send', {'state': 'queued'})['state'] == 'WAITING'
    assert journal.report()['all_passed'] is False
    assert journal.record('send', {'state': 'uncertain'})['state'] == 'UNCERTAIN'
    assert journal.next()['tool'] == 'get_send_status'
    journal.close()


def test_concurrent_readers_cannot_both_claim_the_send(tmp_path):
    first = create(tmp_path)
    first.enable_live('Synthetic test only')
    second = Journal(tmp_path / 'campaign.sqlite')
    one, two = first.next(), second.next()
    assert one['tool'] == 'send_text'
    assert two['tool'] == 'get_send_status'
    first.close(); second.close()


def test_declared_scope_cannot_hide_a_different_payload_destination(tmp_path):
    spec = manifest()
    spec['steps'][0]['arguments']['chat_id'] = '188888888@c.us'
    journal = create(tmp_path, spec)
    journal.enable_live('Synthetic test only')
    with pytest.raises(ValueError, match='outside'):
        journal.next()
    assert journal.report()['steps'][0]['state'] == 'PENDING'
    journal.close()


def test_existing_bindings_and_existing_journal_are_not_replaced(tmp_path):
    journal = create(tmp_path)
    journal.bind('peer', 'one')
    journal.bind('peer', 'one')
    with pytest.raises(ValueError, match='immutable'):
        journal.bind('peer', 'two')
    with pytest.raises(FileExistsError):
        create(tmp_path)
    journal.close()


def test_identity_binding_can_gain_a_label_without_changing_existing_identity(tmp_path):
    journal = create(tmp_path)
    journal.bind('owner', {'id': '199999998@c.us', 'verified': True})
    journal.bind('owner', {'id': '199999998@c.us', 'verified': True, 'web_label': 'Synthetic owner'})
    for replacement in ({'id': '188888888@c.us', 'verified': True},
                        {'id': '199999998@c.us', 'verified': 1}, {'web_label': 'Synthetic owner'}):
        with pytest.raises(ValueError, match='immutable'):
            journal.bind('owner', replacement)
    assert journal.context()['bindings']['owner']['web_label'] == 'Synthetic owner'
    journal.close()


def test_browser_interruption_requires_observation_not_resend(tmp_path):
    spec = manifest()
    spec['steps'][0].update(executor='browser', action='send_text')
    spec['steps'][0].pop('tool')
    journal = create(tmp_path, spec)
    journal.enable_live('Synthetic test only')
    assert journal.next()['status'] == 'execute_once'
    assert journal.next() == {'status': 'needs_reconciliation', 'step_id': 'send', 'resend': False}
    journal.close()


def test_no_pass_without_issued_step_and_asserted_evidence(tmp_path):
    journal = create(tmp_path)
    with pytest.raises(ValueError, match='No issued'):
        journal.record('send', {'state': 'submitted'})
    journal.enable_live('Synthetic test only')
    journal.next()
    assert journal.record('send', {'state': 'submitted'})['state'] == 'FAIL'  # missing provider ID
    journal.close()


def test_dependency_resolution_never_uses_failed_evidence(tmp_path):
    spec = manifest()
    follow = copy.deepcopy(spec['steps'][0])
    follow.update(id='follow', depends_on=['send'], effect='read', tool='get_message',
                  arguments={'message_id': {'$ref': '/steps/send/message_id'}})
    spec['steps'].append(follow)
    journal = create(tmp_path, spec)
    journal.enable_live('Synthetic test only')
    journal.next(); journal.record('send', {'state': 'failed'})
    assert journal.next()['status'] == 'waiting_dependencies'
    assert 'send' not in journal.context()['steps']
    journal.close()


def test_signed_urls_and_secrets_are_not_retained_in_journal(tmp_path):
    journal = create(tmp_path)
    journal.enable_live('Synthetic test only'); journal.next()
    journal.record('send', {'state': 'submitted', 'provider_id': 'synthetic',
                            'download_url': 'https://example.org/?signature=private', 'secret': 'do-not-store'})
    evidence = journal.db.execute('SELECT evidence FROM step').fetchone()[0]
    assert 'signature' not in evidence and 'do-not-store' not in evidence
    assert 'provider_id' not in json.dumps(journal.report())
    journal.close()


def test_manifest_checks_mutation_effects_and_dependencies():
    assert validate_manifest(smoke_manifest())
    spec = manifest(); spec['steps'][0]['effect'] = 'read'
    with pytest.raises(ValueError, match='Mutating'):
        validate_manifest(spec)
    spec = manifest(); spec['steps'][0]['depends_on'] = ['not-earlier']
    with pytest.raises(ValueError, match='Dependencies'):
        validate_manifest(spec)


def test_assertions_distinguish_false_zero_missing_and_unknown_receipts():
    assert assertions({'x': False}, [{'path': '/x', 'op': 'equals', 'value': 0}])
    assert assertions({'delivery': {'scope': 'group_partial'}}, [{'path': '/delivery/scope', 'op': 'equals', 'value': 'direct'}])
    assert not assertions({}, [{'path': '/absent', 'op': 'absent'}])
    assert assertions({'x': False}, [{'path': '/x', 'op': 'one_of', 'value': [0, 1]}])


def test_schema_generator_reaches_optional_nested_fields_and_both_branches():
    schema = {'type': 'object', 'properties': {'optional': {'oneOf': [
        {'type': 'object', 'properties': {'a': {'type': 'integer', 'minimum': 1}}, 'required': ['a'], 'additionalProperties': False},
        {'type': 'object', 'properties': {'b': {'type': 'string', 'enum': ['x', 'y']}}, 'required': ['b'], 'additionalProperties': False},
    ]}}, 'additionalProperties': False}
    surface = Surface('synthetic', schema, 'model', lambda value: value)
    cases = list(generate(surface))
    assert any(case['field'] == '/optional/a' and case['variant'] == 'minimum--1' and case['expected'] == 'reject' for case in cases)
    assert any(case['field'] == '/optional/b' and case['payload']['optional']['b'] == 'y' and case['expected'] == 'accept' for case in cases)
    assert len({case['case_id'] for case in cases}) == len(cases)


def test_oneof_color_selectors_do_not_generate_an_invalid_full_seed():
    schema = {'type': 'object', 'properties': {'color': {'type': 'integer'}, 'hex': {'type': 'string'}},
              'oneOf': [{'required': ['color']}, {'required': ['hex']}]}
    assert sample(schema, schema) == {'color': 0}


def test_unprepared_account_action_cannot_inherit_a_direct_chat_scope(tmp_path):
    spec = manifest()
    spec['steps'][0].update(tool='write_whatsapp', arguments={
        'operation': 'profile_set_profile_name', 'arguments': {'body': {'name': 'Synthetic'}}})
    journal = create(tmp_path, spec)
    journal.enable_live('Synthetic direct-message mandate')
    assert journal.next()['status'] == 'needs_binding'
    assert journal.report()['steps'][0]['state'] == 'PENDING'
    journal.close()


def test_message_mutation_cannot_use_an_unobserved_message_id(tmp_path):
    spec = manifest()
    spec['steps'][0].update(tool='write_whatsapp', arguments={
        'operation': 'messages_set_reaction',
        'arguments': {'body': {'messageId': 'unrelated-message', 'reaction': '👍'}}})
    journal = create(tmp_path, spec)
    journal.enable_live('Synthetic direct-message mandate')
    with pytest.raises(ValueError, match='captured by this campaign'):
        journal.next()
    journal.close()


def test_fixture_preparation_checks_hashes_and_preserves_existing_files(tmp_path):
    from qa.suites import prepare_fixtures, suite_plan
    root = Path(__file__).resolve().parents[1]
    assert len(suite_plan(root)) == 7
    result = prepare_fixtures(root, tmp_path / 'media')
    assert len(result['fixtures']) == 9
    prepare_fixtures(root, tmp_path / 'media')
    existing = tmp_path / 'media' / 'sample.txt'
    existing.write_bytes(b'pre-existing private file')
    with pytest.raises(FileExistsError):
        prepare_fixtures(root, tmp_path / 'media')
    assert existing.read_bytes() == b'pre-existing private file'

def test_only_registered_generated_files_can_be_staged(tmp_path):
    spec=manifest()
    spec['steps'][0].update(tool='prepare_file',arguments={'file':'/private/report.txt'},capture={})
    journal=create(tmp_path,spec)
    journal.enable_live('Synthetic test only')
    with pytest.raises(ValueError, match='registered generated'):
        journal.next()
    journal.close()


def test_group_creation_cannot_add_an_undeclared_participant(tmp_path):
    spec=manifest()
    spec['steps'][0].update(tool='write_whatsapp',arguments={
        'operation':'groups_create_group','arguments':{'body':{
            'name':'QA qa-synthetic-20261023','participants':[{'id':'188888888@c.us'}]}}},
        capture={})
    journal=create(tmp_path,spec)
    journal.enable_live('Synthetic test only')
    with pytest.raises(ValueError, match='test destinations'):
        journal.next()
    journal.close()


def test_foreign_transfer_cannot_be_sent_to_an_allowed_chat(tmp_path):
    spec=manifest()
    spec['steps'][0].update(tool='send_media',arguments={
        'operation':'messages_send_image','transfer_id':'foreign-transfer',
        'arguments':{'body':{'chatId':'199999998@c.us'}}},capture={})
    journal=create(tmp_path,spec)
    journal.enable_live('Synthetic test only')
    with pytest.raises(ValueError, match='captured'):
        journal.next()
    journal.close()


def test_upload_id_contract_and_resume_poll_never_repeat_the_upload(tmp_path):
    destination='199999998@c.us'
    spec={'version':1,'steps':[
        {'id':'prepare','executor':'native','effect':'write','tool':'prepare_file',
         'arguments':{'file':'/generated/QA.png'},'destinations':[destination],
         'assertions':[{'path':'/id','op':'nonempty'}],'capture':{'transfer_id':'/id'}},
        {'id':'ready','executor':'native','effect':'write','tool':'get_transfer_status',
         'arguments':{'transfer_id':{'$ref':'/steps/prepare/transfer_id'}},
         'destinations':[destination],'depends_on':['prepare'],
         'assertions':[{'path':'/state','op':'equals','value':'ready'}],'retry_read':True}
    ]}
    journal=Journal.create(tmp_path/'campaign.sqlite',spec,{'allowed_chat_ids':[destination],
                           'fixture_files':['/generated/QA.png']},run_id='qa-synthetic-20261023')
    journal.enable_live('Synthetic test only')
    assert journal.next()['tool']=='prepare_file'
    # Real observed native shape: an id field, not transfer_id.
    assert journal.record('prepare',{'id':'media_fixture','state':'queued'})['state']=='PASS'
    assert journal.next()['arguments']=={'transfer_id':'media_fixture'}
    journal.close()
    resumed=Journal(tmp_path/'campaign.sqlite')
    instruction=resumed.next()
    assert instruction['tool']=='get_transfer_status'
    assert instruction['status']=='observe' and instruction['resend'] is False
    assert resumed.record('ready',{'id':'media_fixture','state':'ready'})['state']=='PASS'
    resumed.close()

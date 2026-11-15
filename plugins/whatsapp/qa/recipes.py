"""Concrete, scoped native/browser smoke steps and full-catalog coverage index.

Only the scoped live recipes are executable automatically. The full catalog index
keeps per-operation contract/suite/live obligations separate, so a generated
input or a passing unit test cannot silently close a production requirement.
"""
from __future__ import annotations

import ast
import csv
import json
from pathlib import Path

from .campaign import validate_manifest


def ref(path):
    return {'$ref': path}


def text(*parts):
    return {'$text': list(parts)}


def check(path, value, op='equals'):
    return {'path': path, 'op': op, 'value': value}


def smoke_manifest():
    peer = ref('/bindings/testx/chat_id')
    marker = text('QA ', ref('/run_id'))
    message = text(marker, ' · text à 😀\nseconda riga')
    reply = text(marker, ' · risposta TESTX')
    edited = text(marker, ' · text modificato')
    steps = []

    def native(identifier, tool, arguments, checks, *, effect='read', depends=(), capture=None, **extra):
        step = {'id': identifier, 'executor': 'native', 'tool': tool, 'arguments': arguments,
                'effect': effect, 'depends_on': list(depends), 'assertions': checks,
                'capture': capture or {}, **extra}
        if effect == 'write':
            step['destinations'] = [peer]
        steps.append(step)

    def browser(identifier, action, arguments, checks, *, depends=()):
        steps.append({'id': identifier, 'executor': 'browser', 'action': action,
                      'arguments': {'marker': marker, 'chat_label': ref('/bindings/owner/web_label'), **arguments},
                      'effect': 'write', 'destinations': [ref('/bindings/owner/chat_id')], 'depends_on': list(depends),
                      'assertions': checks, 'coverage': ['real_browser_peer']})

    native('plugin_ready', 'connection_status', {},
           [check('/connection', 'WORKING'), check('/connection_fresh', True), check('/readiness/ready', True)],
           coverage=['connection_status'])
    native('profile', 'get_profile', {}, [check('/id', None, 'nonempty')],
           depends=['plugin_ready'], capture={'profile_id': '/id'}, coverage=['get_profile'])
    for name in ('contacts_check_exists', 'chats_edit_message', 'messages_set_reaction'):
        native('schema_' + name, 'get_operation_schema', {'operation': name},
               [check('/operation', name)], depends=['plugin_ready'], coverage=['get_operation_schema', name])
    native('peer_registered', 'read_whatsapp', {'operation': 'contacts_check_exists',
           'arguments': {'query': {'phone': ref('/bindings/testx/phone')}}},
           [check('/result/numberExists', True), check('/result/chatId', peer)],
           depends=['schema_contacts_check_exists'], coverage=['contacts_check_exists', 'read_whatsapp'])
    steps.append({'id': 'peer_identity', 'executor': 'browser', 'action': 'verify_identity',
                  'arguments': {'expected_name': ref('/bindings/testx/name'),
                                'expected_phone': ref('/bindings/testx/phone')},
                  'effect': 'read', 'depends_on': ['peer_registered'],
                  'assertions': [check('/identity_matches', True)], 'coverage': ['browser_identity']})
    native('native_text_submit', 'send_text', {'chat_id': peer, 'text': message},
           [check('/state', 'submitted'), check('/provider_id', None, 'nonempty')], effect='write',
           depends=['peer_identity'], capture={'message_id': '/provider_id', 'key': '/key'},
           coverage=['send_text', 'unicode', 'idempotency', 'submission'])
    browser('peer_observe_text', 'observe_message', {'expected_text': message},
            [check('/match_count', 1), check('/text', message)], depends=['native_text_submit'])
    native('native_text_receipt', 'get_send_status', {'idempotency_key': ref('/steps/native_text_submit/key')},
           [check('/delivery/scope', 'direct'), check('/delivery/evidence/read/ack', 3)],
           depends=['peer_observe_text'], retry_read=True, coverage=['get_send_status', 'read_receipt'])
    browser('peer_reply', 'send_text', {'text': reply}, [check('/match_count', 1), check('/text', reply)],
            depends=['native_text_receipt'])
    native('incoming_search', 'search_messages', {'chat_id': peer, 'query': reply, 'limit': 10},
           [check('/messages/0/body', reply), check('/messages/0/chat_id', [peer, ref('/bindings/testx/pn')], 'one_of'), check('/messages/0/from_me', False)], depends=['peer_reply'], retry_read=True,
           capture={'message_id': '/messages/0/id'}, coverage=['search_messages', 'incoming_message'])
    native('incoming_get', 'get_message', {'message_id': ref('/steps/incoming_search/message_id')},
           [check('/message/body', reply)], depends=['incoming_search'], coverage=['get_message'])
    native('native_edit', 'write_whatsapp', {'operation': 'chats_edit_message',
           'arguments': {'path': {'chatId': peer, 'messageId': ref('/steps/native_text_submit/message_id')},
                         'body': {'text': edited}}},
           [check('/state', 'submitted')], effect='write', depends=['incoming_get', 'schema_chats_edit_message'],
           coverage=['chats_edit_message', 'write_whatsapp'])
    browser('peer_observe_edit', 'observe_message', {'expected_text': edited},
            [check('/match_count', 1), check('/text', edited)], depends=['native_edit'])
    native('native_reaction', 'write_whatsapp', {'operation': 'messages_set_reaction',
           'arguments': {'body': {'messageId': ref('/steps/incoming_search/message_id'), 'reaction': '👍'}}},
           [check('/state', 'submitted')], effect='write',
           depends=['peer_observe_edit', 'schema_messages_set_reaction'], coverage=['messages_set_reaction'])
    # This is a deliberate checkpoint, not a claim that reaction submission
    # proves rendering. The browser adapter returns the observed emoji.
    browser('peer_observe_reaction', 'observe_reaction', {'expected_text': reply, 'emoji': '👍'},
            [check('/reaction', '👍'), check('/match_count', 1)], depends=['native_reaction'])
    steps.append({'id': 'mobile_sample', 'executor': 'human', 'effect': 'human',
                  'depends_on': ['peer_observe_reaction'], 'instruction':
                  'Open only the prepared test group; read the message when prompted and confirm the image, audio and video samples.',
                  'arguments': {'group_ready': ref('/bindings/mobile/group_ready')},
                  'assertions': [check('/confirmed', True), check('/group_ready', True)],
                  'coverage': ['physical_phone_checkpoint']})
    return validate_manifest({'version': 1, 'name': 'WhatsApp native and TESTX browser readiness',
                              'scope': 'Preparation defaults to no live writes. All receipts are distinct from submission.',
                              'steps': steps})


def media_group_manifest():
    """A generated-fixture group with observed participant and media checkpoints."""
    peer = ref('/bindings/testx/pn')
    group = ref('/steps/create_group/created_group_id')
    marker = text('QA ', ref('/run_id'))
    steps = []
    def native(identifier, tool, arguments, checks, effect='read', depends=(), capture=None, destinations=None, **extra):
        step = dict(id=identifier, executor='native', tool=tool, arguments=arguments,
                    assertions=checks, effect=effect, depends_on=list(depends), capture=capture or {},
                    coverage=[arguments.get('operation', tool)], **extra)
        if effect == 'write':
            step['destinations'] = destinations or [group]
        steps.append(step)
    native('schema_create_group', 'get_operation_schema', {'operation':'groups_create_group'},
           [check('/operation','groups_create_group')])
    native('create_group','write_whatsapp', {'operation':'groups_create_group',
           'arguments':{'body':{'name':marker,'participants':[{'id':peer}]}}},
           [check('/state','submitted'),check('/result/id',None,'nonempty')], effect='write',
           depends=['schema_create_group'], capture={'created_group_id':'/result/id'}, destinations=[peer])
    native('schema_get_group','get_operation_schema',{'operation':'groups_get_group'},
           [check('/operation','groups_get_group')])
    native('get_group','read_whatsapp',{'operation':'groups_get_group','arguments':{'path':{'id':group}}},
           [check('/result/JID',group),check('/result/Name',marker)], depends=['create_group','schema_get_group'])
    intro=text(marker,' · text nel gruppo')
    native('group_text','send_text',{'chat_id':group,'text':intro},
           [check('/state','submitted'),check('/provider_id',None,'nonempty')],effect='write',
           depends=['get_group'],capture={'message_id':'/provider_id','key':'/key'})
    for kind, operation in [('image','messages_send_image'),('document','messages_send_file'),
                            ('voice','messages_send_voice'),('video','messages_send_video'),
                            ('sticker','messages_send_sticker')]:
        native('schema_'+kind,'get_operation_schema',{'operation':operation},[check('/operation',operation)])
        native('prepare_'+kind,'prepare_file',{'file':ref('/bindings/media/'+kind)},
               [check('/id',None,'nonempty')],effect='write',depends=['group_text'],
               capture={'transfer_id':'/id'})
        native('ready_'+kind,'get_transfer_status',{'transfer_id':ref('/steps/prepare_'+kind+'/transfer_id')},
               [check('/state','ready')],effect='write',depends=['prepare_'+kind],retry_read=True)
        body={'chatId':group}
        if kind in ('image','document','video'):body['caption']=text(marker,' · ',kind)
        if kind in ('voice','video'):body['convert']=True
        native('send_'+kind,'send_media',{'operation':operation,'transfer_id':ref('/steps/prepare_'+kind+'/transfer_id'),
               'arguments':{'body':body}},[check('/state','submitted'),check('/provider_id',None,'nonempty')],
               effect='write',depends=['schema_'+kind,'ready_'+kind],capture={'message_id':'/provider_id','key':'/key'})
    steps.append(dict(id='observe_group_text',executor='browser',action='observe_message',effect='write',
                 arguments={'marker':marker,'chat_label':marker,'expected_text':intro},destinations=[group],
                 depends_on=['send_sticker'],assertions=[check('/match_count',1),check('/text',intro)],coverage=['group_peer_observation']))
    steps.append(dict(id='group_reply',executor='browser',action='send_text',effect='write',
                 arguments={'marker':marker,'chat_label':marker,'text':text(marker,' · risposta TESTX nel gruppo')},
                 destinations=[group],depends_on=['observe_group_text'],
                 assertions=[check('/match_count',1)],coverage=['group_peer_reply']))
    native('group_receipt','get_send_status',{'idempotency_key':ref('/steps/group_text/key')},
           [check('/delivery/scope','group_partial')],depends=['group_reply'],retry_read=True)
    native('group_incoming','search_messages',{'chat_id':group,'query':text(marker,' · risposta TESTX nel gruppo'),'limit':10},
           [check('/messages/0/from_me',False),check('/messages/0/chat_id',group)],depends=['group_reply'],retry_read=True)
    return validate_manifest({'version':1,'name':'Generated media and disposable group','steps':steps})


def coverage_index(plugin_root, destination):
    root = Path(plugin_root)
    catalog = json.loads((root / 'sally_whatsapp/operations.json').read_text(encoding='utf-8'))
    events = json.loads((root / 'docs/event-coverage.json').read_text(encoding='utf-8'))
    references = {name: [] for name in catalog}
    for path in sorted((root / 'tests').glob('test_*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            values = {part.value for part in ast.walk(node) if isinstance(part, ast.Constant) and isinstance(part.value, str)}
            for name in values & references.keys():
                references[name].append(str(path.relative_to(root)) + '::' + node.name)
    live = {}
    for recipe in (smoke_manifest(), media_group_manifest()):
        for step in recipe['steps']:
            for name in step.get('coverage', ()):
                live.setdefault(name, []).append(step['id'])
    families = {'profile': 'profile_snapshot_restore', 'messages': 'message_and_media_corpus',
                'chats': 'sacrificial_chat_and_messages', 'calls': 'incoming_call',
                'channels': 'disposable_channel_and_cleanup', 'status': 'restricted_audience_status',
                'labels': 'supported_label_account', 'contacts': 'exact_test_contact',
                'identifiers': 'verified_pn_lid', 'groups': 'disposable_group_and_peer_admin',
                'presence': 'peer_observation', 'calendar': 'test_event', 'sessions': 'session_readiness'}
    rows = []
    for name, op in catalog.items():
        rows.append({'operation': name, 'family': op['family'], 'capability': op['capability'],
                     'synthetic_contract': 'automatic', 'referenced_existing_tests': '|'.join(references[name]),
                     'live_recipe': '|'.join(live.get(name, [])),
                     'fixture_requirement': families.get(op['family'], op['family']),
                     'live_status': 'NOT_SUPPORTED' if op['capability'] == 'unsupported_gows' else 'NOT_EXECUTED',
                     'coverage_note': 'Literal test references are an index, not proof of assertion coverage.'})
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with (destination / 'operation-coverage.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), delimiter=';')
        writer.writeheader(); writer.writerows(rows)
    (destination / 'event-coverage.json').write_text(json.dumps(events, indent=2) + '\n', encoding='utf-8')
    (destination / 'live-readiness.json').write_text(json.dumps(smoke_manifest(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (destination / 'live-media-group.json').write_text(json.dumps(media_group_manifest(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return rows

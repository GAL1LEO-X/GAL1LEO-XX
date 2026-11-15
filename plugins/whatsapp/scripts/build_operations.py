import json
import re
import sys
from pathlib import Path
from jsonschema import Draft202012Validator

import argparse
parser=argparse.ArgumentParser(description='Build the fixed catalog from the installed WAHA 2026.9.2 OpenAPI specification')
parser.add_argument('openapi',type=Path)
parser.add_argument('--output',type=Path,help='Catalog destination; defaults to the packaged operations.json')
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from sally_whatsapp.operation_schema import complete_schema
source=json.loads(args.openapi.read_text(encoding='utf-8'))
families = {'ProfileController':'profile','ChattingController':'messages','ChatsController':'chats',
            'CallsController':'calls','ChannelsController':'channels','StatusController':'status',
            'LabelsController':'labels','ContactsController':'contacts','ContactsSessionController':'contacts',
            'LidsController':'identifiers','GroupsController':'groups','PresenceController':'presence',
            'EventsController':'calendar','SessionsController':'sessions'}
# Only these owner-session reads belong in MCP. Never expose administration,
# session credentials, start/stop/logout or caller-selected session lifecycle.
session_reads={'fetchMessageCapping':('get','/api/sessions/{session}/capping'),
               'fetchReachoutTimelock':('get','/api/sessions/{session}/timelock')}
unsupported = {'deleteChat','clearMessages','pinMessage','unpinMessage','archiveChat','unarchiveChat'}
unsupported_names={'messages_set_star','messages_send_buttons_reply',
                   'contacts_get_about','contacts_block','contacts_unblock','channels_delete','groups_delete_group'}
ab_operations={'contacts_get_about','contacts_block','contacts_unblock',
               'chats_archive_chat','chats_unarchive_chat','messages_set_star',
               'chats_pin_message','chats_unpin_message'}

def expand(node, seen=()):
    if isinstance(node,list): return [expand(v,seen) for v in node]
    if not isinstance(node,dict): return node
    if '$ref' in node:
        name=node['$ref'].split('/')[-1]
        if name in seen: raise ValueError('Recursive schema: '+name)
        return expand(source['components']['schemas'][name],(*seen,name))
    value={k:expand(v,seen) for k,v in node.items() if k not in ('example','examples','default','nullable')}
    if value.get('type')=='object' and 'properties' in value:
        value['additionalProperties']=False
    return value

catalog={}
for path, methods in source['paths'].items():
    for method, detail in methods.items():
        if method not in ('get','post','put','delete'): continue
        controller,_,action=detail.get('operationId','').partition('_')
        if action in ('getABCapabilities','getChatArchiveState'): continue  # Internal provider contract/cache probes, not new MCP operations.
        if controller not in families or detail.get('deprecated') or 'DEPRE' in action.upper(): continue
        if path in ('/api/sendText','/api/messages','/api/reply') and method=='get': continue
        if controller=='SessionsController' and session_reads.get(action)!=(method,path): continue
        if action in ('getNewMessageId','getMessages','reply'): continue
        # Creation/voting were explicitly removed from the plugin. Keep
        # historical event readers, but never regenerate these write routes.
        if controller=='ChattingController' and action in ('sendPoll','sendPollVote'): continue
        family=families[controller]
        slug=re.sub(r'(?<!^)(?=[A-Z])','_',action).lower()
        name=family+'_'+slug
        if name in catalog: name+='_session'
        schemas={part:{'type':'object','properties':{},'required':[],'additionalProperties':False} for part in ('path','query')}
        inject=[]
        for p in detail.get('parameters',[]):
            loc=p['in']
            if loc not in schemas: continue
            if p['name']=='session':
                inject.append(loc)
                continue
            ps=expand(p.get('schema',{'type':'string'}))
            if p['name']=='limit': ps.update(minimum=1,maximum=100)
            if p['name']=='offset': ps.update(minimum=0)
            schemas[loc]['properties'][p['name']]=ps
            if p.get('required'): schemas[loc]['required'].append(p['name'])
        raw=detail.get('requestBody',{}).get('content',{}).get('application/json',{}).get('schema')
        body=expand(raw) if raw else {'type':'object','properties':{},'additionalProperties':False}
        if 'session' in body.get('properties',{}):
            inject.append('body')
            body['properties'].pop('session')
            body['required']=[v for v in body.get('required',[]) if v!='session']
        media='file' in body.get('properties',{})
        media_path=['file'] if media else []
        media_required='file' in body.get('required',[])
        if media:
            body['properties'].pop('file')
            body['required']=[v for v in body.get('required',[]) if v!='file']
        if action=='sendLinkCustomPreview':
            body['properties']['preview']['properties'].pop('image')
            media=True
            media_path=['preview','image']
            # The pinned GOWS adapter calls fileToMedia unconditionally, although
            # the WAHA DTO declares the image optional. Only a ready transfer
            # may supply this image; never expose a caller-supplied image URL.
            media_required=True
        if name in ('messages_send_text','chats_edit_message','status_send_text_status'):
            for flag in ('linkPreview','linkPreviewHighQuality'):
                body['properties'][flag]={'type':'boolean','const':False,
                    'description':'Automatic link previews are disabled; omit or set false.'}
        if name=='messages_forward_message':
            # WAHA 90ba445 / GOWS 120a614 implement forwarding despite the
            # current website matrix. The bridge verifies the source before
            # queueing and dispatch; a bare raw ID cannot identify its chat.
            body['properties']['messageId'].update(minLength=1,maxLength=512,
                description='Complete provider message ID including source chat; verified live without importing history. Known removals, uncertain clear coverage and superseded edits prevent forwarding.')
        if name=='messages_send_location':
            body['properties']['latitude'].update(minimum=-90,maximum=90)
            body['properties']['longitude'].update(minimum=-180,maximum=180)
        if name=='messages_send_contact_vcard':
            # Contact.vcard defaults to null in the pinned DTO; toVcardV3
            # generates it from the structured fields when it is omitted.
            # Preserve existing optional string overrides and the raw branch.
            for alternative in body['properties']['contacts']['items']['oneOf']:
                if {'fullName','phoneNumber'} <= alternative.get('properties',{}).keys():
                    alternative['required']=[field for field in alternative.get('required',[]) if field!='vcard']
                    alternative['properties']['vcard']['description']=(
                        'Optional raw vCard override; generated from the structured contact when omitted.')
        if name=='messages_send_list':
            # The pinned GOWS adapter rejects groups, broadcast and newsletter
            # destinations before dispatch. Require an exact direct-chat ID.
            body['properties']['chatId'].update(
                pattern=r'^[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)$',
                description='Exact direct-chat PN/LID ID. Groups, broadcasts and channels are not supported for lists.')
        if name=='calendar_send_event':
            for field in ('startTime','endTime'):
                body['properties']['event']['properties'][field].update(
                    type='integer',minimum=0,maximum=253402300799,
                    description=('Start' if field=='startTime' else 'End')+
                        ' time in Unix seconds, not milliseconds. endTime must not precede startTime.')
        if name=='chats_post_chats_overview':
            pagination=body['properties']['pagination']['properties']
            pagination['limit'].update(minimum=1,maximum=100)
            pagination['offset'].update(minimum=0)
        if name=='chats_read_chat_messages':
            query=schemas['query']['properties']
            query['messages'].update(type='integer',minimum=1,maximum=100,
                description='Maximum unread messages to mark read (1..100 local limit). Omit for 30 in direct chats or 100 in groups.')
            query['days'].update(minimum=0,
                description='Non-negative age window in days; fractional days are supported. Omit for 7 days.')
        if name=='status_delete_status':
            # DeleteStatusRequest overrides the optional StatusRequest.id;
            # pinned Swagger inherits the optional flag from the base DTO.
            body['required']=list(dict.fromkeys([*body.get('required',[]),'id']))
        if name=='calls_reject_call':
            # RejectCallRequest requires IsString + IsNotEmpty for both fields.
            for field in ('from','id'):
                body['properties'][field]['minLength']=1
        if name=='channels_search_by_view':
            body['properties']['countries']['minItems']=1
        if name=='channels_search_by_text':
            body['properties']['text']['minLength']=1
        if name in ('channels_search_by_view','channels_search_by_text'):
            body['properties']['limit'].update(type='integer',minimum=1,maximum=100,
                description='Maximum channels per page (1..100 local limit).')
            body['properties']['startCursor'].update(default='',
                description='Omit or use an empty string for the first page; use the returned endCursor for the next page.')
            # The bridge keeps an explicit page budget even if a provider DTO
            # supplies its own default. This preserves the public MCP contract.
            body['required']=[field for field in body.get('required',[]) if field not in ('startCursor','limit')]+['limit']
        if name in ('labels_create','labels_update'):
            # LabelBody.toDTO in the pinned WAHA source rejects neither/both
            # selectors and hex values outside this exact supported palette.
            body['oneOf']=[{'required':['color']},{'required':['colorHex']}]
            # GOWS serializes this field as int32. Do not infer that the remote
            # service rejects integers outside the standard 20-color palette.
            body['properties']['color'].update(type='integer',minimum=-(2**31),maximum=2**31-1,
                description='Color index, not hex; the standard palette uses 0..19.')
            body['properties']['colorHex']['enum']=[
                '#ff9485','#64c4ff','#ffd429','#dfaef0','#99b6c1','#55ccb3',
                '#ff9dff','#d3a91d','#6d7cce','#d7e752','#00d0e2','#ffc5c7',
                '#93ceac','#f74848','#00a0f2','#83e422','#ffaf04','#b5ebff',
                '#9ba6ff','#9368cf']
        if family=='channels' and action=='create':
            body['properties'].pop('picture')
            media=True
            media_path=['picture']
        readonly=method=='get' and family!='presence'
        if action in ('searchByView','searchByText','getPresenceAll','postChatsOverview'): readonly=True
        # Fetching an invite code can generate a code on the provider, so it is an action.
        if action=='getInviteCode': readonly=False
        sending=family in ('messages','calendar') and not readonly or family=='status' and action.startswith('send')
        if name in ('chats_edit_message','chats_read_chat_messages'): sending=True
        capability='unsupported_gows' if action in unsupported and family=='chats' else 'gateway_available'
        if family in ('labels','channels'): capability='account_and_engine_dependent'
        if name in unsupported_names: capability='unsupported_gows'
        if name in ab_operations: capability='gows_ab_v1'
        if name=='messages_set_star': sending=False  # Personal account metadata.
        if name in ('chats_pin_message','chats_unpin_message'): sending=True  # Visible conversation effect.
        if name=='chats_pin_message':
            body['properties']['duration'].update(type='integer',enum=[86400,604800,2592000])
        catalog[name]={'family':family,'method':method.upper(),'path':path,'readonly':readonly,'sending':sending,
                       'media':media,'media_path':media_path,'media_required':media_required,
                       'capability':capability,'inject_session':inject,
                       'description':detail.get('summary',action),
                       'schema':{'type':'object','properties':{**schemas,'body':body},'additionalProperties':False}}
for operation in catalog.values():
    complete_schema(operation['schema'])
    Draft202012Validator.check_schema(operation['schema'])
out=args.output or root/'sally_whatsapp'/'operations.json'
out.write_text(json.dumps(catalog,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'operations':len(catalog),'media':sum(x['media'] for x in catalog.values()),
                  'read':sum(x['readonly'] for x in catalog.values()),'bytes':out.stat().st_size}))

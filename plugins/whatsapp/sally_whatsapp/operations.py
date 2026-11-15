"""Fixed application operation catalog. No arbitrary URLs, methods, sessions or admin API."""
import copy
import json
import re
from pathlib import Path
from urllib.parse import quote, urlsplit

from jsonschema import Draft202012Validator
from .store import operation_result_metadata, INVITE_CODE_OPERATIONS, PARTICIPANT_RESULT_OPERATIONS
from . import ab_operations
from .operation_outcomes import provider_outcome

OPERATIONS=json.loads(Path(__file__).with_name('operations.json').read_text(encoding='utf-8'))
AUTOMATIC_PREVIEW_OPERATIONS=('messages_send_text','chats_edit_message','status_send_text_status')


class OperationArgumentError(ValueError):
    """Caller arguments rejected locally, before any provider dispatch."""


class OperationUnavailable(ValueError):
    """A provider limitation, distinct from invalid input or missing consent."""

    def __init__(self, name, capability):
        self.name, self.capability = name, capability
        unsupported = capability == 'unsupported_gows'
        super().__init__('This action is not supported by the currently installed GOWS engine'
                         if unsupported else
                         'This operation requires the qualified GOWS A/B provider; check engine availability')

    def detail(self):
        unsupported = self.capability == 'unsupported_gows'
        return {'error_code': 'OPERATION_UNSUPPORTED' if unsupported else 'PROVIDER_CAPABILITY_UNAVAILABLE',
                'operation': self.name, 'capability': self.capability,
                'limitation': 'provider_not_implemented' if unsupported else 'required_provider_contract_unavailable',
                'message': str(self), 'retryable': False}


def message_acknowledged(value):
    """A usable message identity is required; HTTP acceptance is not delivery.

    Keep opaque provider IDs for compatibility. Reject missing, oversized or
    control-bearing identifiers and explicitly contradictory acknowledgements.
    No response validation can prove delivery or justify retrying a mutation.
    """
    if not isinstance(value, dict):
        return False
    identifier = value.get('id')
    return (isinstance(identifier, str) and 0 < len(identifier) <= 512
            and not any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in identifier)
            and provider_outcome(value) not in ('rejected', 'partial', 'uncertain')
            and value.get('outcome', 'accepted') == 'accepted')


def public_result(value):
    if isinstance(value,list): return [public_result(v) for v in value]
    if isinstance(value,dict):
        from .lifetime import project
        value=project(value)
        return {k:public_result(v) for k,v in value.items() if not k.startswith('_') and k.lower() not in
                ('apikey','api_key','password','token','secret','credentials','mediaKey'.lower(),'directpath','fileencsha256')}
    return value


def validate_operation(name, arguments, *, readonly, transfer=None, provider_operations=()):
    op=OPERATIONS.get(name)
    if not op or op['readonly']!=readonly:
        raise OperationArgumentError('Unknown operation or incorrect read/action tool; use get_operation_schema')
    if op['capability']=='unsupported_gows':
        raise OperationUnavailable(name, op['capability'])
    if op['capability']==ab_operations.CAPABILITY and name not in provider_operations:
        raise OperationUnavailable(name, op['capability'])
    args={'path':{},'query':{},'body':{},**copy.deepcopy(arguments)}
    try:
        encoded=json.dumps(args,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
    except (TypeError,ValueError):
        raise OperationArgumentError('Operation arguments must be finite JSON values') from None
    if len(encoded)>200000:
        raise OperationArgumentError('Operation arguments too large')
    error=next(Draft202012Validator(op['schema']).iter_errors(args),None)
    if error:
        # Do not reflect arbitrary private input values in validation errors.
        raise OperationArgumentError('Invalid operation arguments at '+'.'.join(str(p) for p in error.absolute_path)+'; use get_operation_schema')
    from .operation_schema import normalize_paging
    normalize_paging(op['schema'], args)
    if name in ('channels_search_by_view','channels_search_by_text'):
        # Published default; do not rely on a particular provider's DTO
        # transformation to distinguish the initial page from continuation.
        args['body'].setdefault('startCursor','')
    if name=='presence_set_presence':
        directed=args['body']['presence'] in ('typing','recording','paused')
        if directed != bool(args['body'].get('chatId')):
            raise OperationArgumentError('Chat presence requires chatId; global online/offline presence must omit it')
    if name=='messages_send_list' and not re.fullmatch(
            r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)',args['body']['chatId']):
        # JSON Schema's $ anchor can match before a final newline. Require the
        # complete direct-chat identifier at both queue and worker validation.
        raise OperationArgumentError('Lists require an exact direct-chat PN/LID ID; groups, broadcasts and channels are unsupported')
    if name=='calendar_send_event':
        event=args['body']['event']
        if 'endTime' in event and event['endTime'] < event['startTime']:
            raise OperationArgumentError('Event endTime must not precede startTime; use Unix seconds')
    if transfer and not op['media'] or op['media_required'] and not transfer:
        raise OperationArgumentError('Use prepare_file/get_attachment then send_media with a ready transfer_id')
    for value in args['path'].values():
        if not isinstance(value,str) or not value or len(value)>512 or any(v in value for v in ('/','\\','..','%')):
            raise OperationArgumentError('Invalid path identifier')
    # Plain link text is allowed; custom link-preview destinations cannot be private hosts.
    if name=='messages_send_link_custom_preview':
        from .events import public_addresses
        url=urlsplit(args['body']['preview']['url'])
        if url.scheme not in ('http','https') or not url.hostname or url.username or url.password:
            raise OperationArgumentError('Invalid link preview URL')
        public_addresses(url.hostname)
    return op,args


def action_sends(op,args):
    return op['sending'] or (op==OPERATIONS['presence_set_presence']
                            and args['body'].get('presence') in ('typing','recording','paused'))


def authorization_rules(op):
    """Expose every policy branch without guessing a caller's destination."""
    if op==OPERATIONS['presence_set_presence']:
        return [{'effect':'chat_presence','when':'typing/recording/paused','permission':'send_enabled','destination':'body.chatId'},
                {'effect':'global_presence','when':'online/offline','permission':'account_actions_enabled','destination':'none'}]
    if op['readonly']:
        return [{'effect':'read','permission':'whatsapp:read','destination':'none'}]
    if op['sending']:
        destination=('body.contacts' if op['family']=='status' else 'acquired_message.chat_id'
                     if op==OPERATIONS['messages_set_reaction'] else 'path.chatId'
                     if 'chatId' in op['schema']['properties']['path']['properties'] else 'body.chatId')
        return [{'effect':'chat_write','permission':'send_enabled','destination':destination}]
    return [{'effect':'account_or_group_write','permission':'account_actions_enabled','destination':'none'}]


def require_action(settings,op,args,*,message_lookup=None):
    if action_sends(op,args):
        destinations=[]
        if args['body'].get('chatId'): destinations.append(args['body']['chatId'])
        if args['path'].get('chatId'): destinations.append(args['path']['chatId'])
        # Status contacts are recipients; contact-card contacts are message content.
        if op['family']=='status':
            destinations.extend(args['body'].get('contacts') or [])
        if op==OPERATIONS['messages_set_reaction'] and not settings.allow_all_destinations:
            # An arbitrary message ID is not proof of its chat. Use only an exact,
            # acquired, non-revoked message, and repeat this check in the worker.
            message=message_lookup(args['body']['messageId']) if message_lookup else None
            if message: destinations.append(message['chat_id'])
        if not settings.send_enabled or (not settings.allow_all_destinations and
               (not destinations or any(not settings.destination_allowed(v) for v in destinations))):
            raise ValueError('Sending is disabled or the destination is not allowed')
    elif not settings.account_actions_enabled:
        raise ValueError('Account and group modifications await authorization; the capability is available')


def _group_action_metadata(value):
    """Normalize only a group identifier, retaining the existing privacy projection.

    The pinned GOWS create route returns GroupInfo.JID; join returns a JID
    string. Already normalized ``id`` objects are also accepted. A conflicting
    or malformed response cannot identify the group, even when the operation
    was accepted: do not infer an ID from a name, owner or participant.
    """
    metadata=operation_result_metadata(value)
    if not isinstance(metadata,dict):
        return metadata
    metadata.pop('id',None)
    identifiers=([value] if isinstance(value,str) else
                 [value[field] for field in ('JID','id') if field in value]
                 if isinstance(value,dict) else [])
    if (identifiers and all(isinstance(identifier,str) and
            re.fullmatch(r'[0-9]{1,25}(?:-[0-9]{1,25})?@g\.us',identifier)
            for identifier in identifiers) and len(set(identifiers))==1):
        metadata['id']=identifiers[0]
    return metadata


def execute(gateway, settings, op, args, *, media=None, intent=None, target=None, validate_result=None):
    args=copy.deepcopy(args)
    if target is not None and op['capability']==ab_operations.CAPABILITY:
        # Source validation has proved the alias relationship. Preserve the
        # complete message key's namespace instead of asking WAHA to guess it.
        location='body' if op==OPERATIONS['messages_set_star'] else 'path'
        if 'chatId' in args[location]:
            args[location]['chatId']=target['chat_id']
    if any(op==OPERATIONS[name] for name in AUTOMATIC_PREVIEW_OPERATIONS):
        # WAHA defaults omitted preview flags to true. Apply the bridge policy
        # at the wire boundary, without changing persisted arguments or hashes.
        args['body']['linkPreview']=False
        args['body']['linkPreviewHighQuality']=False
    path=op['path'].replace('{session}',quote(settings.session,safe=''))
    for key,value in args['path'].items(): path=path.replace('{'+key+'}',quote(str(value),safe=''))
    if re.search(r'\{[^}]+\}',path): raise ValueError('Missing path identifier')
    for location in op['inject_session']:
        if location!='path': args[location]['session']=settings.session
    if media:
        obj=args['body']
        for key in op['media_path'][:-1]: obj=obj.setdefault(key,{})
        obj[op['media_path'][-1]]={'url':media['url']} if op['media_path']==['preview','image'] else media
    params={k:(str(v).lower() if type(v) is bool else v) for k,v in args['query'].items()}
    kwargs={'params':params}
    if not op['readonly']: kwargs['timeout']=600 if media else 120
    if op['capability']==ab_operations.CAPABILITY and not op['readonly']:
        kwargs['headers']=ab_operations.intent_headers(intent)
    if args['body']: kwargs['json']=args['body']
    value=gateway.request(op['method'],path,**kwargs)
    if op['capability']==ab_operations.CAPABILITY and not op['readonly']:
        if (not isinstance(value,dict) or value.get('outcome', 'accepted')!='accepted'
                or provider_outcome(value) in ('rejected', 'partial', 'uncertain')
                or not (value.get('outcome')=='accepted' or value.get('success') is True
                        or value.get('accepted') is True)):
            from .gateway import GatewayUnavailable
            raise GatewayUnavailable('A/B mutation outcome is uncertain; reconcile before repeating')
    if op==OPERATIONS['presence_get_presence_all']:
        from .presence import validate_presence_list
        validate_presence_list(value,getattr(gateway,'diagnostics',None))
    if op['readonly']:
        # Scope checks need original identity/time fields, before lifetime
        # projection can intentionally reduce a message to a withheld stub.
        if validate_result is not None: validate_result(value)
        return public_result(value)
    from .job_metadata import PRODUCING_OPERATIONS
    if any(op == OPERATIONS[name] for name in PRODUCING_OPERATIONS if name in OPERATIONS):
        if not message_acknowledged(value):
            from .gateway import GatewayUnavailable
            raise GatewayUnavailable('Message outcome is uncertain; reconcile before repeating')
    if any(op==OPERATIONS[name] for name in ('groups_create_group','groups_join_group')):
        return _group_action_metadata(value)
    operation=next((name for name in INVITE_CODE_OPERATIONS | PARTICIPANT_RESULT_OPERATIONS | {'presence_get_presence'}
                    if OPERATIONS[name]==op),None)
    if operation in INVITE_CODE_OPERATIONS and provider_outcome(value) not in ('rejected', 'partial', 'uncertain'):
        if not isinstance(value, str) or not re.fullmatch(r'(?:https://chat\.whatsapp\.com/)?[A-Za-z0-9_-]{1,128}', value):
            from .gateway import GatewayUnavailable
            raise GatewayUnavailable('Invite code outcome is uncertain; reconcile before repeating')
    return operation_result_metadata(value,operation=operation)

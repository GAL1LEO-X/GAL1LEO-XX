"""Compare supplied discovery exports without contacting or changing a service."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)


def _normalized(value,field=''):
    if isinstance(value,dict):
        return {key:_normalized(child,key) for key,child in value.items()}
    if isinstance(value,list):
        items=[_normalized(child) for child in value]
        # JSON Schema enum/required/type and OAuth scope order has no meaning.
        return sorted(items,key=_canonical) if field in ('enum','required','type','scopes') else items
    return value


def expected_contract():
    """Derive the comparison from runtime definitions, never a second catalog."""
    from mcp.server.lowlevel import Server
    from mcp_types.version import MODERN_PROTOCOL_VERSIONS
    from . import __version__
    from .server import (TOOLS,TOOL_EFFECTS,Profile,EVENT_DEFINITION,
                         ACCOUNT_EVENT_DEFINITION,DIGEST_EVENT_DEFINITION,EVENT_CAPABILITY,tool_oauth_scopes)
    # SDK capability derivation needs registered handlers, not a Service,
    # provider connection or settings. No handler is invoked here.
    async def declarations_only(*_):
        raise AssertionError('Discovery comparison must not execute handlers')
    sdk=Server('discovery-contract',on_list_tools=declarations_only,
               on_list_resources=declarations_only,on_list_resource_templates=declarations_only,
               on_read_resource=declarations_only)
    versions=sorted(MODERN_PROTOCOL_VERSIONS)
    capabilities=sdk.get_capabilities(protocol_version=versions[-1]).model_dump(by_alias=True,exclude_none=True)
    capabilities['events']=dict(EVENT_CAPABILITY)
    tools={}
    for name,(model,description,_,readonly) in TOOLS.items():
        destructive,idempotent,open_world=TOOL_EFFECTS[name]
        security=[{'type':'oauth2','scopes':tool_oauth_scopes(name)}]
        tools[name]={'description':description,'inputSchema':model.model_json_schema(),'outputSchema':None,
            'annotations':{'readOnlyHint':readonly,'destructiveHint':destructive,
                           'idempotentHint':idempotent,'openWorldHint':open_world},
            'securitySchemes':security,'_meta':{'securitySchemes':security,
                'openai/profile':None,'openai/fileParams':None}}
        if name=='get_profile':
            tools[name]['outputSchema']=Profile.model_json_schema()
            tools[name]['_meta']['openai/profile']=True
        if name=='prepare_file':
            tools[name]['_meta']['openai/fileParams']=['file']
    events={item['name']:{field:item[field] for field in ('delivery','inputSchema','payloadSchema')}
            for item in (EVENT_DEFINITION,ACCOUNT_EVENT_DEFINITION,DIGEST_EVENT_DEFINITION)}
    return {'backend_version':__version__,'supportedVersions':versions,
            'capabilities':capabilities,'tools':tools,'events':events}


def contract_summary():
    """Current server definition, not an assertion that a consumer reloaded it."""
    value = expected_contract()
    from .operations import OPERATIONS
    return {'backend_version': value['backend_version'],
            'tool_count': len(value['tools']), 'operation_catalog_count': len(OPERATIONS),
            'operation_enum_counts': {name: len(value['tools'][name]['inputSchema']['properties']['operation']['enum'])
                                      for name in ('read_whatsapp','write_whatsapp','send_media')},
            'contract_sha256': hashlib.sha256(_canonical(value).encode()).hexdigest(),
            'get_send_status_modes': ['single','uncertain'],
            'external_catalog_reload_verified': False}


def _result(response):
    if not isinstance(response,dict) or 'error' in response:
        raise ValueError('A successful discovery response is required')
    result=response.get('result',response)
    if not isinstance(result,dict):
        raise ValueError('Invalid discovery result')
    if result.get('nextCursor') or result.get('truncated') is True or result.get('resultType')!='complete':
        raise ValueError('A complete, untruncated discovery result is required')
    return result


def _named(result,field):
    entries=result.get(field)
    if not isinstance(entries,list):
        raise ValueError('Discovery entries must be a list')
    named={}
    for entry in entries:
        if not isinstance(entry,dict) or not isinstance(entry.get('name'),str) or not entry['name']:
            raise ValueError('Invalid discovery entry')
        if entry['name'] in named:
            raise ValueError('Duplicate discovery entry')
        named[entry['name']]=entry
    return named


def compare_snapshot(snapshot):
    """Check names and contracts; the provenance of a supplied export is unverified."""
    from mcp_types import SERVER_INFO_META_KEY
    if not isinstance(snapshot,dict) or snapshot.get('format')!='whatsapp-discovery-v1':
        raise ValueError('Expected a whatsapp-discovery-v1 snapshot')
    observed=snapshot.get('observed_at')
    try:
        timestamp=datetime.fromisoformat(observed.replace('Z','+00:00'))
        if timestamp.tzinfo is None:
            raise ValueError()
    except (AttributeError,TypeError,ValueError):
        raise ValueError('An observation timestamp with timezone is required') from None
    responses=snapshot.get('responses')
    if not isinstance(responses,dict) or set(responses)!={'server/discover','tools/list','events/list'}:
        raise ValueError('Provide server/discover, tools/list and events/list responses')
    discovery=_result(responses['server/discover'])
    actual={'tools':_named(_result(responses['tools/list']),'tools'),
            'events':_named(_result(responses['events/list']),'events')}
    expected=expected_contract()
    differences=[]
    capabilities=discovery.get('capabilities')
    if capabilities!=expected['capabilities']:
        differences.append({'location':'server/discover.capabilities','reason':'contract_mismatch'})
    versions=discovery.get('supportedVersions')
    if not isinstance(versions,list) or any(not isinstance(item,str) for item in versions) or sorted(versions)!=expected['supportedVersions']:
        differences.append({'location':'server/discover.supportedVersions','reason':'contract_mismatch'})
    metadata=discovery.get('_meta')
    info=metadata.get(SERVER_INFO_META_KEY,{}) if isinstance(metadata,dict) else {}
    if not isinstance(info,dict) or info.get('version')!=expected['backend_version']:
        differences.append({'location':'server/discover.backend_version','reason':'version_mismatch'})
    for family in ('tools','events'):
        names,seen=set(expected[family]),set(actual[family])
        for name in sorted(names-seen):
            differences.append({'location':family+'.'+name,'reason':'missing_entry'})
        for name in sorted(seen-names):
            # Unknown entry names are untrusted input; report their digest only.
            differences.append({'location':family,'reason':'unexpected_entry',
                                'name_sha256':hashlib.sha256(name.encode()).hexdigest()})
        for name in sorted(names & seen):
            for field,value in expected[family][name].items():
                candidate=actual[family][name].get(field)
                if field=='_meta' and isinstance(candidate,dict):
                    candidate={key:candidate.get(key) for key in value}
                if _normalized(candidate)!=_normalized(value):
                    differences.append({'location':family+'.'+name+'.'+field,'reason':'contract_mismatch'})
    # Give a precise name comparison for the historical incomplete event enum.
    wanted=expected['events']['whatsapp.event']['payloadSchema']['properties']['event_type']['enum']
    try:
        seen=actual['events']['whatsapp.event']['payloadSchema']['properties']['event_type']['enum']
        if not isinstance(seen,list) or any(not isinstance(item,str) for item in seen):
            raise ValueError()
    except (KeyError,TypeError,ValueError):
        seen=[]
    return {'status':'aligned' if not differences else 'mismatch',
        'evidence':'supplied_snapshot_only','external_catalog_verified':False,
        'observed_at':timestamp.isoformat(),'backend_version':expected['backend_version'],
        'expected_contract_sha256':hashlib.sha256(_canonical(expected).encode()).hexdigest(),
        'missing_application_events':sorted(set(wanted)-set(seen)),
        'differences':differences}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot',type=Path,help='Previously acquired and sanitized JSON discovery snapshot')
    args=parser.parse_args(argv)
    try:
        with args.snapshot.open('rb') as stream:
            content=stream.read(4*1024*1024+1)
        if len(content)>4*1024*1024:
            raise ValueError('Discovery snapshot exceeds 4 MiB')
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result: raise ValueError('Duplicate JSON key in discovery snapshot')
                result[key]=value
            return result
        snapshot=json.loads(content.decode('utf-8'),object_pairs_hook=unique)
        result=compare_snapshot(snapshot)
    except (OSError,ValueError,UnicodeError):
        # Do not echo filenames or arbitrary snapshot text into shared logs.
        print(json.dumps({'status':'invalid_snapshot','external_catalog_verified':False}))
        return 2
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result['status']=='aligned' else 1


if __name__=='__main__':
    raise SystemExit(main())

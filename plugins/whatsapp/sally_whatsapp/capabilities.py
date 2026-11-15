"""Describe configuration and current token grants without authorizing a payload."""
from .operations import OPERATIONS, OperationUnavailable, authorization_rules
from . import ab_operations


def capabilities(settings, scopes, family='', *, provider_operations=()):
    return [operation_capability(settings,scopes,name,provider_operations=provider_operations)
            for name,op in OPERATIONS.items() if not family or op['family']==family]


def operation_capability(settings, scopes, name, *, provider_operations=()):
    """One shared policy projection for capability and argument discovery."""
    op=OPERATIONS[name]
    configured=op['readonly'] or (settings.send_enabled if op['sending'] else settings.account_actions_enabled)
    scope='whatsapp:read' if op['readonly'] else 'whatsapp:send'
    policy='not_applicable'
    if op['sending']:
        policy='disabled' if not settings.send_enabled else 'all' if settings.allow_all_destinations else 'allowlist'
    rules=authorization_rules(op)
    for rule in rules:
        rule['configuration_enabled']=True if op['readonly'] else getattr(settings,rule['permission'])
        rule['required_scope']=scope
        rule['permission_enabled']=rule['configuration_enabled'] and scope in scopes
        rule['destination_policy']=('disabled' if not settings.send_enabled else 'all' if settings.allow_all_destinations else 'allowlist') if rule['permission']=='send_enabled' else 'not_applicable'
    if len(rules)>1:
        configured=all(rule['configuration_enabled'] for rule in rules)
        policy='depends_on_arguments'
    available = (name in provider_operations if op['capability']==ab_operations.CAPABILITY
                 else op['capability']!='unsupported_gows')
    return {'operation':name,**{key:op[key] for key in ('family','description','readonly','sending','media','capability')},
            'engine_available':available,
            'limitation':None if available else OperationUnavailable(name, op['capability']).detail(),
            'configuration_enabled':configured,'required_scope':scope,'scope_granted':scope in scopes,
            'permission_enabled':configured and scope in scopes,
            'authorization_rules':rules,
            'destination_policy':policy,'destination_checked':False}

"""Deployment model for isolated users, not a shared-data tenant switch in MCP."""
from dataclasses import dataclass,asdict
import copy
import json
import ipaddress
from pathlib import Path
import re
from urllib.parse import urlsplit
from .installation import Installation, active
from .config import MCP_SCOPES

ROOT=Path(active().path('project'))
ISSUER='https://identity.example.invalid'
CHATGPT_CALLBACK='https://chatgpt.com/connector_platform_oauth_redirect'
# ChatGPT can request the identity scopes advertised by the OIDC provider.
CHATGPT_OIDC_SCOPES=('openid','profile','email','offline_access')


def validate_hostname(value):
    """Canonical DNS name for administrator-controlled Apache/TLS input."""
    if (not isinstance(value,str) or len(value)>253 or value!=value.lower()
            or not value.isascii() or len(value.split('.'))<2
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label)
                   for label in value.split('.'))):
        raise ValueError('Use a canonical lowercase ASCII FQDN (IDNs as punycode)')
    try: ipaddress.ip_address(value)
    except ValueError: return value
    raise ValueError('A DNS hostname, not an IP address, is required')


def validate_https_url(value,*,origin=False):
    if (not isinstance(value,str) or not value or len(value)>2048
            or any(c.isspace() or ord(c)<32 or ord(c)==127 for c in value)
            or '\\' in value):
        raise ValueError('Use an explicit canonical HTTPS URL')
    u=urlsplit(value)
    validate_hostname(u.hostname)
    if (u.scheme!='https' or u.username is not None or u.password is not None
            or u.port is not None or u.query or u.fragment or u.netloc!=u.hostname
            or (origin and u.path)):
        raise ValueError('Use HTTPS without credentials, port, query or fragment')
    return value


def oidc_endpoints(instance,discovery):
    """Validate discovery against administrative configuration, never HTTP input."""
    if not isinstance(discovery,dict) or discovery.get('issuer')!=instance.issuer:
        raise ValueError('OIDC discovery issuer differs from the configured issuer')
    if discovery.get('jwks_uri')!=instance.effective_jwks_url:
        raise ValueError('OIDC discovery JWKS differs from the configured URL')
    issuer=urlsplit(instance.issuer)
    result={}
    for name,key in (('authorize_url','authorization_endpoint'),('token_url','token_endpoint')):
        value=validate_https_url(discovery.get(key))
        parsed=urlsplit(value)
        if parsed.netloc!=issuer.netloc or not parsed.path:
            raise ValueError('Pairing OAuth endpoints must belong to the configured issuer')
        result[name]=value
    return result


@dataclass(frozen=True)
class Instance:
    slug: str
    display_name: str
    subject: str
    bridge_port: int
    # Defaults preserve existing registry records; fresh setup supplies these explicitly.
    public_hostname: str | None = None
    issuer: str = ISSUER
    jwks_url: str | None = None
    chatgpt_callback: str = CHATGPT_CALLBACK
    auth_mode: str = 'managed-authelia'
    oauth_client_id: str | None = None
    pairing_client_id: str | None = None
    installation: dict | None = None

    def __post_init__(self):
        profile = Installation.legacy() if self.installation is None else Installation.from_dict(self.installation)
        if not profile.compatibility:
            # Registry records keep the original, immutable installation. A
            # later tenant may use only allocations admitted for that same
            # installation, never arbitrary per-record account/port overrides.
            selected = active()
            if selected.sha256 == profile.sha256:
                profile = selected
        object.__setattr__(self, '_installation_identity', profile)
        if not re.fullmatch(r'[a-z][a-z0-9-]{1,19}',self.slug) or '--' in self.slug:
            raise ValueError('Use a lowercase user identifier of 2..20 letters/digits/hyphens')
        if not self.display_name or len(self.display_name)>80 or any(ord(c)<32 for c in self.display_name):
            raise ValueError('Invalid display name')
        if self.auth_mode=='managed-authelia' and (not isinstance(self.subject,str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',self.subject)):
            raise ValueError('A stable UUID v4 subject is required')
        if self.auth_mode not in ('managed-authelia','external-oidc'):
            raise ValueError('Unsupported authentication setup mode')
        if (not isinstance(self.subject,str) or not self.subject or len(self.subject)>255
                or any(ord(c)<32 or ord(c)==127 for c in self.subject)):
            raise ValueError('An exact stable OIDC subject is required')
        if self.public_hostname is not None: validate_hostname(self.public_hostname)
        validate_https_url(self.issuer)
        validate_https_url(self.effective_jwks_url)
        validate_https_url(self.chatgpt_callback)
        if not urlsplit(self.chatgpt_callback).path:
            raise ValueError('The exact client callback path is required')
        for client in (self.oauth_client_id,self.pairing_client_id):
            if client is not None and (not isinstance(client,str) or not client or len(client)>200
                    or any(c.isspace() or ord(c)<32 or ord(c)==127 for c in client)):
                raise ValueError('Invalid registered OAuth client ID')
        if self.chatgpt_client==self.link_client:
            raise ValueError('MCP and pairing require distinct OAuth clients')
        if self.auth_mode=='external-oidc' and not all((self.public_hostname,self.jwks_url,
                                                      self.oauth_client_id,self.pairing_client_id)):
            raise ValueError('External OIDC setup requires hostname, JWKS and both registered client IDs')
        if profile.compatibility:
            if self.bridge_port<8820 or self.bridge_port>8998 or self.bridge_port%2:
                raise ValueError('Use an available even bridge port in 8820..8998')
            if (self.slug=='personal')!=(self.bridge_port==8820):
                raise ValueError('Port 8820 belongs to the preserved personal instance')
        else:
            if self.auth_mode != 'external-oidc':
                raise ValueError('General installations require external OIDC')
            if type(self.bridge_port) is not int or self.bridge_port != profile.instance_ports(self.slug)['bridge']:
                raise ValueError('Bridge port differs from the approved installation profile')
            profile.account(self.slug)

    @property
    def base(self): return self._installation_identity.service(self.slug)
    @property
    def username(self): return 'whatsapp-personale' if self.slug=='personal' else 'whatsapp-'+self.slug
    @property
    def service_user(self): return self._installation_identity.account(self.slug)
    @property
    def hostname(self): return self.public_hostname or ('whatsapp.example.invalid' if self.slug=='personal' else 'whatsapp-'+self.slug+'.example.invalid')
    @property
    def public_url(self): return 'https://'+self.hostname
    @property
    def config_dir(self): return Path(self._installation_identity.instance_paths(self.slug)['configuration'])
    @property
    def state_dir(self): return Path(self._installation_identity.instance_paths(self.slug)['state'])
    @property
    def gateway_home(self): return Path(self._installation_identity.instance_paths(self.slug)['gateway'])
    @property
    def gateway_port(self):
        return self.bridge_port+1 if self._installation_identity.compatibility else self._installation_identity.instance_ports(self.slug)['gateway']
    @property
    def chatgpt_client(self): return self.oauth_client_id or self.base+'-chatgpt'
    @property
    def link_client(self): return self.pairing_client_id or self.base+'-link'
    @property
    def effective_jwks_url(self): return self.jwks_url or self.issuer.rstrip('/')+'/jwks.json'
    @property
    def policy(self): return self.base.replace('-','_')+'_only'
    @property
    def project_root(self):
        return ROOT if self._installation_identity.compatibility else Path(self._installation_identity.path('project'))
    @property
    def private_dir(self): return self.project_root/'private/tenants'/self.slug
    @property
    def wrapper(self): return self.project_root/'scripts/as-user' if self.slug=='personal' else self.private_dir/'as-user'

    def record(self):
        result = asdict(self)
        if self._installation_identity.compatibility:
            result.pop('installation')
        else:
            result['installation'] = self._installation_identity.as_dict()
        return result

    def public_details(self):
        return {'id':self.slug,'display_name':self.display_name,'username':self.username,
                'mcp_url':self.public_url+'/mcp','pairing_url':self.public_url+'/connect',
                'oauth_client_id':self.chatgpt_client,'oauth_issuer':self.issuer,
                'oauth_client_auth_method':'none','callback':self.chatgpt_callback,
                'bridge_service':self.base+'.service','service_user':self.service_user,
                'bridge_port':self.bridge_port,'gateway_port':self.gateway_port}


def render_config(instance,*,authorize_url,token_url,live_enabled=True):
    conf=instance.config_dir
    data={'database':str(instance.state_dir/'archive.sqlite'),'public_url':instance.public_url,
          'issuer':instance.issuer,'owner_subject':instance.subject,'jwks_url':instance.effective_jwks_url,
          'webhook_secret_file':str(conf/'webhook.key'),'encryption_key_file':str(conf/'encryption.key'),
          'waha_key_file':str(conf/'waha.key'),'waha_url':f'http://127.0.0.1:{instance.gateway_port}',
          'session':'default','listen_port':instance.bridge_port,
          'profile_name':'WhatsApp' if instance.slug=='personal' else 'WhatsApp · '+instance.display_name,
          'live_account_enabled':live_enabled,'send_enabled':live_enabled,'allow_all_destinations':live_enabled,'account_actions_enabled':live_enabled,
          'oauth_client_ids':[instance.chatgpt_client],
          'oauth_consent_scopes':list(MCP_SCOPES) if live_enabled else [],
          'callback_hosts':['connectors.api.openai.com'],
          'allowed_hosts':[instance.hostname,f'127.0.0.1:{instance.bridge_port}',f'10.0.2.2:{instance.bridge_port}'],
          'subscription_ttl':86400,'poll_seconds':60,'max_attachment_bytes':536870912,
          'media_cache_bytes':4294967296,'media_ttl_seconds':3600,
          'media_gateway_origin':f'http://10.0.2.2:{instance.bridge_port}',
          'link_enabled':live_enabled,'link_client_id':instance.link_client,
          'link_authorize_url':authorize_url,'link_token_url':token_url}
    return '[bridge]\n'+'\n'.join(k+' = '+json.dumps(v,ensure_ascii=False) for k,v in data.items())+'\n'


def idp_candidate(config,users,instance,identity,*,required_mcp_scopes=()):
    """Add/reconcile this managed identity/clients; preserve unrelated registrations."""
    cfg,usr=copy.deepcopy(config),copy.deepcopy(users)
    oidc=cfg['identity_providers']['oidc']
    if any(scope not in MCP_SCOPES for scope in required_mcp_scopes):
        raise ValueError('Unsupported required MCP scope')
    policy={'default_policy':'deny','rules':[{'policy':'two_factor','subject':[['user:'+instance.username]]}]}
    old_policy=oidc['authorization_policies'].get(instance.policy)
    if old_policy is not None and old_policy!=policy:
        raise ValueError('Existing authorization policy differs; reconcile the exact owner and two-factor MFA policy before activation')
    oidc['authorization_policies'][instance.policy]=policy
    if instance.username not in usr['users']:
        if not identity or identity['username']!=instance.username or identity['subject']!=instance.subject:
            raise ValueError('Missing matching managed identity')
        usr['users'][instance.username]={'disabled':False,'displayname':instance.display_name,
                                      'password':identity['password_hash'],'groups':[instance.base]}
    elif instance.slug!='personal' and (not identity or usr['users'][instance.username]['password']!=identity['password_hash']):
        raise ValueError('Refuse to adopt or overwrite an existing unrelated user')
    oidc['scopes'].setdefault('whatsapp:link',{'claims':[]})
    registered_mcp=any(client.get('client_id')==instance.chatgpt_client for client in oidc['clients'])
    for scope in (required_mcp_scopes if registered_mcp else MCP_SCOPES):
        oidc['scopes'].setdefault(scope,{'claims':[]})
    basic={'public':True,'authorization_policy':instance.policy,'consent_mode':'explicit',
           'audience':[instance.public_url],'response_types':['code'],'response_modes':['query'],
           'require_pkce':True,'pkce_challenge_method':'S256','access_token_signed_response_alg':'RS256',
           'token_endpoint_auth_method':'none'}
    wanted=[{**basic,'client_id':instance.chatgpt_client,'client_name':'WhatsApp · '+instance.display_name+' · ChatGPT',
             'redirect_uris':[instance.chatgpt_callback],
             'scopes':[*CHATGPT_OIDC_SCOPES,'whatsapp:read','whatsapp:events','whatsapp:send'],
             'grant_types':['authorization_code','refresh_token']},
            {**basic,'client_id':instance.link_client,'client_name':'WhatsApp · '+instance.display_name+' · Connection',
             'redirect_uris':[instance.public_url+'/connect/callback'],
             'scopes':['openid','profile','whatsapp:link'],'grant_types':['authorization_code']}]
    for client in wanted:
        previous=next((c for c in oidc['clients'] if c['client_id']==client['client_id']),None)
        if previous is None: oidc['clients'].append(client)
        else:
            for field in ('audience','authorization_policy','public','require_pkce','pkce_challenge_method','token_endpoint_auth_method',
                          'consent_mode','access_token_signed_response_alg'):
                if previous.get(field)!=client[field]: raise ValueError('Existing OAuth client security settings differ')
            redirects=previous.get('redirect_uris')
            if not isinstance(redirects,list) or any(not isinstance(uri,str) for uri in redirects):
                raise ValueError('Existing OAuth client redirect_uris are invalid; review the registered callbacks')
            # Reconcile only the known bootstrap placeholder; retain valid extra callbacks.
            legacy=instance.public_url+'/oauth/setup-callback'
            if instance.slug=='personal' and client['client_id']==instance.chatgpt_client and legacy in redirects:
                redirects=list(dict.fromkeys(instance.chatgpt_callback if uri==legacy else uri for uri in redirects))
                previous['redirect_uris']=redirects
            if not set(client['redirect_uris']).issubset(redirects):
                raise ValueError('Existing OAuth client redirect_uris differ; reconcile the exact registered callbacks before continuing')
            if client['client_id']==instance.chatgpt_client:
                scopes=previous.get('scopes')
                if not isinstance(scopes,list) or not scopes or any(not isinstance(scope,str) or not scope for scope in scopes):
                    raise ValueError('Existing OAuth client scopes are invalid; review the registered scopes')
                # Older managed clients omitted email. Repair only that omission;
                # retain deliberate permissions and keep the link client separate.
                if 'email' not in scopes: scopes.append('email')
                # Only an explicit capability selection may expand existing
                # MCP registration; never infer consent from a runtime restart.
                for scope in required_mcp_scopes:
                    if scope not in scopes: scopes.append(scope)
    return cfg,usr


def _render_template(original,replacements):
    """Replace only template tokens, without interpreting inserted values again."""
    pattern='|'.join(re.escape(token) for token in sorted(replacements,key=len,reverse=True))
    return re.sub(pattern,lambda match:replacements[match.group()],original)


def render_bridge_unit(instance,*,template_root=None):
    original=((template_root or instance.project_root/'deploy')/'whatsapp-personal.service').read_text()
    replacements={
        'User=whatsappbridge':'User='+instance.service_user,
        'Group=whatsappbridge':'Group='+instance.service_user,
        '/etc/whatsapp-personal/config.toml':(instance.config_dir/'config.toml').as_posix(),
        'StateDirectory=whatsapp-personal':'StateDirectory='+instance.base,
    }
    if not instance._installation_identity.compatibility:
        replacements['/srv/openai-codex/projects/whatsapp-personal']=instance.project_root.as_posix()
        # General provisioning creates these exact account-owned data leaves.
        # StateDirectory would force an unrelated /var/lib/<unit> location.
        original=re.sub(r'^StateDirectory=.*\n|^StateDirectoryMode=.*\n','',original,flags=re.M)
        replacements['ProtectSystem=strict']='ProtectSystem=strict\nReadWritePaths='+instance.state_dir.as_posix()
    return _render_template(original,replacements)


def render_quadlet(instance,*,template_root=None):
    templates=template_root or instance.project_root/'deploy'
    original=(templates/'whatsapp-waha.container').read_text()
    image=json.loads((templates/'images.lock.json').read_text())['waha_image']
    if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}',image): raise ValueError('Invalid pinned WAHA image')
    replacements={
        '/var/lib/whatsapp-personal-waha':instance.gateway_home.as_posix(),
        '127.0.0.1:8821':'127.0.0.1:'+str(instance.gateway_port),
        '10.0.2.2:8820':'10.0.2.2:'+str(instance.bridge_port),
    }
    replacements.update({line:'Image='+image for line in re.findall(r'^Image=.*$',original,flags=re.M)})
    if not instance._installation_identity.compatibility:
        original=re.sub(r'^# Bound CPU discovery.*\n|^CPUAffinity=.*\n','',original,flags=re.M)
    return _render_template(original,replacements)


def render_apache(instance,*,template_root=None):
    original=((template_root or instance.project_root/'deploy')/'apache-whatsapp.conf.in').read_text()
    return _render_template(original,{
        '__DOMAIN__':instance.hostname,
        '127.0.0.1:8820':'127.0.0.1:'+str(instance.bridge_port),
        'whatsapp-personal-error.log':instance.base+'-error.log',
        'whatsapp-personal-access.log':instance.base+'-access.log',
    })


def deployment_artifacts(instance,*,template_root=None):
    """Read and render every required template before an administrator mutates state."""
    return {'bridge':render_bridge_unit(instance,template_root=template_root),'gateway':render_quadlet(instance,template_root=template_root),'apache':render_apache(instance,template_root=template_root)}

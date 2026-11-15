"""Export a portable per-user plugin without credentials or another account's app ID."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import zipfile

from sally_whatsapp.tenancy import Instance, ROOT

_spec = importlib.util.spec_from_file_location('export_skills', Path(__file__).with_name('plugin_skills.py'))
_skills = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_skills)


def export(instance, output, source):
    template=source/'plugin'
    manifest=json.loads((template/'plugin.json').read_text(encoding='utf-8'))
    manifest['name']=instance.base
    manifest['extensions']['com.openai']['interface']['displayName']='WhatsApp'
    mcp={'$schema':'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
         'mcpServers':{instance.base:{'type':'streamable-http','url':instance.public_url+'/mcp'}}}
    details=instance.public_details()
    guide='\n'.join([
        '# WhatsApp - '+instance.display_name,'',
        'Portable package for this account. Contains no credentials or app registrations belonging to other accounts.',
        'Create the MCP connection in your own ChatGPT account using public OAuth/PKCE and the following settings.',
        'The package does not prove that the connection is already installed in ChatGPT.',
        'This export bundles remote MCP server configuration: a personal ChatGPT upload may make it available only on desktop.',
        'For ChatGPT web, register the MCP connection in your own account first, then build the web variant with .app.json referencing that registration and no mcp.json. Do not copy .app.json from another user.','',
        *[f'- {key}: {details[key]}' for key in ('username','pairing_url','mcp_url','oauth_client_id','oauth_issuer','oauth_client_auth_method','callback')],
        '', 'The OAuth client is public: leave the client secret empty.',
        ('Sign in with your OIDC provider credentials; setup does not create or supply passwords.'
         if instance.auth_mode=='external-oidc' else 'The service password is provided separately.'),
        'Open the connection page with your own account, then approve the code or QR on your own phone.',
        'An existing session for another user is rejected: use your own browser profile or sign out of the identity portal.',''])
    files={'plugin.json':json.dumps(manifest,ensure_ascii=False,indent=2).encode(),
           'mcp.json':json.dumps(mcp,indent=2).encode(),
           'assets/whatsapp-gpt.png':(template/'assets/whatsapp-gpt.png').read_bytes(),
           'CONFIGURATION.md':guide.encode()}
    for notice in ('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md'):
        selected = source/notice
        if selected.is_symlink() or not selected.is_file():
            raise ValueError('License notices must be regular source files')
        files[notice] = selected.read_bytes()
    files.update(_skills.collect(template,instance.public_url+'/connect',allow_legacy=True))
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'x',zipfile.ZIP_DEFLATED) as archive:
        for name,body in files.items(): archive.writestr(name,body)
    return {'user':instance.slug,'file':str(output),'credentials_included':False,'chatgpt_installation_required':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if os.geteuid()!=0: raise SystemExit('Run as the authorized server administrator')
    os.umask(0o077)
    registry=json.loads((ROOT/'private/tenants.json').read_text())['instances']
    if args.user not in registry: raise SystemExit('Unknown managed user')
    print(json.dumps(export(Instance(**registry[args.user]['spec']),args.output,ROOT)))


if __name__=='__main__': main()

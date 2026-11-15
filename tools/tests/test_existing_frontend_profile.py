"""General multisite inventory on real temporary files; commands stay mocked."""
import copy

import pytest

import test_fresh_frontend_profile as fixture
from test_fresh_frontend_profile import prepared

existing=fixture.load('existing_frontend_tests','host/frontend/existing_profile.py')


def inputs(prepared):
    root,config,generation,_=prepared
    baseline=fixture.compile_profile(prepared)
    registry=copy.deepcopy(baseline['registry']);profile=copy.deepcopy(baseline['profile'])
    registry['legacy_hooks']={};registry['artifacts']={};registry['links']={};registry['directories']={};registry['host_files']=[]
    site='/etc/apache2/sites-enabled/shop.conf'
    hook='/etc/letsencrypt/renewal-hooks/deploy/vendor-app'
    bodies={fixture.fresh.MAIN:baseline['pinned_artifacts'][fixture.fresh.MAIN],
            site:b'<VirtualHost *:80>\nServerName shop.other.example\n</VirtualHost>\n',
            hook:b'#!/bin/sh\n# Synthetic foreign application hook.\nexit 0\n'}
    for name,body in bodies.items():
        fixture.put(root,name,body,0o700 if name==hook else 0o644)
        registry['artifacts'][name]={**root.snapshot(name),'retention':'retain'}
        registry['host_files'].append(name)
    profile['config_files'].append(site)
    profile['includes'][0]['targets']=[site]
    value={'format':1,'registry':registry,'profile':profile,
           'hook_inventory':{'deploy':['vendor-app'],'post':[]},
           'python':{'path':'/usr/bin/python3.13','sha256':root.snapshot('/usr/bin/python3.13')['sha256']}}
    return value,bodies


def test_existing_multisite_adds_only_neutral_hooks_and_preserves_foreign_bytes(prepared):
    root,_,generation,_=prepared
    value,bodies=inputs(prepared)
    result=existing.build(root,value,provider=fixture.provider,adapter=fixture.adapter,engine=fixture.engine,generation=generation)
    assert result['foreign_artifacts_preserved'] and result['runtime_verified'] is False
    assert all(root.read_bytes(name)==body for name,body in bodies.items())
    assert fixture.publish(root,result,fixture.Commands())['phase']=='complete'
    assert all(root.read_bytes(name)==body for name,body in bodies.items())
    assert root.link(existing.HOOKS['deploy'])['target'].endswith('/deploy-hook')


@pytest.mark.parametrize('fault',['unlisted-include','changed-source','unlisted-hook','hook-collision',
                                 'python-writable','python-not-executable'])
def test_incomplete_or_changed_foreign_inventory_stops_before_publication(prepared,fault):
    root,_,generation,_=prepared
    value,bodies=inputs(prepared)
    if fault=='unlisted-include':fixture.put(root,'/etc/apache2/sites-enabled/unlisted.conf',b'# unlisted\n')
    elif fault=='changed-source':fixture.put(root,'/etc/apache2/sites-enabled/shop.conf',b'# replaced\n')
    elif fault=='unlisted-hook':fixture.put(root,'/etc/letsencrypt/renewal-hooks/deploy/unlisted',b'# unlisted\n')
    elif fault=='hook-collision':fixture.put(root,existing.HOOKS['post'],b'# occupied\n')
    else:(root.base/value['python']['path'].lstrip('/')).chmod(0o777 if fault=='python-writable' else 0o644)
    with pytest.raises(ValueError):
        existing.build(root,value,provider=fixture.provider,adapter=fixture.adapter,engine=fixture.engine,generation=generation)
    assert root.snapshot(fixture.provider.REGISTRY) is None


def test_general_host_bundle_has_no_pro8_observation_dependency(tmp_path):
    output=tmp_path/'general'
    metadata=fixture.builder.build(fixture.REPOSITORY,output,source_revision='a'*40,profile='general')
    assert metadata['profile']=='general'
    assert all('pro8' not in name for name in metadata['source_hashes'])
    assert metadata['entrypoints']['frontend_profile'].endswith('/host/frontend/existing_profile.py')
    loaded=fixture.installer.load_bundle(output,fixture.builder.sha(fixture.builder.encoded(metadata)))
    assert loaded['manifest']['files']


def test_existing_relative_site_link_is_preserved(prepared):
    root,_,generation,_=prepared
    value,bodies=inputs(prepared)
    enabled='/etc/apache2/sites-enabled/shop.conf'
    available='/etc/apache2/sites-available/shop.conf'
    fixture.put(root,available,bodies[enabled])
    selected=root.base/enabled.lstrip('/')
    selected.unlink()
    selected.symlink_to('../sites-available/shop.conf')
    value['registry']['artifacts'].pop(enabled)
    value['registry']['artifacts'][available]={**root.snapshot(available),'retention':'retain'}
    value['registry']['links'][enabled]={**root.link(enabled),'retention':'retain'}
    value['registry']['host_files'].append(available)
    value['profile']['config_files'].remove(enabled)
    value['profile']['config_files'].append(available)
    result=existing.build(root,value,provider=fixture.provider,adapter=fixture.adapter,
                          engine=fixture.engine,generation=generation)
    assert result['before']['links'][enabled]==value['registry']['links'][enabled]
    assert fixture.publish(root,result,fixture.Commands())['phase']=='complete'
    assert root.link(enabled)=={key:val for key,val in value['registry']['links'][enabled].items()
                               if key!='retention'}
    assert root.read_bytes(available)==bodies[enabled]


def test_existing_package_is_exclusive_pinned_and_has_no_service_effects(prepared):
    root,_,generation,_=prepared
    value,_=inputs(prepared)
    built=existing.build(root,value,provider=fixture.provider,adapter=fixture.adapter,
                         engine=fixture.engine,generation=generation)
    receipt=existing.write_package(root,'/etc/existing-review',built)
    assert receipt['activated'] is False and receipt['private_material_read'] is False
    for name,digest in receipt['files'].items():
        assert existing.sha(root.read_bytes('/etc/existing-review/'+name))==digest
    assert root.snapshot(fixture.provider.REGISTRY) is None
    assert root.link(existing.HOOKS['deploy']) is None
    with pytest.raises(ValueError):existing.write_package(root,'/etc/existing-review',built)
    (root.base/'etc/output-alias').symlink_to(root.base/'etc',target_is_directory=True)
    with pytest.raises(ValueError):existing.write_package(root,'/etc/output-alias/rejected',built)
    assert not (root.base/'etc/rejected').exists()


def test_neutral_existing_frontend_needs_neither_application_identity(prepared,monkeypatch):
    root,_,generation,_=prepared
    value,bodies=inputs(prepared)
    def forbidden():raise AssertionError('An application identity was consulted')
    monkeypatch.setattr(fixture.installation,'active',forbidden)
    import builtins
    original=builtins.__import__
    def guarded(name,*args,**kwargs):
        if name in ('host.installation','installation_layout') or name.startswith('sally_whatsapp'):
            raise AssertionError('Neutral frontend imported application configuration: '+name)
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',guarded)
    result=existing.build(root,value,provider=fixture.provider,adapter=fixture.adapter,
                          engine=fixture.engine,generation=generation)
    assert fixture.publish(root,result,fixture.Commands())['phase']=='complete'
    assert all(root.read_bytes(name)==body for name,body in bodies.items())
    for product in ('whatsapp','box'):
        assert root.snapshot('/etc/'+product+'-installation.json') is None
        assert root.snapshot('/etc/'+product+'-installation-identity.json') is None


def test_occupied_historical_hooks_are_preserved_and_new_registrations_are_distinct(prepared):
    root,_,generation,_=prepared
    value,bodies=inputs(prepared)
    for event,name in [('deploy','50-develative-services'),('post','90-develative-services')]:
        path='/etc/letsencrypt/renewal-hooks/'+event+'/'+name
        body=b'#!/bin/sh\n# Synthetic historical mail/Webmin hook; never executed.\nexit 0\n'
        fixture.put(root,path,body,0o700)
        bodies[path]=body
        value['registry']['artifacts'][path]={**root.snapshot(path),'retention':'retain'}
        value['registry']['host_files'].append(path)
        value['hook_inventory'][event].append(name)
        value['hook_inventory'][event].sort()
    result=existing.build(root,value,provider=fixture.provider,adapter=fixture.adapter,
                          engine=fixture.engine,generation=generation)
    commands=fixture.Commands()
    assert fixture.publish(root,result,commands)['phase']=='complete'
    assert all(root.read_bytes(name)==body for name,body in bodies.items())
    assert all('50-develative-services' not in ' '.join(call) and '90-develative-services' not in ' '.join(call)
               for call in commands.calls)
    assert root.link('/etc/letsencrypt/renewal-hooks/deploy/60-develative-host-frontend')
    assert root.link('/etc/letsencrypt/renewal-hooks/post/95-develative-host-frontend')

"""Release safety and real temporary-file rollback with simulated services."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import github_release_common as common
import github_release as release


@pytest.fixture
def health_response(tmp_path,monkeypatch):
    config=tmp_path/'config.toml'
    config.write_text('[bridge]\npublic_url="https://synthetic.example.invalid"\nissuer="https://issuer.invalid"\n')
    (tmp_path/'waha.key').write_text('synthetic-key')
    instance={'slug':'synthetic','unit':'synthetic.service','port':8820,'config':config}
    payload={'process':'running','version':'0.3.4'}
    calls=[]
    def get_json(url,headers=None):
        calls.append(url)
        if url.endswith('/healthz'):return payload.copy()
        if url.endswith('/.well-known/oauth-protected-resource'):
            return {'resource':'https://synthetic.example.invalid','authorization_servers':['https://issuer.invalid']}
        assert url.endswith('/api/sessions/default')
        return {'status':'WORKING'}
    def challenge(request,**kwargs):
        raise urllib.error.HTTPError(request.full_url,401,'synthetic',{},None)
    monkeypatch.setattr(release,'active',lambda unit:True)
    monkeypatch.setattr(release,'get_json',get_json)
    monkeypatch.setattr(release.urllib.request,'urlopen',challenge)
    return instance,payload,calls


def ready_payload():
    return {'state':'ready','ready':True,
            'workers':{name:True for name in ('events','transfers','history','actions','portal')}}


def test_health_legacy_liveness_does_not_require_readiness(health_response):
    instance,payload,calls=health_response
    assert release.health(instance,'0.3.4')=='WORKING'
    with pytest.raises(common.ReleaseError,match='application readiness'):
        release.health(instance,'0.3.4',require_ready=True)


@pytest.mark.parametrize('readiness',[None,False,[],{},'ready',
    {'state':'ready','ready':1},{'state':'ready','ready':'true'},
    {'state':'failed','ready':True},{'state':'waiting','ready':False},
    {'state':'ready','ready':True},{'state':'ready','ready':True,'workers':[]},
    {'state':'ready','ready':True,'workers':{}}])
def test_candidate_health_rejects_missing_or_malformed_readiness(health_response,readiness):
    instance,payload,calls=health_response;payload['readiness']=readiness
    with pytest.raises(common.ReleaseError,match='readiness|workers'):
        release.health(instance,'0.3.4',require_ready=True)


@pytest.mark.parametrize('worker',['events','transfers','history','actions','portal'])
@pytest.mark.parametrize('value',[False,1,'true',None])
def test_candidate_health_requires_every_worker_true(health_response,worker,value):
    instance,payload,calls=health_response;payload['readiness']=ready_payload()
    payload['readiness']['workers'][worker]=value
    with pytest.raises(common.ReleaseError,match='workers'):
        release.health(instance,'0.3.4',require_ready=True)


@pytest.mark.parametrize('portal',[True,False])
def test_candidate_health_accepts_ready_workers_with_optional_portal(health_response,portal):
    instance,payload,calls=health_response;payload['readiness']=ready_payload()
    if not portal:payload['readiness']['workers'].pop('portal')
    assert release.health(instance,'0.3.4',require_ready=True)=='WORKING'


def test_wait_health_checks_both_instances_and_bounds_failed_attempts(monkeypatch):
    calls=[];sleeps=[]
    def health(instance,version,**kwargs):
        assert kwargs=={'maintenance':False,'require_ready':True}
        calls.append(instance['slug'])
        if instance['slug']=='second':raise common.ReleaseError('required worker unavailable')
        return 'WORKING'
    monkeypatch.setattr(release,'health',health)
    monkeypatch.setattr(release.time,'sleep',sleeps.append)
    with pytest.raises(common.ReleaseError,match='worker unavailable'):
        release.wait_health([{'slug':'first'},{'slug':'second'}],'0.3.4',
                            {'first':'WORKING','second':'WORKING'},require_ready=True)
    assert calls==['first','second']*30 and sleeps==[2]*29


def test_wait_health_allows_delayed_readiness_beyond_repair_retry_budget(monkeypatch):
    elapsed=0
    def sleep(seconds):
        nonlocal elapsed
        elapsed+=seconds
    def health(instance,version,**kwargs):
        assert kwargs['require_ready'] is True
        if elapsed<32:raise common.ReleaseError('still preparing')
        return 'WORKING'
    monkeypatch.setattr(release,'health',health);monkeypatch.setattr(release.time,'sleep',sleep)
    assert release.wait_health([{'slug':'first'}],'0.3.4',{'first':'WORKING'},require_ready=True)=={'first':'WORKING'}
    assert elapsed==32


class Gates(unittest.TestCase):
    def test_filesystem_probe_uses_every_service_account_before_activation(self):
        candidate = Path('/synthetic/release')
        instances = [{'unit': 'first.service'}, {'unit': 'suspended.service'}]
        def run(command):
            if command[0] == 'systemctl':
                return 'first-user' if command[2] == 'first.service' else 'second-user'
            return ''
        with patch.object(release, 'prepare_gate_directory') as prepare, \
             patch.object(release, 'run', side_effect=run) as calls:
            release.verify_service_access(candidate, instances)
        prepare.assert_called_once_with()
        probes = [call.args[0] for call in calls.call_args_list if call.args[0][0] == 'runuser']
        self.assertEqual([command[2] for command in probes], ['first-user', 'second-user'])
        self.assertTrue(all(command[-2:] == [str(release.GATE), str(candidate)] for command in probes))
        self.assertFalse(any('start' in call.args[0] or 'stop' in call.args[0] for call in calls.call_args_list))

    def test_filesystem_probe_failure_blocks_publication(self):
        with patch.object(release, 'prepare_gate_directory'), \
             patch.object(release, 'run', side_effect=['service-user', common.ReleaseError('Permission denied')]):
            with self.assertRaisesRegex(common.ReleaseError, 'Permission denied'):
                release.verify_service_access(Path('/synthetic/release'), [{'unit': 'bridge.service'}])

    def test_filesystem_probe_cannot_pass_by_using_root(self):
        for account in ['', 'root', '0']:
            with self.subTest(account=account), patch.object(release, 'prepare_gate_directory'), \
                 patch.object(release, 'run', return_value=account) as run:
                with self.assertRaises(common.ReleaseError):
                    release.verify_service_access(Path('/synthetic/release'), [{'unit': 'bridge.service'}])
                self.assertEqual(run.call_count, 1)

    def test_only_whatsapp_tags_route_to_main(self):
        self.assertEqual(common.route('whatsapp', 'whatsapp/v0.3.2')['branch'], 'main')
        for tag in ['v0.3.2', 'box/v1.4.8', 'whatsapp/v0.3.2-beta.1', 'whatsapp/v0.3.2;id']:
            with self.subTest(tag=tag), self.assertRaises(common.ReleaseError):
                common.route('whatsapp', tag)

    def test_pr_success_does_not_replace_branch_ci(self):
        run = {'id': 1, 'head_sha': 'a'*40, 'head_branch': 'main', 'event': 'pull_request',
               'status': 'completed', 'conclusion': 'success'}
        with self.assertRaises(common.ReleaseError):
            common.select_ci_run([run], 'a'*40, 'main')

    def test_unknown_request_fields_fail_before_network(self):
        with self.assertRaises(common.ReleaseError):
            common.verify_request(None, 'whatsapp', {'tag': 'whatsapp/v0.3.2', 'command': 'id'})


if __name__ == '__main__':
    unittest.main()


@pytest.mark.parametrize('dry_run', [False, True])
def test_pinned_manual_request_rechecks_release_id_sha_and_ci(monkeypatch, dry_run):
    commit = 'a'*40
    request = {'tag': 'whatsapp/v0.5.0', 'release_id': 42,
               'expected_commit': commit, 'dry_run': dry_run}
    class API:
        release_id = 42
        sha = commit
        draft = False
        def get(self, path):
            if path == '/releases/42':
                return {'id': self.release_id, 'tag_name': request['tag'], 'draft': self.draft,
                        'published_at': '2026-10-19T12:00:00Z', 'prerelease': False}
            if path.startswith('/commits/'):
                return {'sha': self.sha}
            return {'status': 'ahead'}
    api = API()
    with patch.object(common, 'verify_ci', return_value=['exact-main-ci']) as ci:
        target = common.verify_request(api, 'whatsapp', request)
        assert target['commit'] == commit and target['githubReleaseId'] == 42
        ci.assert_called_once_with(api, 'whatsapp', commit, target)
        api.sha = 'b'*40
        with pytest.raises(common.ReleaseError, match='selected commit'):
            common.verify_request(api, 'whatsapp', request)
        api.sha = commit
        api.release_id = 43
        with pytest.raises(common.ReleaseError, match='Release ID'):
            common.verify_request(api, 'whatsapp', request)
        api.release_id = 42
        api.draft = True
        with pytest.raises(common.ReleaseError, match='published'):
            common.verify_request(api, 'whatsapp', request)


def test_unpinned_whatsapp_activation_fails_before_network():
    with pytest.raises(common.ReleaseError, match='expected commit'):
        common.verify_request(None, 'whatsapp', {'tag': 'whatsapp/v0.5.0', 'release_id': 42})


def test_legacy_branch_preview_stays_compatible(monkeypatch):
    class API:
        def get(self, path):
            return {'sha': 'a'*40} if path.startswith('/commits/') else {'status': 'identical'}
    monkeypatch.setattr(common, 'verify_ci', lambda *args: [])
    target = common.verify_request(API(), 'whatsapp',
                                  {'tag': 'whatsapp/v0.5.0', 'dry_run': True, 'preview_ref': 'main'})
    assert target['githubReleaseId'] == 0 and target['sourceReference'] == 'main'


@pytest.mark.parametrize('expected', ['', 'main', 'A'*40, True, 123])
def test_invalid_expected_commit_fails_before_network(expected):
    with pytest.raises(common.ReleaseError, match='expected commit'):
        common.verify_request(None, 'whatsapp', {'tag': 'whatsapp/v0.5.0',
                              'release_id': 42, 'expected_commit': expected})


def test_pinned_request_does_not_bypass_failed_ci(monkeypatch):
    class API:
        def get(self, path):
            if path.startswith('/releases/'):
                return {'id': 42, 'tag_name': 'whatsapp/v0.5.0', 'draft': False,
                        'published_at': '2026-10-19T12:00:00Z', 'prerelease': False}
            return {'sha': 'a'*40} if path.startswith('/commits/') else {'status': 'identical'}
    def failed_ci(*args):
        raise common.ReleaseError('Latest CI did not succeed')
    monkeypatch.setattr(common, 'verify_ci', failed_ci)
    with pytest.raises(common.ReleaseError, match='CI did not succeed'):
        common.verify_request(API(), 'whatsapp', {'tag': 'whatsapp/v0.5.0',
                              'release_id': 42, 'expected_commit': 'a'*40})

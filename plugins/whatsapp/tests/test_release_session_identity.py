"""Release health must observe the configured session, with no real provider I/O."""
import json
import urllib.parse

import pytest

from test_github_release import health_response
import github_release as release
from github_release_common import ReleaseError


@pytest.mark.parametrize('name', ['another-session', 'session/with separator', 'session-è'])
def test_release_health_observes_exact_configured_session(health_response, monkeypatch, name):
    instance, payload, calls = health_response
    with instance['config'].open('a') as stream:
        stream.write('session = ' + json.dumps(name) + '\n')
    previous = release.get_json
    expected = '/api/sessions/' + urllib.parse.quote(name, safe='')
    observed = []

    def response(url, headers=None):
        if '/api/sessions/' in url:
            observed.append(url)
            assert url.endswith(expected)
            assert headers == {'X-Api-Key': 'synthetic-key'}
            return {'name': name, 'status': 'WORKING'}
        return previous(url, headers)

    monkeypatch.setattr(release, 'get_json', response)
    assert release.health(instance, '0.3.4') == 'WORKING'
    assert len(observed) == 1


@pytest.mark.parametrize('response', [None, [], {'name': 'foreign', 'status': 'WORKING'}])
def test_release_health_cannot_admit_another_session(health_response, monkeypatch, response):
    instance, _, _ = health_response
    previous = release.get_json
    monkeypatch.setattr(release, 'get_json', lambda url, headers=None:
        response if '/api/sessions/' in url else previous(url, headers))
    with pytest.raises(ReleaseError, match='gateway session status'):
        release.health(instance, '0.3.4')


@pytest.mark.parametrize('name', ['', 12, 'bad\nname'])
def test_release_health_rejects_invalid_session_without_provider_request(health_response, name):
    instance, _, calls = health_response
    with instance['config'].open('a') as stream:
        stream.write('session = ' + json.dumps(name) + '\n')
    with pytest.raises(ReleaseError, match='session identity'):
        release.health(instance, '0.3.4')
    assert not any('/api/sessions/' in url for url in calls)

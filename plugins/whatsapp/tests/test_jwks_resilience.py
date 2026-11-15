"""JWKS failure/rotation regressions: real PyJWT, synthetic keys, no network."""
import io
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event
from types import SimpleNamespace
from urllib.error import URLError

import jwt
import jwt.api_jwk
import jwt.jwk_set_cache
import jwt.jwks_client
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from sally_whatsapp import auth


@pytest.fixture
def jwks_case(environment, monkeypatch):
    settings = replace(environment[0], public_key_file=None, jwks_url='https://issuer.example/jwks')
    clock = SimpleNamespace(now=1000.0)
    clock.monotonic = lambda: clock.now
    for module in (auth, jwt.api_jwk, jwt.jwk_set_cache, jwt.jwks_client):
        # Replace only these module references; real thread deadlines keep working.
        monkeypatch.setattr(module, 'time', clock, raising=False)
    keys = {name: rsa.generate_private_key(public_exponent=65537, key_size=2048)
            for name in ('old', 'new')}

    def keyset(*names):
        result = []
        for name in names:
            value = jwt.algorithms.RSAAlgorithm.to_jwk(keys[name].public_key(), as_dict=True)
            result.append({**value, 'kid': name, 'use': 'sig', 'alg': 'RS256'})
        return json.dumps({'keys': result}).encode()

    def token(kid='old', *, signing_key='old', **changes):
        claims = {'iss': settings.issuer, 'aud': settings.public_url,
                  'sub': settings.owner_subject, 'azp': settings.oauth_client_ids[0],
                  'iat': int(time.time()), 'exp': int(time.time()) + 3600,
                  'scope': 'whatsapp:read whatsapp:events whatsapp:send'}
        claims.update(changes)
        return jwt.encode(claims, keys[signing_key], algorithm='RS256', headers={'kid': kid})

    class Endpoint:
        def __init__(self):
            self.body = keyset('old')
            self.error = None
            self.calls = 0
            self.entered = Event()
            self.release = Event()
            self.block = False

        def open(self, request, timeout):
            assert request.full_url == settings.jwks_url
            assert timeout == 5
            self.calls += 1
            if self.block:
                self.entered.set()
                assert self.release.wait(3), 'Synthetic fetch was not released'
            if self.error:
                raise self.error
            return io.BytesIO(self.body)

    endpoint = Endpoint()
    monkeypatch.setattr(jwt.jwks_client.urllib.request, 'build_opener', lambda *args: endpoint)
    return SimpleNamespace(settings=settings, clock=clock, endpoint=endpoint, token=token,
                           keyset=keyset, verifier=auth.JWTVerifier(settings))


def test_failed_unknown_key_refresh_has_backoff_without_losing_fresh_cache(jwks_case):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    case.clock.now += 31
    case.endpoint.error = URLError('synthetic outage')
    for _ in range(4):
        assert case.verifier._verify(case.token('unknown')) is None
    assert case.endpoint.calls == 2  # one warmup, one failed fetch
    assert case.verifier._verify(case.token()) is not None
    case.clock.now += 30
    assert case.verifier._verify(case.token('unknown')) is None
    assert case.endpoint.calls == 3


def test_known_fresh_key_does_not_wait_for_unknown_key_network_failure(jwks_case):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    case.clock.now += 31
    case.endpoint.error = URLError('synthetic outage')
    case.endpoint.block = True
    with ThreadPoolExecutor(max_workers=2) as executor:
        unknown = executor.submit(case.verifier._verify, case.token('unknown'))
        try:
            assert case.endpoint.entered.wait(1)
            known = executor.submit(case.verifier._verify, case.token())
            assert known.result(timeout=.5) is not None
            assert not unknown.done()  # the fake network call is still blocked
        finally:
            case.endpoint.release.set()
        assert unknown.result(timeout=1) is None
    assert case.endpoint.calls == 2


def test_healthy_unknown_keys_keep_existing_success_cooldown(jwks_case):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    for index in range(4):
        assert case.verifier._verify(case.token(f'unknown-{index}')) is None
    assert case.endpoint.calls == 1
    case.clock.now += 31
    assert case.verifier._verify(case.token('unknown')) is None
    assert case.endpoint.calls == 2
    assert case.verifier._verify(case.token('another-unknown')) is None
    assert case.endpoint.calls == 2


def test_expired_keys_are_not_used_during_outage_or_failure_backoff(jwks_case):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    case.clock.now += 290
    case.endpoint.error = URLError('synthetic outage')
    assert case.verifier._verify(case.token('unknown')) is None
    assert case.endpoint.calls == 2
    assert case.verifier._verify(case.token()) is not None
    case.clock.now += 11  # cache TTL ends before the failure backoff
    assert case.verifier._verify(case.token()) is None
    assert case.endpoint.calls == 2
    case.clock.now += 20
    assert case.verifier._verify(case.token()) is None
    assert case.endpoint.calls == 3
    case.clock.now += 30
    case.endpoint.error = None
    assert case.verifier._verify(case.token()) is not None
    assert case.endpoint.calls == 4


def test_rotation_and_key_removal_replace_cache_without_indefinite_key_cache(jwks_case):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    case.endpoint.body = case.keyset('new')
    assert case.verifier._verify(case.token('new', signing_key='new')) is None
    assert case.endpoint.calls == 1  # existing successful-fetch cooldown applies
    case.clock.now += 31
    assert case.verifier._verify(case.token('new', signing_key='new')) is not None
    assert case.verifier._verify(case.token()) is None  # removed key is not cached separately
    assert case.endpoint.calls == 2


def test_ttl_expiry_refreshes_even_with_same_key_id(jwks_case):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    payload = json.loads(case.keyset('new'))
    payload['keys'][0]['kid'] = 'old'
    case.endpoint.body = json.dumps(payload).encode()
    case.clock.now += 301
    assert case.verifier._verify(case.token('old', signing_key='new')) is not None
    assert case.verifier._verify(case.token()) is None
    assert case.endpoint.calls == 2


@pytest.mark.parametrize('bad_body', [
    b'not-json', b'[]', b'{"keys":[]}', b'{"keys":[{}]}', b'[' * 10000 + b']' * 10000,
], ids=['invalid-json', 'wrong-container', 'empty-set', 'invalid-key', 'excessive-depth'])
def test_invalid_endpoint_payloads_back_off_and_never_extend_old_cache(jwks_case, bad_body):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    case.clock.now += 31
    case.endpoint.body = bad_body
    for _ in range(3):
        assert case.verifier._verify(case.token('unknown')) is None
    assert case.endpoint.calls == 2
    assert case.verifier._verify(case.token()) is not None
    case.clock.now += 270
    assert case.verifier._verify(case.token()) is None
    assert case.endpoint.calls == 3


def test_concurrent_failed_cold_fetches_are_coalesced(jwks_case):
    case = jwks_case
    case.endpoint.error = URLError('synthetic outage')
    case.endpoint.block = True
    signed = case.token()
    with ThreadPoolExecutor(max_workers=8) as executor:
        requests = [executor.submit(case.verifier._verify, signed) for _ in range(8)]
        try:
            assert case.endpoint.entered.wait(1)
        finally:
            case.endpoint.release.set()
        assert [future.result(timeout=2) for future in requests] == [None] * 8
    assert case.endpoint.calls == 1


def test_explicit_cache_invalidation_does_not_fall_back_to_cached_key(jwks_case):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    case.verifier.jwks.jwk_set_cache.put(None)
    case.endpoint.error = URLError('synthetic outage')
    assert case.verifier._verify(case.token()) is None
    assert case.endpoint.calls == 2


@pytest.mark.parametrize('changes', [
    {'iss': 'https://other.example'}, {'aud': 'https://other.example'},
    {'sub': 'other-owner'}, {'azp': 'other-client'}, {'exp': 1},
    {'scope': 'whatsapp:read', 'scp': ['whatsapp:send']},
])
def test_fresh_key_fast_path_keeps_claim_and_tenant_checks(jwks_case, changes):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    assert case.verifier._verify(case.token(**changes)) is None
    assert case.endpoint.calls == 1


def test_verifiers_do_not_share_cache_or_outage_backoff(jwks_case):
    case = jwks_case
    assert case.verifier._verify(case.token()) is not None
    other = auth.JWTVerifier(replace(case.settings, owner_subject='other-owner',
                                     oauth_client_ids=['other-client']))
    case.endpoint.body = case.keyset('new')
    other_token = case.token('new', signing_key='new', sub='other-owner', azp='other-client')
    assert other._verify(other_token) is not None
    case.clock.now += 31
    case.endpoint.error = URLError('synthetic outage')
    assert case.verifier._verify(case.token('unknown')) is None
    assert other._verify(other_token) is not None
    assert other._verify(case.token()) is None
    assert other._verify(other_token) is not None
    assert case.verifier._verify(other_token) is None
    assert case.verifier._verify(case.token()) is not None

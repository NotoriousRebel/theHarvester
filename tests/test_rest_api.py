from argparse import Namespace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from theHarvester.lib.api import api
from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.core import Core


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    api.limiter.reset()
    yield
    api.limiter.reset()


def test_query_expands_source_capability(monkeypatch) -> None:
    captured: list[tuple[Namespace, bool]] = []

    async def public_target(_target: str) -> bool:
        return True

    async def fake_start(
        args: Namespace,
        *,
        persist_completed_result: bool = False,
        include_breaches: bool = False,
    ):
        captured.append((args, persist_completed_result))
        assert include_breaches is True
        return ([], [], [], [], [], [], [], [], [], [])

    monkeypatch.setattr(api.__main__, 'start', fake_start)
    monkeypatch.setattr(api, 'is_public_target', public_target)
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')

    response = TestClient(api.app).get(
        '/query?domain=example.test&source=subdomains',
        headers={'X-API-Key': 'operator-secret'},
    )

    assert response.status_code == 200
    assert captured[0][0].source == ','.join(Core.expand_source_selection('subdomains'))
    assert captured[0][1] is True


def test_query_forwards_bounded_recursive_dns_options(monkeypatch) -> None:
    captured: list[Namespace] = []
    completed_at = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    completed = CompletedResult.finish(
        target='example.test',
        started_at=completed_at,
        completed_at=completed_at,
        groups={'dns-recursive-summary': ['{"query_count":12}']},
    )

    async def fake_start(
        args: Namespace,
        *,
        persist_completed_result: bool = False,
        include_breaches: bool = False,
        return_completed_result: bool = False,
    ):
        captured.append(args)
        assert return_completed_result is True
        return ([], [], [], [], [], [], [], [], [], [], completed)

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get(
        '/query?domain=example.test&source=certspotter&dns_recursive_depth=2'
        '&dns_recursive_query_limit=321&dns_recursive_runtime_seconds=4.5'
        '&dns_resolve=192.0.2.53,192.0.2.54,192.0.2.55',
        headers={'X-API-Key': 'operator-secret'},
    )

    assert response.status_code == 200
    assert captured[0].dns_recursive_depth == 2
    assert captured[0].dns_recursive_query_limit == 321
    assert captured[0].dns_recursive_runtime_seconds == 4.5
    assert response.json()['results'] == [
        {'type': 'dns-recursive-summary', 'value': '{"query_count":12}', 'sources': []}
    ]


def test_query_executes_every_advertised_post_collection_action(monkeypatch) -> None:
    captured: list[tuple[Namespace, bool]] = []
    completed_at = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    completed = CompletedResult.finish(
        target='example.test',
        started_at=completed_at,
        completed_at=completed_at,
        groups={'api-endpoint': ['/api/v1'], 'shodan': ['{"ip":"192.0.2.10","ports":[443]}']},
    )

    async def fake_start(
        args: Namespace,
        *,
        persist_completed_result: bool = False,
        include_breaches: bool = False,
        return_completed_result: bool = False,
    ):
        captured.append((args, return_completed_result))
        return ([], [], [], [], [], [], [], [], [], [], completed)

    async def public_target(_target: str) -> bool:
        return True

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__, 'start', fake_start)
    monkeypatch.setattr(api, 'is_public_target', public_target)

    response = TestClient(api.app).get(
        '/query?domain=example.test&source=certspotter&dns_brute=true&dns_lookup=true&shodan=true&take_over=true&api_scan=true',
        headers={'X-API-Key': 'operator-secret'},
    )

    assert response.status_code == 200
    args, return_completed_result = captured[0]
    assert (args.dns_brute, args.dns_lookup, args.shodan, args.take_over, args.api_scan) == (True, True, True, True, True)
    assert return_completed_result is True
    assert response.json()['run_id'] == str(completed.run_id)
    assert response.json()['status'] == 'complete'
    assert response.json()['results'] == [
        {'type': 'api-endpoint', 'value': '/api/v1', 'sources': []},
        {'type': 'shodan', 'value': '{"ip":"192.0.2.10","ports":[443]}', 'sources': []},
    ]


@pytest.mark.parametrize(
    'query',
    [
        'source=pentesttools',
        'source=criminalip',
        'source=certspotter&dns_brute=true',
        'source=certspotter&dns_lookup=true',
        'source=certspotter&take_over=true',
        'source=certspotter&api_scan=true',
    ],
)
def test_query_requires_operator_auth_for_p1_and_p2_work(monkeypatch, query: str) -> None:
    async def unexpected_start(*_args, **_kwargs):
        raise AssertionError('active collection must not start without operator authentication')

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get(f'/query?domain=example.test&{query}')

    assert response.status_code == 401


def test_query_rejects_a_non_public_p2_source_before_collection(monkeypatch) -> None:
    async def unexpected_start(*_args, **_kwargs):
        raise AssertionError('direct collection must not start for a non-public target')

    async def private_target(_target: str) -> bool:
        return False

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__, 'start', unexpected_start)
    monkeypatch.setattr(api, 'is_public_target', private_target)

    response = TestClient(api.app).get(
        '/query?domain=internal.example&source=criminalip',
        headers={'X-API-Key': 'operator-secret'},
    )

    assert response.status_code == 400
    assert response.json()['detail'] == 'P2 direct interaction requires a publicly routable target'


def test_dnsbrute_requires_operator_auth(monkeypatch) -> None:
    async def unexpected_start(*_args, **_kwargs):
        raise AssertionError('DNS brute force must not start without operator authentication')

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get('/dnsbrute?domain=example.test')

    assert response.status_code == 401


def test_query_requires_operator_key_for_recursive_dns(monkeypatch) -> None:
    async def unexpected_start(*_args, **_kwargs):
        raise AssertionError('enumeration must not start')

    monkeypatch.delenv('THEHARVESTER_API_KEY', raising=False)
    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get(
        '/query?domain=example.test&source=certspotter&dns_recursive_depth=1&dns_resolve=192.0.2.53,192.0.2.54,192.0.2.55'
    )

    assert response.status_code == 503
    assert response.json()['detail'] == 'THEHARVESTER_API_KEY is not configured'


def test_query_documents_safe_recursive_dns_query_default() -> None:
    query_operation = api.app.openapi()['paths']['/query']['get']
    query_limit = next(
        parameter for parameter in query_operation['parameters'] if parameter['name'] == 'dns_recursive_query_limit'
    )

    assert query_limit['schema']['default'] == 3_000


@pytest.mark.parametrize('runtime_seconds', ['nan', 'inf'])
def test_query_rejects_non_finite_recursive_dns_runtime(monkeypatch, runtime_seconds: str) -> None:
    async def unexpected_start(*_args, **_kwargs):
        raise AssertionError('enumeration must not start')

    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get(
        f'/query?domain=example.test&source=certspotter&dns_recursive_runtime_seconds={runtime_seconds}'
    )

    assert response.status_code == 422


def test_query_rejects_recursive_dns_without_three_distinct_resolvers(monkeypatch) -> None:
    async def unexpected_start(*_args, **_kwargs):
        raise AssertionError('enumeration must not start')

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get(
        '/query?domain=example.test&source=certspotter&dns_recursive_depth=1&dns_resolve=192.0.2.53,192.0.2.54',
        headers={'X-API-Key': 'operator-secret'},
    )

    assert response.status_code == 400
    assert response.json()['detail'] == 'recursive DNS requires exactly three distinct resolver IPs'


def test_query_unions_capabilities_and_explicit_sources(monkeypatch) -> None:
    captured: list[tuple[Namespace, bool]] = []

    async def fake_start(
        args: Namespace,
        *,
        persist_completed_result: bool = False,
        include_breaches: bool = False,
    ):
        captured.append((args, persist_completed_result))
        assert include_breaches is True
        return ([], [], [], [], [], [], [], [], [], [])

    monkeypatch.setattr(api.__main__, 'start', fake_start)
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')

    response = TestClient(api.app).get(
        '/query?domain=example.test&source=emails&source=certspotter',
        headers={'X-API-Key': 'operator-secret'},
    )

    assert response.status_code == 200
    expected_sources = Core.expand_source_selection('emails,certspotter')
    assert captured[0][0].source == ','.join(expected_sources)
    assert captured[0][1] is True


def test_query_rejects_unknown_source_or_capability(monkeypatch) -> None:
    async def unexpected_start(_args: Namespace):
        raise AssertionError('enumeration must not start')

    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=unknown')

    assert response.status_code == 400
    assert response.json()['detail'].startswith("Source 'unknown' is not supported")


@pytest.mark.parametrize('source', ['hibpverified', 'breaches', 'emails', 'all'])
def test_query_requires_operator_key_when_selection_includes_verified_hibp(monkeypatch, source: str) -> None:
    async def unexpected_start(
        _args: Namespace,
        *,
        persist_completed_result: bool = False,
        include_breaches: bool = False,
    ):
        raise AssertionError('enumeration must not start')

    monkeypatch.delenv('THEHARVESTER_API_KEY', raising=False)
    monkeypatch.setattr(api.__main__.Core, 'hibpverified_key', lambda: 'provider-secret')
    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get(f'/query?domain=example.test&source={source}')

    assert response.status_code == 503
    assert response.json()['detail'] == 'THEHARVESTER_API_KEY is not configured'


def test_authenticated_query_returns_verified_hibp_emails_and_breaches(monkeypatch) -> None:
    captured: list[Namespace] = []

    async def fake_start(
        args: Namespace,
        *,
        persist_completed_result: bool = False,
        include_breaches: bool = False,
    ):
        captured.append(args)
        assert persist_completed_result is True
        assert include_breaches is True
        return ([], [], [], [], [], [], [], ['alice@example.test'], [], ['ExampleBreach'])

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__.Core, 'hibpverified_key', lambda: 'provider-secret')
    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get(
        '/query?domain=example.test&source=hibpverified',
        headers={'X-API-Key': 'operator-secret'},
    )

    assert response.status_code == 200
    assert captured[0].source == 'hibpverified'
    assert response.json()['emails'] == ['alice@example.test']
    assert response.json()['breaches'] == ['ExampleBreach']


def test_authenticated_query_includes_verified_hibp_from_capability_selection(monkeypatch) -> None:
    captured: list[Namespace] = []

    async def fake_start(
        args: Namespace,
        *,
        persist_completed_result: bool = False,
        include_breaches: bool = False,
    ):
        captured.append(args)
        assert include_breaches is True
        return ([], [], [], [], [], [], [], [], [], [])

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__.Core, 'hibpverified_key', lambda: 'provider-secret')
    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get(
        '/query?domain=example.test&source=breaches',
        headers={'X-API-Key': 'operator-secret'},
    )

    assert response.status_code == 200
    assert captured[0].source == 'haveibeenpwned,hibpverified,leaklookup'


def test_query_requires_operator_auth_for_configured_leaklookup(monkeypatch) -> None:
    async def unexpected_start(*_args, **_kwargs):
        raise AssertionError('collection must not start without operator authentication')

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__.Core, 'leaklookup_key', lambda: 'provider-secret')
    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=leaklookup')

    assert response.status_code == 401


@pytest.mark.parametrize('source', ['dehashed', 'emails'])
def test_query_requires_operator_auth_for_configured_dehashed(monkeypatch, source) -> None:
    async def unexpected_start(*_args, **_kwargs):
        raise AssertionError('collection must not start without operator authentication')

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
    monkeypatch.setattr(api.__main__.Core, 'dehashed_key', lambda: 'provider-secret')
    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get(f'/query?domain=example.test&source={source}')

    assert response.status_code == 401


@pytest.mark.parametrize('dehashed_key', [None, '', ' '])
def test_query_skips_operator_auth_when_dehashed_key_is_blank(monkeypatch, dehashed_key) -> None:
    captured: list[Namespace] = []

    async def fake_start(
        args: Namespace,
        *,
        persist_completed_result: bool = False,
        include_breaches: bool = False,
    ):
        captured.append(args)
        return ([], [], [], [], [], [], [], [], [], [])

    monkeypatch.delenv('THEHARVESTER_API_KEY', raising=False)
    monkeypatch.setattr(api.__main__.Core, 'dehashed_key', lambda: dehashed_key)
    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=dehashed')

    assert response.status_code == 200
    assert captured[0].source == 'dehashed'


@pytest.mark.parametrize('leaklookup_key', [None, '', ' '])
def test_query_skips_operator_auth_when_credentialed_provider_keys_are_blank(monkeypatch, leaklookup_key) -> None:
    captured: list[Namespace] = []

    async def fake_start(
        args: Namespace,
        *,
        persist_completed_result: bool = False,
        include_breaches: bool = False,
    ):
        captured.append(args)
        return ([], [], [], [], [], [], [], [], [], [])

    monkeypatch.delenv('THEHARVESTER_API_KEY', raising=False)
    monkeypatch.setattr(api.__main__.Core, 'hibpverified_key', lambda: None)
    monkeypatch.setattr(api.__main__.Core, 'leaklookup_key', lambda: leaklookup_key)
    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=breaches')

    assert response.status_code == 200
    assert captured[0].source == 'haveibeenpwned,hibpverified,leaklookup'


def test_sources_advertises_authenticated_verified_hibp(monkeypatch) -> None:
    monkeypatch.setattr(api.__main__.Core, 'get_supportedengines', lambda: ['crtsh', 'hibpverified'])

    response = TestClient(api.app).get('/sources')

    assert response.status_code == 200
    assert response.json() == {'sources': ['crtsh', 'hibpverified']}

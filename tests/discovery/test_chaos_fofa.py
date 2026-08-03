from collections.abc import Callable
from functools import partial
from typing import Any

import pytest

from theHarvester.discovery import chaos, fofa
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
async def test_chaos_success_reports_subdomains(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')
    requests: list[str] = []
    getter_calls = 0
    get_hostnames = chaos.SearchChaos.get_hostnames

    async def counted_get_hostnames(search: chaos.SearchChaos) -> set[str]:
        nonlocal getter_calls
        getter_calls += 1
        return await get_hostnames(search)

    async def fake_fetch(*, url: str, **kwargs: Any) -> dict[str, Any]:
        requests.append(url)
        assert kwargs['json'] is True
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return {'subdomains': ['api', 'WWW']}

    async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise AssertionError('legacy fetch_all called')

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch_all', reject_fetch_all)
    monkeypatch.setattr(chaos.SearchChaos, 'get_hostnames', counted_get_hostnames)
    result = await execute_collection(
        'example.com',
        'chaos',
        lambda: chaos.SearchChaos('example.com'),
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {
        'api.example.com',
        'www.example.com',
    }
    assert requests == ['https://dns.projectdiscovery.io/dns/example.com/subdomains']
    assert getter_calls == 1


@pytest.mark.asyncio
async def test_fofa_success_reports_declared_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))
    requests: list[str] = []
    getter_calls = {'hostnames': 0, 'ips': 0}
    get_hostnames = fofa.SearchFofa.get_hostnames
    get_ips = fofa.SearchFofa.get_ips

    async def counted_get_hostnames(search: fofa.SearchFofa) -> set[str]:
        getter_calls['hostnames'] += 1
        return await get_hostnames(search)

    async def counted_get_ips(search: fofa.SearchFofa) -> set[str]:
        getter_calls['ips'] += 1
        return await get_ips(search)

    async def fake_fetch(*, url: str, **kwargs: Any) -> dict[str, Any]:
        requests.append(url)
        assert kwargs['json'] is True
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return {
            'error': False,
            'results': [
                ['https://API.Example.COM:443', '192.0.2.10'],
                ['https://outside.test', '198.51.100.20'],
            ],
        }

    async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise AssertionError('legacy fetch_all called')

    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(fofa.AsyncFetcher, 'fetch_all', reject_fetch_all)
    monkeypatch.setattr(fofa.SearchFofa, 'get_hostnames', counted_get_hostnames)
    monkeypatch.setattr(fofa.SearchFofa, 'get_ips', counted_get_ips)
    result = await execute_collection(
        'example.com',
        'fofa',
        lambda: fofa.SearchFofa('example.com'),
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert set(result.route_values[ResultRoute.IPS]) == {'192.0.2.10', '198.51.100.20'}
    assert len(requests) == 1
    assert requests[0].startswith('https://fofa.info/api/v1/search/all?')
    assert getter_calls == {'hostnames': 1, 'ips': 1}


@pytest.mark.asyncio
async def test_chaos_preserves_alternate_results_after_empty_primary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        return {'subdomains': [], 'data': ['api']}

    monkeypatch.setattr(chaos.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'chaos',
        lambda: chaos.SearchChaos('example.com'),
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)


@pytest.fixture(params=['chaos', 'fofa'])
def provider(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, Any, Callable[[], Any]]:
    if request.param == 'chaos':
        monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: 'test-key')
        return 'chaos', chaos, lambda: chaos.SearchChaos('example.com')
    monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('test-key', 'operator@example.com'))
    return 'fofa', fofa, lambda: fofa.SearchFofa('example.com')


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(
    monkeypatch: pytest.MonkeyPatch,
    provider: tuple[str, Any, Callable[[], Any]],
) -> None:
    source, module, factory = provider
    payload = {'subdomains': []} if source == 'chaos' else {'error': False, 'results': []}

    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        return payload

    monkeypatch.setattr(module.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.EMPTY


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['chaos', 'fofa'])
async def test_missing_credentials_skip_before_request(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    requests: list[str] = []
    if source == 'chaos':
        monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', lambda: '')
        module = chaos
        factory = partial(chaos.SearchChaos, 'example.com')
    else:
        monkeypatch.setattr(fofa.Core, 'fofa_key', lambda: ('', ''))
        module = fofa
        factory = partial(fofa.SearchFofa, 'example.com')

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(url)
        return {}

    monkeypatch.setattr(module.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'
    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['chaos', 'fofa'])
async def test_unexpected_credential_failure_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    def fail_credentials() -> Any:
        raise RuntimeError('configuration unavailable')

    if source == 'chaos':
        monkeypatch.setattr(chaos.Core, 'projectdiscovery_key', fail_credentials)
        factory: Callable[[], Any] = partial(chaos.SearchChaos, 'example.com')
    else:
        monkeypatch.setattr(fofa.Core, 'fofa_key', fail_credentials)
        factory = partial(fofa.SearchFofa, 'example.com')

    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'


@pytest.mark.asyncio
async def test_malformed_json_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    provider: tuple[str, Any, Callable[[], Any]],
) -> None:
    source, module, factory = provider

    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        raise ValueError('malformed JSON')

    monkeypatch.setattr(module.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'


@pytest.mark.asyncio
async def test_unexpected_response_shape_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    provider: tuple[str, Any, Callable[[], Any]],
) -> None:
    source, module, factory = provider
    payload = {} if source == 'chaos' else {'error': False}

    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        return payload

    monkeypatch.setattr(module.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'


@pytest.mark.asyncio
async def test_authentication_error_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    provider: tuple[str, Any, Callable[[], Any]],
) -> None:
    source, module, factory = provider
    payload = {'error': 'unauthorized'} if source == 'chaos' else {'error': True, 'errmsg': 'invalid account'}

    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        return payload

    monkeypatch.setattr(module.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'PermissionError'


@pytest.mark.asyncio
async def test_provider_error_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    provider: tuple[str, Any, Callable[[], Any]],
) -> None:
    source, module, factory = provider
    payload = (
        {'error': 'unavailable', 'message': 'upstream unavailable'}
        if source == 'chaos'
        else {'error': True, 'errmsg': 'request blocked'}
    )

    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        return payload

    monkeypatch.setattr(module.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'


@pytest.mark.asyncio
async def test_transport_failure_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    provider: tuple[str, Any, Callable[[], Any]],
) -> None:
    source, module, factory = provider

    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        raise ConnectionError('provider unavailable')

    monkeypatch.setattr(module.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ConnectionError'


@pytest.mark.asyncio
async def test_non_success_response_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    provider: tuple[str, Any, Callable[[], Any]],
) -> None:
    source, module, factory = provider

    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError('HTTP 503')

    monkeypatch.setattr(module.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'


@pytest.mark.asyncio
async def test_malformed_later_result_retains_partial_values(
    monkeypatch: pytest.MonkeyPatch,
    provider: tuple[str, Any, Callable[[], Any]],
) -> None:
    source, module, factory = provider
    payload = (
        {'subdomains': ['api', None]}
        if source == 'chaos'
        else {
            'error': False,
            'results': [
                ['https://api.example.com', '192.0.2.10'],
                ['invalid'],
            ],
        }
    )

    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        return payload

    monkeypatch.setattr(module.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', source, factory)

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    if source == 'fofa':
        assert result.route_values[ResultRoute.IPS] == ('192.0.2.10',)

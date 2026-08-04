from typing import Any

import pytest

from theHarvester.discovery import projectdiscovery
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
async def test_blank_key_skips_before_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(projectdiscovery.Core, 'projectdiscovery_key', lambda: '   ')

    async def reject_request(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError('provider request attempted')

    monkeypatch.setattr(projectdiscovery.AsyncFetcher, 'fetch', reject_request)
    monkeypatch.setattr(projectdiscovery.AsyncFetcher, 'fetch_all', reject_request)
    result = await execute_collection(
        'example.com',
        'projectdiscovery',
        lambda: projectdiscovery.SearchDiscovery('example.com'),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
async def test_timeout_preserves_transport_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(projectdiscovery.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch(*_args: Any, **kwargs: Any) -> str:
        if kwargs.get('raise_on_error', False):
            raise TimeoutError('provider timed out')
        return ''

    monkeypatch.setattr(projectdiscovery.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'projectdiscovery',
        lambda: projectdiscovery.SearchDiscovery('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'TimeoutError'


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(projectdiscovery.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch(*, url: str, **kwargs: Any) -> dict[str, list[Any]]:
        assert url == 'https://dns.projectdiscovery.io/dns/example.com/subdomains'
        assert kwargs['json'] is True
        assert kwargs['headers']['Authorization'] == 'test-key'
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return {'subdomains': []}

    monkeypatch.setattr(projectdiscovery.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com', 'projectdiscovery', lambda: projectdiscovery.SearchDiscovery('example.com')
    )

    assert result.outcome.status is SourceStatus.EMPTY


@pytest.mark.asyncio
async def test_valid_response_preserves_hostname_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(projectdiscovery.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch(**_kwargs: Any) -> dict[str, list[str]]:
        return {'subdomains': ['api', 'WWW']}

    monkeypatch.setattr(projectdiscovery.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com', 'projectdiscovery', lambda: projectdiscovery.SearchDiscovery('example.com')
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'api.example.com', 'www.example.com'}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        pytest.param({'error': 'unauthorized'}, 'ValueError', id='provider-error'),
        pytest.param({'subdomains': {}}, 'ValueError', id='malformed-subdomains'),
        pytest.param([], 'ValueError', id='malformed-payload'),
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='http-error'),
        pytest.param(ConnectionError('provider unavailable'), 'ConnectionError', id='transport-error'),
    ],
)
async def test_collection_failures_report_failed(
    monkeypatch: pytest.MonkeyPatch, response: object, error_type: str
) -> None:
    monkeypatch.setattr(projectdiscovery.Core, 'projectdiscovery_key', lambda: 'test-key')

    async def fake_fetch(**_kwargs: Any) -> object:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(projectdiscovery.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com', 'projectdiscovery', lambda: projectdiscovery.SearchDiscovery('example.com')
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type

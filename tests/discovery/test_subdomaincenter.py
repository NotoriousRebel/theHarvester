from typing import Any

import pytest

from theHarvester.discovery import subdomaincenter
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[str] = []

    async def fake_fetch(*, url: str, **kwargs: Any) -> list[str]:
        requests.append(url)
        assert kwargs['json'] is True
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return []

    async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError('legacy fetch_all called')

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', reject_fetch_all)
    result = await execute_collection(
        'example.com',
        'subdomaincenter',
        lambda: subdomaincenter.SubdomainCenter('example.com'),
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}
    assert requests == ['https://api.subdomain.center/?domain=example.com']


@pytest.mark.asyncio
async def test_success_preserves_public_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> list[str]:
        return ['api.example.com', 'www.example.com']

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'subdomaincenter',
        lambda: subdomaincenter.SubdomainCenter('example.com'),
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'api.example.com', 'example.com'}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        ({'error': 'rate limited'}, 'ValueError'),
        ('invalid', 'ValueError'),
        ([None], 'TypeError'),
        (ConnectionError('provider unavailable'), 'ConnectionError'),
        (TimeoutError('provider timed out'), 'TimeoutError'),
        (RuntimeError('HTTP 503'), 'RuntimeError'),
    ],
)
async def test_collection_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    response: Any,
    error_type: str,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> Any:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'subdomaincenter',
        lambda: subdomaincenter.SubdomainCenter('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}

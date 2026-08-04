from typing import Any

import pytest

from theHarvester.discovery import urlscan
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(*, url: str, **kwargs: Any) -> dict[str, list[Any]]:
        assert url == 'https://urlscan.io/api/v1/search/?q=domain:example.com'
        assert kwargs['json'] is True
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return {'results': []}

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'urlscan',
        lambda: urlscan.SearchUrlscan('example.com'),
    )

    assert result.outcome.status is SourceStatus.EMPTY


@pytest.mark.asyncio
async def test_valid_response_preserves_result_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(*_args: Any, **_kwargs: Any) -> dict[str, list[dict[str, dict[str, str]]]]:
        return {
            'results': [
                {
                    'page': {
                        'domain': 'api.example.com',
                        'ip': '192.0.2.10',
                        'asn': 'AS64500',
                        'url': 'https://api.example.com/',
                    }
                }
            ]
        }

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'urlscan',
        lambda: urlscan.SearchUrlscan('example.com'),
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: ('api.example.com',),
        ResultRoute.IPS: ('192.0.2.10',),
        ResultRoute.ASNS: ('AS64500',),
        ResultRoute.INTERESTING_URLS: ('https://api.example.com/',),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        pytest.param({'error': 'rate limited'}, 'ValueError', id='provider-error'),
        pytest.param({'results': {}}, 'ValueError', id='malformed-results'),
        pytest.param([], 'ValueError', id='malformed-payload'),
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='http-error'),
        pytest.param(ConnectionError('provider unavailable'), 'ConnectionError', id='transport-error'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
    ],
)
async def test_collection_failures_report_failed(
    monkeypatch: pytest.MonkeyPatch,
    response: object,
    error_type: str,
) -> None:
    async def fake_fetch(*_args: Any, **kwargs: Any) -> object:
        if isinstance(response, Exception):
            if isinstance(response, TimeoutError | ConnectionError) and not kwargs.get('raise_on_error', False):
                return ''
            raise response
        return response

    monkeypatch.setattr(urlscan.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'urlscan',
        lambda: urlscan.SearchUrlscan('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type

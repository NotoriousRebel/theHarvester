import json
from typing import Any

import pytest

from theHarvester.discovery import threatcrowd
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(*, url: str, **kwargs: Any) -> str:
        assert url == 'http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain=example.com'
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return json.dumps({'response_code': '1', 'subdomains': [], 'resolutions': []})

    monkeypatch.setattr(threatcrowd.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'threatcrowd',
        lambda: threatcrowd.SearchThreatcrowd('example.com'),
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: (),
        ResultRoute.IPS: (),
    }


@pytest.mark.asyncio
async def test_valid_response_preserves_result_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(*_args: Any, **_kwargs: Any) -> str:
        return json.dumps(
            {
                'response_code': 1,
                'subdomains': ['API.Example.com', 'outside.test'],
                'resolutions': [{'ip_address': '192.0.2.10'}, '198.51.100.20'],
            }
        )

    monkeypatch.setattr(threatcrowd.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'threatcrowd',
        lambda: threatcrowd.SearchThreatcrowd('example.com'),
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert set(result.route_values[ResultRoute.IPS]) == {'192.0.2.10', '198.51.100.20'}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        pytest.param(
            {'response_code': '0', 'subdomains': [], 'resolutions': []},
            'ValueError',
            id='provider-error',
        ),
        pytest.param(
            {'response_code': '1', 'subdomains': {}, 'resolutions': []},
            'ValueError',
            id='malformed-collections',
        ),
        pytest.param('not json', 'ValueError', id='malformed-json'),
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
    async def fake_fetch(*_args: Any, **kwargs: Any) -> str:
        if isinstance(response, Exception):
            if isinstance(response, TimeoutError) and not kwargs.get('raise_on_error', False):
                return ''
            raise response
        return response if isinstance(response, str) else json.dumps(response)

    monkeypatch.setattr(threatcrowd.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'threatcrowd',
        lambda: threatcrowd.SearchThreatcrowd('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type

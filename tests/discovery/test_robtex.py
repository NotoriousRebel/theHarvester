from typing import Any

import pytest

from theHarvester.discovery import robtex
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
async def test_robtex_does_not_send_domain_to_reverse_ip_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_fetch(*, url: str, **kwargs: Any) -> str:
        requested_urls.append(url)
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return '{"rrname":"api.example.com","rrtype":"A","rrdata":"192.0.2.1"}'

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch', fake_fetch)
    search = robtex.SearchRobtex('example.com')
    await search.process()

    assert requested_urls == ['https://freeapi.robtex.com/pdns/forward/example.com']
    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.1'}


@pytest.mark.asyncio
async def test_completed_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> str:
        return ''

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', 'robtex', lambda: robtex.SearchRobtex('example.com'))

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert result.route_values[ResultRoute.IPS] == ()


@pytest.mark.asyncio
async def test_malformed_later_line_retains_partial_results(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> str:
        return '{"rrname":"api.example.com","rrtype":"A","rrdata":"192.0.2.1"}\nnot-json'

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', 'robtex', lambda: robtex.SearchRobtex('example.com'))

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert result.route_values[ResultRoute.IPS] == ('192.0.2.1',)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='http-error'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
        pytest.param('{"error":"rate limit exceeded"}', 'RuntimeError', id='provider-error'),
        pytest.param('[]', 'ValueError', id='malformed-record'),
        pytest.param('{}', 'ValueError', id='missing-record-fields'),
    ],
)
async def test_collection_failures_report_failed(
    monkeypatch: pytest.MonkeyPatch, response: str | Exception, error_type: str
) -> None:
    async def fake_fetch(**_kwargs: Any) -> str:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection('example.com', 'robtex', lambda: robtex.SearchRobtex('example.com'))

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type

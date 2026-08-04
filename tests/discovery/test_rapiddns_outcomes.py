from typing import Any

import pytest

from theHarvester.discovery import rapiddns
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
async def test_valid_empty_table_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(*, url: str, **kwargs: Any) -> str:
        assert url == 'https://rapiddns.io/subdomain/example.com?full=1#result'
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return '<table><tbody></tbody></table>'

    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com', 'rapiddns', lambda: rapiddns.SearchRapidDns('example.com')
    )

    assert result.outcome.status is SourceStatus.EMPTY


@pytest.mark.asyncio
async def test_valid_table_preserves_hostname_route(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> str:
        return (
            '<table><tbody><tr><td>API.Example.com</td>'
            '<td>target.example.net</td><td>CNAME</td></tr></tbody></table>'
        )

    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com', 'rapiddns', lambda: rapiddns.SearchRapidDns('example.com')
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        pytest.param('', 'ValueError', id='blank-response'),
        pytest.param('<html></html>', 'ValueError', id='missing-table'),
        pytest.param(
            '<html><body><div class="alert alert-danger">Provider error</div></body></html>',
            'ValueError',
            id='provider-error-page',
        ),
        pytest.param('<table></table>', 'ValueError', id='missing-table-body'),
        pytest.param(
            '<table><tbody>'
            '<tr><td>api.example.com</td><td>target.example.net</td><td>CNAME</td></tr>'
            '<tr><td>CNAME</td></tr>'
            '</tbody></table>',
            'ValueError',
            id='malformed-row',
        ),
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='http-error'),
        pytest.param(ConnectionError('provider unavailable'), 'ConnectionError', id='transport-error'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
    ],
)
async def test_collection_failures_report_failed(
    monkeypatch: pytest.MonkeyPatch, response: str | Exception, error_type: str
) -> None:
    async def fake_fetch(**_kwargs: Any) -> str:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com', 'rapiddns', lambda: rapiddns.SearchRapidDns('example.com')
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type

from typing import Any

import pytest

from theHarvester.discovery import duckduckgosearch
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


async def _collect(
    monkeypatch: pytest.MonkeyPatch,
    outcome: object,
    *,
    proxy: bool = False,
):
    calls: list[dict[str, Any]] = []

    async def fake_fetch(*, url: str, **kwargs: Any) -> object:
        calls.append({'url': url, **kwargs})
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> list[object]:
        raise AssertionError('legacy fetch_all called')

    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_all', reject_fetch_all)
    result = await execute_collection(
        'example.com',
        'duckduckgo',
        lambda: duckduckgosearch.SearchDuckDuckGo('example.com', 100),
        proxy=proxy,
    )
    return result, calls


@pytest.mark.asyncio
async def test_duckduckgo_does_not_fetch_provider_returned_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = """
    {
      "AbstractURL": "https://api.example.com",
      "AbstractText": "Contact admin@example.com.",
      "Results": [{"FirstURL": "https://outside.test"}]
    }
    """

    result, calls = await _collect(monkeypatch, payload, proxy=True)

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert len(calls) == 1
    assert calls[0]['url'] == 'https://api.duckduckgo.com/?q=example.com&format=json&pretty=1'
    assert calls[0]['proxy'] is True
    assert calls[0]['request_timeout'] == 60
    assert calls[0]['fail_on_http_error'] is True
    assert calls[0]['follow_redirects'] is False
    assert calls[0]['raise_on_error'] is True
    assert isinstance(calls[0]['headers']['User-Agent'], str)
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {
        'api.example.com',
        'example.com',
    }
    assert result.route_values[ResultRoute.EMAILS] == ('admin@example.com',)


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(monkeypatch, '{}')

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.outcome.process_succeeded is True
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert result.route_values[ResultRoute.EMAILS] == ()
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('error', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='non-success-http'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
    ],
)
async def test_request_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    error_type: str,
) -> None:
    result, calls = await _collect(monkeypatch, error)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert result.route_values[ResultRoute.EMAILS] == ()
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        pytest.param('', id='empty-body'),
        pytest.param('not-json', id='invalid-json'),
        pytest.param('[]', id='non-object-json'),
        pytest.param(None, id='non-text-response'),
    ],
)
async def test_malformed_response_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    result, calls = await _collect(monkeypatch, payload)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert result.route_values[ResultRoute.EMAILS] == ()
    assert len(calls) == 1

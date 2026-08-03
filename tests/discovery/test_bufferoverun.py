from typing import Any

import pytest

from theHarvester.discovery import bufferoverun
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
@pytest.mark.parametrize('key', [None, ''])
async def test_missing_key_skips_before_request(
    monkeypatch: pytest.MonkeyPatch,
    key: str | None,
) -> None:
    monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', lambda: key)

    async def reject_request(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError('provider request attempted')

    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch', reject_request)
    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch_all', reject_request)
    result = await execute_collection(
        'example.com',
        'bufferoverun',
        lambda: bufferoverun.SearchBufferover('example.com'),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', lambda: 'test-key')

    async def fake_fetch(*, url: str, **kwargs: Any) -> dict[str, list[Any]]:
        assert url == 'https://tls.bufferover.run/dns?q=example.com'
        assert kwargs['json'] is True
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return {'Results': []}

    async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError('legacy fetch_all called')

    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch_all', reject_fetch_all)
    result = await execute_collection(
        'example.com',
        'bufferoverun',
        lambda: bufferoverun.SearchBufferover('example.com'),
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: (),
        ResultRoute.IPS: (),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        ({'error': 'unauthorized'}, 'ValueError'),
        ({'Results': {}}, 'ValueError'),
        ([], 'ValueError'),
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
    monkeypatch.setattr(bufferoverun.Core, 'bufferoverun_key', lambda: 'test-key')

    async def fake_fetch(**_kwargs: Any) -> Any:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'bufferoverun',
        lambda: bufferoverun.SearchBufferover('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: (),
        ResultRoute.IPS: (),
    }

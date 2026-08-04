import logging
from typing import Any

import pytest

from theHarvester.discovery import whoisxml
from theHarvester.lib.run import SourceStatus, execute_collection


@pytest.mark.asyncio
async def test_blank_key_skips_before_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', lambda: '   ')

    async def reject_request(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError('provider request attempted')

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', reject_request)
    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch_all', reject_request)
    result = await execute_collection(
        'example.com',
        'whoisxml',
        lambda: whoisxml.SearchWhoisXML('example.com'),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', lambda: 'test-key')

    async def fake_fetch(*, url: str, **kwargs: Any) -> dict[str, dict[str, list[Any]]]:
        assert url == 'https://subdomains.whoisxmlapi.com/api/v1'
        assert kwargs['params'] == {'apiKey': 'test-key', 'domainName': 'example.com'}
        assert kwargs['json'] is True
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return {'result': {'records': []}}

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'whoisxml',
        lambda: whoisxml.SearchWhoisXML('example.com'),
    )

    assert result.outcome.status is SourceStatus.EMPTY


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        pytest.param({'error': 'invalid API key'}, 'ValueError', id='provider-error'),
        pytest.param({'result': {'records': {}}}, 'ValueError', id='malformed-records'),
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
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', lambda: 'test-key')

    async def fake_fetch(*_args: Any, **kwargs: Any) -> object:
        if isinstance(response, Exception):
            if isinstance(response, TimeoutError | ConnectionError) and not kwargs.get('raise_on_error', False):
                return ''
            raise response
        return response

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'whoisxml',
        lambda: whoisxml.SearchWhoisXML('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type


@pytest.mark.asyncio
async def test_response_body_is_not_logged_and_records_are_returned(monkeypatch, caplog) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', lambda: 'test-key')
    monkeypatch.setattr(whoisxml.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_fetch(*args, **kwargs):
        return {
            'secret': 'provider-secret-payload',
            'result': {'records': [{'domain': 'www.example.com'}]},
        }

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch', fake_fetch)
    caplog.set_level(logging.INFO, logger=whoisxml.__name__)

    search = whoisxml.SearchWhoisXML('example.com')
    await search.process()

    assert await search.get_hostnames() == ['www.example.com']
    assert 'provider-secret-payload' not in caplog.text

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from theHarvester.discovery import waybackarchive
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


async def _collect(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: list[object],
    *,
    target: str = 'example.com',
):
    pending = list(outcomes)
    calls: list[dict[str, Any]] = []

    async def fake_fetch(*, url: str, **kwargs: Any) -> object:
        calls.append({'url': url, **kwargs})
        if not pending:
            pytest.fail('Wayback made an unexpected request')
        outcome = pending.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(waybackarchive.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        target,
        'waybackarchive',
        lambda: waybackarchive.SearchWaybackarchive(target),
    )
    assert not pending
    return result, calls


@pytest.mark.asyncio
async def test_provider_error_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        ['<html>provider error</html>', ''],
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(monkeypatch, ['', ''])

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.outcome.process_succeeded is True
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 2
    assert all(call['fail_on_http_error'] is True for call in calls)
    assert all(call['follow_redirects'] is False for call in calls)
    assert all(call['raise_on_error'] is True for call in calls)
    assert all(call['request_timeout'] == 60 for call in calls)


@pytest.mark.asyncio
async def test_resume_key_pagination_preserves_public_subdomain_route(monkeypatch: pytest.MonkeyPatch) -> None:
    resume_key = 'com%2Cexample%29%2F+20260101000000%21'
    result, calls = await _collect(
        monkeypatch,
        [
            f'https://beta.example.com/path\n\n{resume_key}',
            'https://alpha.example.com/path',
            '',
        ],
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'alpha.example.com', 'beta.example.com'}
    queries = [parse_qs(urlparse(call['url']).query) for call in calls]
    assert [query['url'] for query in queries] == [
        ['*.example.com'],
        ['*.example.com'],
        ['example.com/*'],
    ]
    assert queries[1]['resumeKey'] == ['com,example)/ 20260101000000!']
    assert f'resumeKey={resume_key}' in calls[1]['url']


@pytest.mark.asyncio
async def test_success_preserves_hostname_normalization_and_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = '\n'.join(
        (
            'HTTPS://API.Example.COM:8443/path',
            'https://example.com/root',
            'https://notexample.com/path',
            'https://example.com.attacker.net/path',
        )
    )
    result, _calls = await _collect(monkeypatch, [payload, ''])

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'api.example.com', 'example.com'}


@pytest.mark.asyncio
async def test_requested_domain_normalization_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        ['https://api.example.com/path', ''],
        target='Example.COM.',
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert parse_qs(urlparse(calls[0]['url']).query)['url'] == ['*.example.com']


@pytest.mark.asyncio
async def test_malformed_resume_section_retains_completed_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        ['https://api.example.com/path\n\nresume-one\nresume-two', ''],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_empty_page_with_resume_key_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(monkeypatch, ['\n\nnext-page', ''])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_repeated_resume_key_reports_partial_without_repeating_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = 'https://api.example.com/path\n\nsame-key'
    result, calls = await _collect(monkeypatch, [page, page, ''])

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_page_cap_reports_partial_after_completed_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(waybackarchive.SearchWaybackarchive, 'MAX_PAGES_PER_QUERY', 2)
    result, calls = await _collect(
        monkeypatch,
        [
            'https://one.example.com/path\n\nnext-one',
            'https://two.example.com/path\n\nnext-two',
            '',
        ],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'RuntimeError'
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'one.example.com', 'two.example.com'}
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_mixed_malformed_and_usable_rows_report_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        ['https://api.example.com/path\nmalformed row', ''],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('error', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='non-success-http'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
    ],
)
async def test_first_request_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    error_type: str,
) -> None:
    result, calls = await _collect(monkeypatch, [error, ''])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('later_outcome', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 429'), 'RuntimeError', id='non-success-http'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
        pytest.param('<html>provider error</html>', 'RuntimeError', id='provider-error'),
        pytest.param({'unexpected': 'shape'}, 'ValueError', id='malformed-response'),
    ],
)
async def test_later_page_failure_retains_completed_rows(
    monkeypatch: pytest.MonkeyPatch,
    later_outcome: object,
    error_type: str,
) -> None:
    first_page = 'https://api.example.com/path\n\nnext-page'
    result, calls = await _collect(monkeypatch, [first_page, later_outcome, ''])

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == error_type
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert len(calls) == 3

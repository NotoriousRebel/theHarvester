from typing import Any

import pytest

from theHarvester.discovery import virustotal
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


def _domain(hostname: str) -> dict[str, object]:
    return {
        'id': hostname,
        'attributes': {
            'last_dns_records': [],
        },
    }


def _page(
    *records: object,
    cursor: object | None = None,
    next_page: bool = False,
    count: object | None = None,
) -> dict[str, object]:
    meta: dict[str, object] = {'count': len(records) if count is None else count}
    if cursor is not None:
        meta['cursor'] = cursor
    links = {'self': 'https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=40'}
    if next_page:
        links['next'] = f'{links["self"]}&cursor={cursor}'
    return {'data': list(records), 'meta': meta, 'links': links}


async def _collect(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: list[object],
):
    pending = list(outcomes)
    calls: list[dict[str, Any]] = []

    async def fake_fetch(*, url: str, **kwargs: Any) -> object:
        calls.append({'url': url, **kwargs})
        if not pending:
            pytest.fail('VirusTotal made an unexpected request')
        outcome = pending.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> list[object]:
        raise AssertionError('legacy fetch_all called')

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(virustotal.Core, 'virustotal_key', lambda: 'test-key')
    monkeypatch.setattr(virustotal.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(virustotal.AsyncFetcher, 'fetch_all', reject_fetch_all)
    monkeypatch.setattr(virustotal.asyncio, 'sleep', no_sleep)
    result = await execute_collection(
        'example.com',
        'virustotal',
        lambda: virustotal.SearchVirustotal('example.com'),
    )
    assert not pending
    return result, calls


@pytest.mark.asyncio
@pytest.mark.parametrize('key', [None, '', ' '])
async def test_missing_key_reports_skipped_without_request(
    monkeypatch: pytest.MonkeyPatch,
    key: object,
) -> None:
    monkeypatch.setattr(virustotal.Core, 'virustotal_key', lambda: key)

    async def unexpected_request(**_kwargs: Any) -> object:
        pytest.fail('VirusTotal request must not run without a key')

    monkeypatch.setattr(virustotal.AsyncFetcher, 'fetch', unexpected_request)
    result = await execute_collection(
        'example.com',
        'virustotal',
        lambda: virustotal.SearchVirustotal('example.com'),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(monkeypatch, [_page()])

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.outcome.process_succeeded is True
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 1
    assert calls[0]['url'] == 'https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=40'
    assert calls[0]['headers']['x-apikey'] == 'test-key'
    assert calls[0]['json'] is True
    assert calls[0]['fail_on_http_error'] is True
    assert calls[0]['follow_redirects'] is False
    assert calls[0]['raise_on_error'] is True
    assert calls[0]['request_timeout'] == 60


@pytest.mark.asyncio
async def test_provider_error_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [{'error': {'code': 'QuotaExceededError', 'message': 'quota exceeded'}}],
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
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
async def test_first_request_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    error_type: str,
) -> None:
    result, calls = await _collect(monkeypatch, [error])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        pytest.param([], id='non-object'),
        pytest.param({'meta': {'count': 0}, 'links': {}}, id='missing-data'),
        pytest.param({'data': {}, 'meta': {'count': 0}, 'links': {}}, id='invalid-data'),
        pytest.param({'data': [], 'links': {}}, id='missing-meta'),
        pytest.param({'data': [], 'meta': [], 'links': {}}, id='invalid-meta'),
        pytest.param(_page(count='0'), id='invalid-count'),
        pytest.param({'data': [], 'meta': {'count': 0}}, id='missing-links'),
        pytest.param({'data': [], 'meta': {'count': 0}, 'links': []}, id='invalid-links'),
    ],
)
async def test_malformed_response_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    result, calls = await _collect(monkeypatch, [payload])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_cursor_pagination_preserves_public_subdomain_route(monkeypatch: pytest.MonkeyPatch) -> None:
    first_page = _page(_domain('beta.example.com'), cursor='cursor / 1', next_page=True, count=2)
    final_page = _page(_domain('alpha.example.com'), count=2)
    result, calls = await _collect(monkeypatch, [first_page, final_page])

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('alpha.example.com', 'beta.example.com')
    assert [call['url'] for call in calls] == [
        'https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=40',
        'https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=40&cursor=cursor+%2F+1',
    ]


@pytest.mark.asyncio
async def test_success_preserves_existing_hostname_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    domain = {
        'id': 'api.example.com',
        'attributes': {
            'last_dns_records': [
                {'value': 'dns.example.com'},
                {'value': '192.0.2.1'},
            ],
            'last_https_certificate': {
                'extensions': {
                    'subject_alternative_name': [
                        'cert.example.com',
                        'outside.test',
                    ]
                }
            },
        },
    }
    result, _calls = await _collect(monkeypatch, [_page(domain)])

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.SUBDOMAINS] == (
        'api.example.com',
        'cert.example.com',
        'dns.example.com',
    )


@pytest.mark.asyncio
async def test_missing_next_cursor_retains_completed_page(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [_page(_domain('api.example.com'), next_page=True)],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_empty_page_with_next_cursor_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [_page(cursor='next-cursor', next_page=True)],
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_malformed_domain_record_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [_page({'id': 7, 'attributes': {'last_dns_records': []}})],
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_blank_domain_identifier_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [_page({'id': ' ', 'attributes': {'last_dns_records': []}})],
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_mixed_malformed_and_usable_records_report_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [
            _page(
                {'id': 7, 'attributes': {'last_dns_records': []}},
                _domain('api.example.com'),
            )
        ],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('cursor', [7, ' '], ids=['non-string', 'blank'])
async def test_invalid_next_cursor_retains_completed_page(
    monkeypatch: pytest.MonkeyPatch,
    cursor: object,
) -> None:
    result, calls = await _collect(
        monkeypatch,
        [_page(_domain('api.example.com'), cursor=cursor, next_page=True)],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_repeated_cursor_stops_after_completed_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    first_page = _page(_domain('api.example.com'), cursor='same-cursor', next_page=True, count=2)
    repeated_page = _page(_domain('web.example.com'), cursor='same-cursor', next_page=True, count=2)
    result, calls = await _collect(monkeypatch, [first_page, repeated_page])

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com', 'web.example.com')
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('later_outcome', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 429'), 'RuntimeError', id='non-success-http'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
        pytest.param(
            {'error': {'code': 'InvalidArgumentError', 'message': 'invalid cursor'}},
            'RuntimeError',
            id='provider-error',
        ),
        pytest.param({'meta': {'count': 1}, 'links': {}}, 'ValueError', id='malformed-response'),
    ],
)
async def test_later_request_failure_retains_completed_page(
    monkeypatch: pytest.MonkeyPatch,
    later_outcome: object,
    error_type: str,
) -> None:
    first_page = _page(_domain('api.example.com'), cursor='next-cursor', next_page=True, count=1)
    result, calls = await _collect(monkeypatch, [first_page, later_outcome])

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == error_type
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert len(calls) == 2

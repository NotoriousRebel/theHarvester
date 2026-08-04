from typing import Any

import pytest

from theHarvester.discovery import zoomeyesearch
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


def _domain_page(*records: object, total: int = 0, code: int = 0) -> dict[str, object]:
    return {'code': code, 'data': {'total': total, 'list': list(records)}}


def _host_page(*records: object, total: int = 0, code: int = 0) -> dict[str, object]:
    return {'code': code, 'data': {'total': total, 'matches': list(records)}}


async def _collect(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: list[object],
    *,
    remaining: int = 0,
):
    pending = list(outcomes)
    calls: list[dict[str, Any]] = []

    async def fake_fetch(*, url: str, **kwargs: Any) -> object:
        calls.append({'url': url, **kwargs})
        if not pending:
            pytest.fail('ZoomEye made an unexpected request')
        outcome = pending.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> list[object]:
        raise AssertionError('legacy fetch_all called')

    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', lambda: 'test-key')
    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'fetch_all', reject_fetch_all)
    result = await execute_collection(
        'example.com',
        'zoomeye',
        lambda: zoomeyesearch.SearchZoomEye('example.com', 2),
    )
    assert len(pending) == remaining
    return result, calls


@pytest.mark.asyncio
@pytest.mark.parametrize('key', [None, '', ' '])
async def test_missing_key_reports_skipped_without_request(
    monkeypatch: pytest.MonkeyPatch,
    key: object,
) -> None:
    monkeypatch.setattr(zoomeyesearch.Core, 'zoomeye_key', lambda: key)

    async def unexpected_request(**_kwargs: Any) -> object:
        pytest.fail('ZoomEye request must not run without a key')

    monkeypatch.setattr(zoomeyesearch.AsyncFetcher, 'fetch', unexpected_request)
    result = await execute_collection(
        'example.com',
        'zoomeye',
        lambda: zoomeyesearch.SearchZoomEye('example.com', 2),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
async def test_valid_empty_responses_report_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(monkeypatch, [_domain_page(), _host_page()])

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.outcome.process_succeeded is True
    assert all(not values for values in result.route_values.values())
    assert [call['url'] for call in calls] == [
        'https://api.zoomeye.ai/domain/search',
        'https://api.zoomeye.ai/host/search',
    ]
    assert all(call['headers']['API-KEY'] == 'test-key' for call in calls)
    assert all(call['json'] is True for call in calls)
    assert all(call['fail_on_http_error'] is True for call in calls)
    assert all(call['follow_redirects'] is False for call in calls)
    assert all(call['raise_on_error'] is True for call in calls)
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()


@pytest.mark.asyncio
async def test_documented_success_code_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _calls = await _collect(
        monkeypatch,
        [_domain_page(code=60000), _host_page(code=60000)],
    )

    assert result.outcome.status is SourceStatus.EMPTY


@pytest.mark.asyncio
async def test_provider_error_reports_failed_not_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [{'code': 401, 'message': 'invalid key'}],
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert all(not values for values in result.route_values.values())
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
    assert all(not values for values in result.route_values.values())
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        pytest.param([], id='non-object'),
        pytest.param({'code': 0, 'data': []}, id='non-object-data'),
        pytest.param({'code': 0, 'data': {'total': 0}}, id='missing-container'),
        pytest.param({'code': 0, 'data': {'total': 0, 'list': {}}}, id='non-list-container'),
    ],
)
async def test_malformed_response_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    result, calls = await _collect(monkeypatch, [payload])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert all(not values for values in result.route_values.values())
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_later_domain_page_failure_retains_completed_page(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [
            _domain_page({'name': 'dns.example.com'}, total=60),
            RuntimeError('HTTP 503'),
        ],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('dns.example.com',)
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_later_host_page_failure_retains_domain_and_host_values(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [
            _domain_page({'name': 'dns.example.com'}, total=1),
            _host_page(
                {'domain': 'api.example.com', 'ip': '192.0.2.10', 'asn': 64500},
                total=40,
            ),
            TimeoutError('provider timed out'),
        ],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'TimeoutError'
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {
        'api.example.com',
        'dns.example.com',
    }
    assert result.route_values[ResultRoute.IPS] == ('192.0.2.10',)
    assert result.route_values[ResultRoute.ASNS] == ('AS64500',)
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_success_preserves_all_public_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _calls = await _collect(
        monkeypatch,
        [
            _domain_page({'name': 'dns.example.com'}, total=1),
            _host_page(
                {
                    'domain': 'api.example.com',
                    'ip': '192.0.2.10',
                    'asn': 64500,
                    'service': {
                        'banner': 'Contact admin@example.com at "https://portal.example.com/login"',
                    },
                },
                total=1,
            ),
        ],
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {
        'api.example.com',
        'dns.example.com',
        'example.com',
        'portal.example.com',
    }
    assert result.route_values[ResultRoute.EMAILS] == ('admin@example.com',)
    assert result.route_values[ResultRoute.IPS] == ('192.0.2.10',)
    assert result.route_values[ResultRoute.ASNS] == ('AS64500',)
    assert result.route_values[ResultRoute.INTERESTING_URLS] == ('https://portal.example.com/login',)


@pytest.mark.asyncio
async def test_malformed_host_row_retains_usable_values(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _calls = await _collect(
        monkeypatch,
        [
            _domain_page(total=0),
            _host_page({'domain': 'api.example.com'}, 'malformed-row', total=2),
        ],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)


@pytest.mark.asyncio
async def test_malformed_domain_row_retains_usable_values(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _calls = await _collect(
        monkeypatch,
        [
            _domain_page({'name': 'dns.example.com'}, 'malformed-row', total=2),
            _host_page(total=0),
        ],
        remaining=1,
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('dns.example.com',)


@pytest.mark.asyncio
async def test_zero_available_pages_does_not_request_extra_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(
        monkeypatch,
        [
            {'code': 0, 'data': {'available': 0, 'list': []}},
            _host_page(total=0),
        ],
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        pytest.param({'code': 0, 'data': {'available': 'many', 'list': []}}, id='available'),
        pytest.param({'code': 0, 'data': {'total': 'many', 'list': []}}, id='total'),
        pytest.param({'code': 0, 'data': {'total': 1, 'size': 0, 'list': []}}, id='size'),
    ],
)
async def test_malformed_pagination_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    result, _calls = await _collect(
        monkeypatch,
        [payload, _host_page(total=0)],
        remaining=1,
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'


@pytest.mark.asyncio
async def test_duplicate_valid_host_rows_remain_successful(monkeypatch: pytest.MonkeyPatch) -> None:
    record = {'domain': 'api.example.com', 'ip': '192.0.2.10'}
    result, _calls = await _collect(
        monkeypatch,
        [_domain_page(total=0), _host_page(record, record, total=2)],
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert result.route_values[ResultRoute.IPS] == ('192.0.2.10',)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        pytest.param({'code': False, 'data': {'total': 0, 'list': []}}, id='boolean-code'),
        pytest.param({'status': False, 'total': 0, 'list': []}, id='boolean-status'),
    ],
)
async def test_boolean_success_indicator_reports_malformed(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    result, _calls = await _collect(
        monkeypatch,
        [payload, _host_page(total=0)],
        remaining=1,
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'


@pytest.mark.asyncio
async def test_mixed_usable_and_malformed_host_fields_report_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _calls = await _collect(
        monkeypatch,
        [
            _domain_page(total=0),
            _host_page({'domain': 'api.example.com', 'ip': 7}, total=1),
        ],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert result.route_values[ResultRoute.IPS] == ()

from collections.abc import Awaitable, Callable

import pytest

from theHarvester.discovery import windvane
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


async def _collect(
    monkeypatch: pytest.MonkeyPatch,
    fetch: Callable[..., Awaitable[object]],
    *,
    api_key: str | None | Exception = '',
):
    def key_lookup() -> str | None:
        if isinstance(api_key, Exception):
            raise api_key
        return api_key

    monkeypatch.setattr(windvane.Core, 'windvane_key', key_lookup)
    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fetch)
    return await execute_collection(
        'example.com',
        'windvane',
        lambda: windvane.SearchWindvane('example.com'),
    )


def _success(items: list[object]) -> dict[str, object]:
    return {'code': 0, 'data': {'list': items}}


@pytest.mark.asyncio
async def test_unkeyed_provider_error_reports_failed_without_dns_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def fake_post_fetch(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {'code': 401, 'message': 'unauthorized'}

    result = await _collect(monkeypatch, fake_post_fetch)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert result.route_values[ResultRoute.EMAILS] == ()
    assert result.route_values[ResultRoute.IPS] == ()
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'api_key',
    [
        pytest.param('', id='empty'),
        pytest.param('  \t  ', id='whitespace'),
        pytest.param(None, id='null'),
    ],
)
async def test_unkeyed_valid_empty_response_reports_empty(
    monkeypatch: pytest.MonkeyPatch,
    api_key: str | None,
) -> None:
    calls: list[dict[str, object]] = []

    async def fake_post_fetch(*_args: object, **kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return _success([])

    result = await _collect(monkeypatch, fake_post_fetch, api_key=api_key)

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.outcome.process_succeeded is True
    assert all(not values for values in result.route_values.values())
    assert len(calls) == 1
    assert calls[0]['fail_on_http_error'] is True
    assert calls[0]['raise_on_error'] is True
    assert 'X-Api-Key' not in calls[0]['headers']


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        pytest.param('not-json', id='invalid-json'),
        pytest.param(None, id='non-object'),
        pytest.param({'code': 0, 'data': []}, id='non-object-data'),
        pytest.param({'code': 0, 'data': {'list': {}}}, id='non-list-results'),
    ],
)
async def test_unkeyed_malformed_response_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    async def fake_post_fetch(*_args: object, **_kwargs: object) -> object:
        return payload

    result = await _collect(monkeypatch, fake_post_fetch)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert all(not values for values in result.route_values.values())


@pytest.mark.asyncio
async def test_keyed_valid_empty_responses_use_strict_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    async def fake_post_fetch(*_args: object, **kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return _success([])

    result = await _collect(monkeypatch, fake_post_fetch, api_key='test-key')

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.outcome.process_succeeded is True
    assert all(not values for values in result.route_values.values())
    assert len(calls) == 3
    assert all(call['fail_on_http_error'] is True for call in calls)
    assert all(call['raise_on_error'] is True for call in calls)
    assert all(call['headers']['X-Api-Key'] == 'test-key' for call in calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('later_outcome', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='non-success-http'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
        pytest.param({'code': 403, 'message': 'invalid key'}, 'RuntimeError', id='provider-error'),
        pytest.param({'code': 0, 'data': {'list': {}}}, 'ValueError', id='malformed-response'),
    ],
)
async def test_keyed_later_page_failure_retains_sibling_endpoint_values(
    monkeypatch: pytest.MonkeyPatch,
    later_outcome: object,
    error_type: str,
) -> None:
    calls: list[str] = []
    subdomain_calls = 0
    dns_calls = 0

    async def fake_post_fetch(url: str, **_kwargs: object) -> object:
        nonlocal dns_calls, subdomain_calls
        calls.append(url)
        if url.endswith('/ListSubDomain'):
            subdomain_calls += 1
            if subdomain_calls == 1:
                return _success([{'domain': 'api.example.com'}])
            if isinstance(later_outcome, BaseException):
                raise later_outcome
            return later_outcome
        if url.endswith('/ListDNS'):
            dns_calls += 1
            if dns_calls == 1:
                return _success(
                    [
                        {
                            'domain': 'dns.example.com',
                            'answer': '192.0.2.10',
                            'answer_type': 'A',
                        }
                    ]
                )
            return _success([])
        return _success([{'email': 'admin@example.com', 'domain': 'whois.example.com'}])

    result = await _collect(monkeypatch, fake_post_fetch, api_key='test-key')

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == error_type
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {
        'api.example.com',
        'dns.example.com',
        'whois.example.com',
    }
    assert result.route_values[ResultRoute.EMAILS] == ('admin@example.com',)
    assert result.route_values[ResultRoute.IPS] == ('192.0.2.10',)
    assert len(calls) == 5


@pytest.mark.asyncio
async def test_keyed_page_cap_reports_partial_after_completed_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    subdomain_calls = 0

    async def fake_post_fetch(url: str, **_kwargs: object) -> dict[str, object]:
        nonlocal subdomain_calls
        if url.endswith('/ListSubDomain'):
            subdomain_calls += 1
            return _success([{'domain': f'host-{subdomain_calls}.example.com'}])
        return _success([])

    result = await _collect(monkeypatch, fake_post_fetch, api_key='test-key')

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'RuntimeError'
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {
        'host-1.example.com',
        'host-2.example.com',
        'host-3.example.com',
    }
    assert subdomain_calls == 3


@pytest.mark.asyncio
async def test_unkeyed_malformed_row_retains_usable_values(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_post_fetch(*_args: object, **_kwargs: object) -> dict[str, object]:
        return _success([{'domain': 'api.example.com'}, 'malformed-row'])

    result = await _collect(monkeypatch, fake_post_fetch)

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert result.route_values[ResultRoute.EMAILS] == ()
    assert result.route_values[ResultRoute.IPS] == ()


@pytest.mark.asyncio
async def test_api_key_configuration_failure_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def unexpected_request(*_args: object, **_kwargs: object) -> object:
        pytest.fail('Windvane requested the provider after configuration failed')

    result = await _collect(
        monkeypatch,
        unexpected_request,
        api_key=RuntimeError('configuration unavailable'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.process_succeeded is False
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('error', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 429'), 'RuntimeError', id='non-success-http'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
    ],
)
async def test_unkeyed_request_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    error_type: str,
) -> None:
    async def fake_post_fetch(*_args: object, **_kwargs: object) -> object:
        raise error

    result = await _collect(monkeypatch, fake_post_fetch)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert all(not values for values in result.route_values.values())


@pytest.mark.asyncio
async def test_invalid_remote_key_reports_failed_not_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def fake_post_fetch(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {'code': 401, 'message': 'invalid key'}

    result = await _collect(monkeypatch, fake_post_fetch, api_key='invalid-test-key')

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.status is not SourceStatus.SKIPPED
    assert result.outcome.error_type == 'RuntimeError'
    assert all(not values for values in result.route_values.values())
    assert calls == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'invalid_row',
    [
        pytest.param({}, id='missing-domain'),
        pytest.param({'domain': ''}, id='blank-domain'),
        pytest.param({'domain': 7}, id='non-string-domain'),
    ],
)
async def test_unkeyed_invalid_mapping_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    invalid_row: dict[str, object],
) -> None:
    async def fake_post_fetch(*_args: object, **_kwargs: object) -> dict[str, object]:
        return _success([invalid_row])

    result = await _collect(monkeypatch, fake_post_fetch)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert all(not values for values in result.route_values.values())


@pytest.mark.asyncio
async def test_invalid_mapping_retains_later_usable_rows_across_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_post_fetch(url: str, **_kwargs: object) -> dict[str, object]:
        if url.endswith('/ListSubDomain'):
            return _success([{'domain': 7}, {'domain': 'api.example.com'}])
        if url.endswith('/ListDNS'):
            return _success(
                [
                    {'domain': 7, 'answer': '192.0.2.1', 'answer_type': 'A'},
                    {'domain': 'dns.example.com', 'answer': '192.0.2.10', 'answer_type': 'A'},
                ]
            )
        return _success(
            [
                {'email': 7, 'domain': 'ignored.example.com'},
                {'email': 'admin@example.com', 'domain': 'whois.example.com'},
            ]
        )

    result = await _collect(monkeypatch, fake_post_fetch, api_key='test-key')

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {
        'api.example.com',
        'dns.example.com',
        'whois.example.com',
    }
    assert result.route_values[ResultRoute.EMAILS] == ('admin@example.com',)
    assert result.route_values[ResultRoute.IPS] == ('192.0.2.10',)


@pytest.mark.asyncio
async def test_whitespace_key_setter_uses_unkeyed_access(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    async def fake_post_fetch(*_args: object, **kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return _success([])

    monkeypatch.setattr(windvane.Core, 'windvane_key', lambda: 'initial-test-key')
    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fake_post_fetch)
    search = windvane.SearchWindvane('example.com')
    search.set_api_key('  \t  ')

    result = await execute_collection('example.com', 'windvane', lambda: search)

    assert result.outcome.status is SourceStatus.EMPTY
    assert len(calls) == 1
    assert 'X-Api-Key' not in calls[0]['headers']

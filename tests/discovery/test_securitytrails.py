from typing import Any

import pytest

from theHarvester.discovery import securitytrailssearch
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


async def _collect(monkeypatch: pytest.MonkeyPatch, responses: list[Any]):
    monkeypatch.setattr(securitytrailssearch.Core, 'security_trails_key', lambda: 'test-key')
    response_iter = iter(responses)
    calls: list[dict[str, Any]] = []

    async def fake_fetch(**kwargs: Any):
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['raise_on_error'] is True
        assert kwargs['request_timeout'] == 60
        calls.append(kwargs)
        try:
            response = next(response_iter)
        except StopIteration:
            pytest.fail('SecurityTrails requested an unexpected endpoint')
        if isinstance(response, Exception):
            raise response
        return response

    async def reject_fetch_all(*_args: Any, **_kwargs: Any):
        pytest.fail('SecurityTrails must use the strict single-request transport')

    async def fake_sleep(_seconds: int) -> None:
        return None

    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'fetch_all', reject_fetch_all)
    monkeypatch.setattr(securitytrailssearch.asyncio, 'sleep', fake_sleep)
    result = await execute_collection(
        'example.com',
        'securityTrails',
        lambda: securitytrailssearch.SearchSecuritytrail('example.com'),
    )
    return result, calls


@pytest.mark.asyncio
@pytest.mark.parametrize('key', [None, '', ' '])
async def test_missing_key_reports_skipped(monkeypatch: pytest.MonkeyPatch, key: object) -> None:
    monkeypatch.setattr(securitytrailssearch.Core, 'security_trails_key', lambda: key)

    async def unexpected_request(*_args: Any, **_kwargs: Any):
        pytest.fail('SecurityTrails request must not run without a key')

    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'fetch', unexpected_request)
    monkeypatch.setattr(securitytrailssearch.AsyncFetcher, 'fetch_all', unexpected_request)
    result = await execute_collection(
        'example.com',
        'securityTrails',
        lambda: securitytrailssearch.SearchSecuritytrail('example.com'),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
async def test_invalid_remote_key_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = await _collect(monkeypatch, ['Invalid authentication'])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('error', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='http-error'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
    ],
)
async def test_request_failure_reports_failed(monkeypatch: pytest.MonkeyPatch, error: Exception, error_type: str) -> None:
    result, _ = await _collect(monkeypatch, ['{"success": true}', error])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type


@pytest.mark.asyncio
async def test_malformed_domain_response_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = await _collect(monkeypatch, ['{"success": true}', []])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert all(not values for values in result.route_values.values())


@pytest.mark.asyncio
async def test_completed_empty_responses_report_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = await _collect(
        monkeypatch,
        ['{"success": true}', {'current_dns': {}}, {'subdomains': []}],
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: (),
        ResultRoute.IPS: (),
    }


@pytest.mark.asyncio
async def test_provider_error_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = await _collect(
        monkeypatch,
        ['{"success": true}', {'message': 'invalid API key'}],
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        {},
        {'subdomains': {}},
        {'subdomains': ['api', None]},
    ],
)
async def test_malformed_subdomain_response_reports_failed(monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
    result, _ = await _collect(
        monkeypatch,
        ['{"success": true}', {'current_dns': {}}, payload],
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert all(not values for values in result.route_values.values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('failure', 'error_type'),
    [
        pytest.param(TimeoutError('subdomain endpoint timed out'), 'TimeoutError', id='timeout'),
        pytest.param({'message': 'quota exceeded'}, 'RuntimeError', id='provider-error'),
        pytest.param({'subdomains': {}}, 'ValueError', id='malformed'),
    ],
)
async def test_later_endpoint_failure_retains_domain_values(
    monkeypatch: pytest.MonkeyPatch, failure: Any, error_type: str
) -> None:
    domain_response = {
        'apex_domain': 'example.com',
        'current_dns': {'a': {'values': [{'ip': '192.0.2.1'}]}},
    }
    result, _ = await _collect(
        monkeypatch,
        ['{"success": true}', domain_response, failure],
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == error_type
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: (),
        ResultRoute.IPS: ('192.0.2.1',),
    }


@pytest.mark.asyncio
async def test_completed_endpoints_preserve_routes_and_request_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    domain_response = {
        'apex_domain': 'example.com',
        'current_dns': {
            'a': {'values': [{'ip': '192.0.2.1'}]},
            'aaaa': {'values': [{'ipv6': '2001:db8::1'}]},
        },
    }
    result, calls = await _collect(
        monkeypatch,
        ['{"success": true}', domain_response, {'subdomains': ['api', 'www']}],
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'api.example.com', 'www.example.com'}
    assert set(result.route_values[ResultRoute.IPS]) == {'192.0.2.1', '2001:db8::1'}
    assert [call['url'] for call in calls] == [
        'https://api.securitytrails.com/v1/ping',
        'https://api.securitytrails.com/v1/domain/example.com',
        'https://api.securitytrails.com/v1/domain/example.com/subdomains',
    ]
    assert all(call['headers']['APIKEY'] == 'test-key' for call in calls)
    assert all(call['proxy'] is False for call in calls)

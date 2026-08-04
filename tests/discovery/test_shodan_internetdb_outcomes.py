import socket

import pytest

from theHarvester.discovery import shodan_internetdb
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute

_BASE_URL = 'https://internetdb.shodan.io/'
_EMPTY_ROUTES = {
    ResultRoute.SUBDOMAINS: (),
    ResultRoute.IPS: (),
}


async def _collect(monkeypatch: pytest.MonkeyPatch, responses: dict[str, object]):
    monkeypatch.setattr(
        shodan_internetdb.socket,
        'getaddrinfo',
        lambda *_args: [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (ip, 0)) for ip in responses],
    )

    async def fake_fetch(**kwargs: object) -> object:
        assert kwargs['json'] is True
        assert kwargs['proxy'] is False
        assert kwargs['request_timeout'] == 60
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['raise_on_error'] is True
        url = kwargs['url']
        assert isinstance(url, str)
        assert url.startswith(_BASE_URL)
        ip = url.removeprefix(_BASE_URL)
        if ip not in responses:
            pytest.fail(f'unexpected InternetDB IP: {ip}')
        response = responses[ip]
        if isinstance(response, Exception):
            raise response
        return response

    async def reject_fetch_all(*_args: object, **_kwargs: object) -> object:
        pytest.fail('InternetDB must use strict per-IP requests')

    monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', reject_fetch_all)
    return await execute_collection(
        'example.com',
        'shodanInternetDB',
        lambda: shodan_internetdb.SearchShodanInternetDB('example.com'),
    )


@pytest.mark.asyncio
async def test_shodan_internetdb_dns_failure_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_resolution(*_args: object) -> object:
        raise socket.gaierror('offline DNS failure')

    async def unexpected_request(*_args: object, **_kwargs: object) -> object:
        pytest.fail('InternetDB request must not run after DNS failure')

    monkeypatch.setattr(shodan_internetdb.socket, 'getaddrinfo', fail_resolution)
    monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch', unexpected_request)
    monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', unexpected_request)

    result = await execute_collection(
        'example.com',
        'shodanInternetDB',
        lambda: shodan_internetdb.SearchShodanInternetDB('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'gaierror'
    assert result.route_values == _EMPTY_ROUTES


@pytest.mark.asyncio
async def test_shodan_internetdb_no_resolved_addresses_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result = await _collect(monkeypatch, {})

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == _EMPTY_ROUTES


@pytest.mark.asyncio
async def test_shodan_internetdb_timeout_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result = await _collect(monkeypatch, {'192.0.2.10': TimeoutError('provider timed out')})

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'TimeoutError'
    assert result.route_values == _EMPTY_ROUTES


@pytest.mark.asyncio
async def test_shodan_internetdb_retains_completed_ip_before_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    result = await _collect(
        monkeypatch,
        {
            '192.0.2.10': {
                'ip': '192.0.2.10',
                'hostnames': ['api.example.com'],
                'ports': [443],
                'vulns': [],
                'tags': [],
                'cpes': [],
            },
            '198.51.100.20': TimeoutError('provider timed out'),
        },
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'TimeoutError'
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: ('api.example.com',),
        ResultRoute.IPS: ('192.0.2.10',),
    }


@pytest.mark.asyncio
async def test_shodan_internetdb_retains_usable_fields_from_malformed_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = await _collect(
        monkeypatch,
        {
            '192.0.2.10': {
                'ip': '192.0.2.10',
                'hostnames': ['api.example.com'],
                'ports': [True],
                'vulns': [],
                'tags': [],
                'cpes': [],
            },
        },
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: ('api.example.com',),
        ResultRoute.IPS: ('192.0.2.10',),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'response',
    [
        pytest.param({'detail': 'No information available'}, id='detail'),
        pytest.param(RuntimeError('HTTP 404'), id='http-404'),
    ],
)
async def test_shodan_internetdb_no_data_reports_empty(
    monkeypatch: pytest.MonkeyPatch,
    response: object,
) -> None:
    result = await _collect(monkeypatch, {'192.0.2.10': response})

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == _EMPTY_ROUTES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        pytest.param([], id='non-mapping'),
        pytest.param({}, id='empty-mapping'),
        pytest.param({'detail': []}, id='invalid-detail'),
        pytest.param(
            {
                'ip': '192.0.2.10',
                'hostnames': 'api.example.com',
                'ports': [],
                'vulns': [],
                'tags': [],
                'cpes': [],
            },
            id='invalid-hostnames',
        ),
        pytest.param(
            {
                'hostnames': [],
                'ports': [],
                'vulns': [],
                'tags': [],
                'cpes': [],
            },
            id='missing-ip',
        ),
        pytest.param(
            {
                'ip': '192.0.2.10',
                'hostnames': [None],
                'ports': [],
                'vulns': [],
                'tags': [],
                'cpes': [],
            },
            id='invalid-hostname-item',
        ),
        pytest.param(
            {
                'ip': '192.0.2.10',
                'hostnames': [],
                'ports': [True],
                'vulns': [],
                'tags': [],
                'cpes': [],
            },
            id='boolean-port-item',
        ),
    ],
)
async def test_shodan_internetdb_malformed_response_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    result = await _collect(monkeypatch, {'192.0.2.10': payload})

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values == _EMPTY_ROUTES


@pytest.mark.asyncio
async def test_shodan_internetdb_provider_error_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result = await _collect(monkeypatch, {'192.0.2.10': {'error': 'provider rejected request'}})

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values == _EMPTY_ROUTES


@pytest.mark.asyncio
async def test_shodan_internetdb_unrecognized_detail_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result = await _collect(monkeypatch, {'192.0.2.10': {'detail': 'rate limit exceeded'}})

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values == _EMPTY_ROUTES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('error', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='http-error'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
    ],
)
async def test_shodan_internetdb_request_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    error_type: str,
) -> None:
    result = await _collect(monkeypatch, {'192.0.2.10': error})

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values == _EMPTY_ROUTES

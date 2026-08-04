import logging
import sys
import types

import pytest

if 'aiohttp_socks' not in sys.modules:
    aiohttp_socks_stub = types.ModuleType('aiohttp_socks')

    class _ProxyConnector:
        @staticmethod
        def from_url(*_args, **_kwargs):
            return None

    setattr(aiohttp_socks_stub, 'ProxyConnector', _ProxyConnector)
    sys.modules['aiohttp_socks'] = aiohttp_socks_stub

from theHarvester.discovery import sherlockeye
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.run import SourceStatus, execute_collection


def _install_response(monkeypatch, payload, status=200) -> None:
    class _FakeResponse:
        async def json(self):
            return payload

        async def __aenter__(self):
            self.status = status
            return self

        async def __aexit__(self, *_args):
            pass

    class _FakeSession:
        def __init__(self, **_kwargs):
            pass

        def post(self, *_args, **_kwargs):
            return _FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(sherlockeye.aiohttp, 'ClientSession', _FakeSession)


@pytest.mark.asyncio
async def test_missing_key_raises(monkeypatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: None)

    with pytest.raises(MissingKey):
        sherlockeye.SearchSherlockeye('example.com')


@pytest.mark.asyncio
async def test_blank_key_skips_before_request(monkeypatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: '   ')
    monkeypatch.setattr(
        sherlockeye.aiohttp,
        'ClientSession',
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError('provider request attempted')),
    )
    result = await execute_collection(
        'example.com', 'sherlockeye', lambda: sherlockeye.SearchSherlockeye('example.com')
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')
    _install_response(monkeypatch, {'success': True, 'data': {'results': []}})

    result = await execute_collection(
        'example.com', 'sherlockeye', lambda: sherlockeye.SearchSherlockeye('example.com')
    )

    assert result.outcome.status is SourceStatus.EMPTY


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        {'data': {'results': []}},
        {'success': True, 'data': {'results': {}}},
        {'success': True, 'data': {'results': [{'attributes': None}]}},
        {
            'success': True,
            'data': {'results': [{'attributes': {'domain': 'api.example.com'}}, None]},
        },
    ],
)
async def test_malformed_response_reports_failed(monkeypatch, payload) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')
    _install_response(monkeypatch, payload)

    result = await execute_collection(
        'example.com', 'sherlockeye', lambda: sherlockeye.SearchSherlockeye('example.com')
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert all(not values for values in result.route_values.values())


@pytest.mark.asyncio
async def test_transport_error_reports_failed(monkeypatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    class _FailingSession:
        def __init__(self, **_kwargs):
            raise ConnectionError('provider unavailable')

    monkeypatch.setattr(sherlockeye.aiohttp, 'ClientSession', _FailingSession)
    result = await execute_collection(
        'example.com', 'sherlockeye', lambda: sherlockeye.SearchSherlockeye('example.com')
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ConnectionError'


@pytest.mark.asyncio
async def test_process_extracts_domain_intelligence(monkeypatch) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    api_payload = {
        'success': True,
        'data': {
            'searchId': 'search-1',
            'type': 'domain',
            'value': 'example.com',
            'timeoutSeconds': 60,
            'status': 'complete',
            'progress': 100,
            'results': [
                {
                    'id': 'result-1',
                    'source': 'provider-a',
                    'attributes': {
                        'domain': 'sub.example.com',
                        'email': 'user@example.com',
                        'ip': '203.0.113.10',
                        'link': 'https://www.example.com/path',
                    },
                },
                {
                    'id': 'result-2',
                    'source': 'provider-b',
                    'attributes': {
                        'email': 'other@not-example.org',
                        'link': 'https://api.example.com/docs',
                    },
                },
            ],
        },
        'balance': {'credits': 10},
    }

    _install_response(monkeypatch, api_payload)

    search = sherlockeye.SearchSherlockeye('example.com')
    await search.process()

    assert await search.get_hostnames() == {'sub.example.com', 'example.com', 'api.example.com'}
    assert await search.get_emails() == {'user@example.com'}
    assert await search.get_ips() == {'203.0.113.10'}


@pytest.mark.asyncio
async def test_process_handles_api_error(monkeypatch, caplog) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    _install_response(monkeypatch, 'provider-secret-payload', status=401)
    caplog.set_level(logging.INFO, logger=sherlockeye.__name__)

    result = await execute_collection(
        'example.com', 'sherlockeye', lambda: sherlockeye.SearchSherlockeye('example.com')
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert 'provider-secret-payload' not in caplog.text
    assert '401' in caplog.text


@pytest.mark.asyncio
async def test_process_does_not_log_provider_error_message(monkeypatch, caplog) -> None:
    monkeypatch.setattr(sherlockeye.Core, 'sherlockeye_key', lambda: 'dummy-key')

    _install_response(monkeypatch, {'success': False, 'message': 'provider-secret-payload'})
    caplog.set_level(logging.INFO, logger=sherlockeye.__name__)

    result = await execute_collection(
        'example.com', 'sherlockeye', lambda: sherlockeye.SearchSherlockeye('example.com')
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert 'provider-secret-payload' not in caplog.text
    assert 'API error' in caplog.text

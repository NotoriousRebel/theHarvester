import sys
import types
from typing import Any

import pytest

if 'aiohttp_socks' not in sys.modules:
    aiohttp_socks_stub = types.ModuleType('aiohttp_socks')

    class _ProxyConnector:
        @staticmethod
        def from_url(*_args, **_kwargs):
            return None

    setattr(aiohttp_socks_stub, 'ProxyConnector', _ProxyConnector)
    sys.modules['aiohttp_socks'] = aiohttp_socks_stub

from theHarvester.discovery import rocketreach
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


def _profile(index: int) -> dict[str, Any]:
    return {
        'linkedin_url': f'https://linkedin.example/in/user{index}',
        'emails': [{'email': f'user{index}@example.com'}],
    }


async def _collect(monkeypatch: pytest.MonkeyPatch, responses: list[Any], limit: int = 10):
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: 'test-key')
    response_iter = iter(responses)
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake_post_fetch(url: str, **kwargs: Any):
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['raise_on_error'] is True
        calls.append((url, kwargs))
        try:
            response = next(response_iter)
        except StopIteration:
            pytest.fail('RocketReach requested an unexpected page')
        if isinstance(response, Exception):
            raise response
        return response

    async def fake_sleep(_seconds: int) -> None:
        return None

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(rocketreach.asyncio, 'sleep', fake_sleep)
    result = await execute_collection('example.com', 'rocketreach', lambda: rocketreach.SearchRocketReach('example.com', limit))
    return result, calls


@pytest.mark.asyncio
@pytest.mark.parametrize('key', ['', ' '])
async def test_blank_key_reports_skipped(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: key)

    async def unexpected_request(*_args, **_kwargs):
        pytest.fail('RocketReach request must not run without a key')

    monkeypatch.setattr(rocketreach.AsyncFetcher, 'post_fetch', unexpected_request)
    result = await execute_collection('example.com', 'rocketreach', lambda: rocketreach.SearchRocketReach('example.com', 10))

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('error', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 503'), 'RuntimeError', id='http-error'),
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
    ],
)
async def test_request_failures_report_failed(monkeypatch: pytest.MonkeyPatch, error: Exception, error_type: str) -> None:
    result, _ = await _collect(monkeypatch, [error])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type


@pytest.mark.asyncio
async def test_completed_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = await _collect(monkeypatch, [{'profiles': [], 'pagination': {'total': 0}}])

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values[ResultRoute.EMAILS] == ()
    assert result.route_values[ResultRoute.LINKS] == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        pytest.param(
            {'detail': 'Subscribe to a plan to access this endpoint.'},
            'RuntimeError',
            id='subscription',
        ),
        pytest.param(
            {'detail': 'Request was throttled. Credits will become available later.'},
            'RuntimeError',
            id='throttle',
        ),
        pytest.param({'detail': 'Invalid API key.'}, 'RuntimeError', id='provider-error'),
        pytest.param([], 'ValueError', id='non-object'),
        pytest.param({}, 'ValueError', id='missing-profiles'),
    ],
)
async def test_provider_failures_report_failed(monkeypatch: pytest.MonkeyPatch, response: Any, error_type: str) -> None:
    result, _ = await _collect(monkeypatch, [response])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        pytest.param({'profiles': [_profile(0), None]}, 'ValueError', id='profile'),
        pytest.param(
            {'profiles': [{'linkedin_url': 42, 'emails': []}]},
            'ValueError',
            id='profile-fields',
        ),
        pytest.param(
            {'profiles': [_profile(0)], 'pagination': None},
            'ValueError',
            id='pagination',
        ),
    ],
)
async def test_malformed_page_does_not_commit_results(monkeypatch: pytest.MonkeyPatch, response: Any, error_type: str) -> None:
    result, _ = await _collect(monkeypatch, [response])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values[ResultRoute.EMAILS] == ()
    assert result.route_values[ResultRoute.LINKS] == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('failure', 'error_type'),
    [
        pytest.param(TimeoutError('later page timed out'), 'TimeoutError', id='timeout'),
        pytest.param({'profiles': [], 'pagination': None}, 'ValueError', id='malformed-empty-page'),
    ],
)
async def test_later_page_failure_retains_completed_page(
    monkeypatch: pytest.MonkeyPatch, failure: Any, error_type: str
) -> None:
    first_page = {
        'profiles': [_profile(index) for index in range(100)],
        'pagination': {'total': 101},
    }
    result, calls = await _collect(
        monkeypatch,
        [first_page, failure],
        limit=101,
    )

    assert len(calls) == 2
    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == error_type
    assert len(result.route_values[ResultRoute.EMAILS]) == 100
    assert len(result.route_values[ResultRoute.LINKS]) == 100


@pytest.mark.asyncio
async def test_missing_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rocketreach.Core, 'rocketreach_key', lambda: None)
    with pytest.raises(MissingKey):
        rocketreach.SearchRocketReach('example.com', 10)


@pytest.mark.asyncio
async def test_search_uses_people_endpoint_and_start_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rocketreach.Core, 'get_user_agent', lambda: 'test-agent')
    responses = [
        {
            'profiles': [_profile(index) for index in range(100)],
            'pagination': {'page': 1, 'total': 150},
        },
        {
            'profiles': [_profile(index) for index in range(100, 150)],
            'pagination': {'page': 2, 'total': 150},
        },
    ]
    result, calls = await _collect(monkeypatch, responses, limit=150)

    assert len(calls) == 2
    first_url, first_kwargs = calls[0]
    second_url, second_kwargs = calls[1]
    assert first_url == 'https://api.rocketreach.co/api/v2/person/search'
    assert second_url == first_url
    assert first_kwargs['headers']['Api-Key'] == 'test-key'
    assert first_kwargs['headers']['User-Agent'] == 'test-agent'
    assert first_kwargs['json'] is True
    assert first_kwargs['data'] == {
        'query': {'current_employer_domain': ['example.com']},
        'start': 0,
        'page_size': 100,
    }
    assert second_kwargs['data'] == {
        'query': {'current_employer_domain': ['example.com']},
        'start': 100,
        'page_size': 50,
    }
    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert len(result.route_values[ResultRoute.EMAILS]) == 150
    assert len(result.route_values[ResultRoute.LINKS]) == 150

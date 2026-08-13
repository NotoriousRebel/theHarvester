from __future__ import annotations

import asyncio
import json
import sys
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.discovery import hudsonrocksearch
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib import source_runner
from theHarvester.lib.core import FetcherResponse

if TYPE_CHECKING:
    from pathlib import Path

    from theHarvester.lib.completed_result import CompletedResult


async def _no_sleep(_delay: float) -> None:
    return None


@pytest.mark.asyncio
async def test_v3_paginates_both_endpoints_and_sanitizes_target_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object], dict[str, str]]] = []
    credential = {
        'url': 'https://portal.example.com/reset/secret-token?session=never-export#private',
        'domain': 'example.com',
        'username': 'employee@example.com',
        'password': 'never-export',
        'cookie': 'never-export',
        'type': 'employee',
    }
    responses = [
        {
            'data': [{'url': 'https://portal.example.com/discovery/secret-token?session=never-export'}],
            'nextCursor': 'discovery-next',
        },
        {'data': [{'url': 'https://portal.example.com/duplicate'}]},
        {
            'data': [
                {
                    '_id': 'ABCDEF0123456789ABCDEF01',
                    'stealer_family': 'Lumma',
                    'date_compromised': '2026-01-01T00:00:00Z',
                    'date_uploaded': '2026-01-02T00:00:00Z',
                    'ip': '192.0.2.1',
                    'computer_name': 'WORKSTATION',
                    'operating_system': 'Windows 11',
                    'antiviruses': [{'name': 'Defender', 'engine': 'never-export'}],
                    'malware_path': '/never/export',
                    'sensitive_applications': [{'name': 'Okta', 'description': 'never-export'}],
                    'credentials': [credential, dict(credential)],
                }
            ],
            'nextCursor': 'search-next',
        },
        {
            'data': [
                {
                    'credentials': [
                        {
                            'url': 'https://outside.invalid/login',
                            'domain': 'outside.invalid',
                            'username': 'other@outside.invalid',
                            'password': 'never-export',
                        }
                    ]
                }
            ]
        },
    ]

    async def fake_fetch_json(url: str, **kwargs: Any) -> FetcherResponse:
        assert kwargs['method'] == 'POST'
        assert kwargs['request_timeout'] <= search.MAX_RUNTIME_SECONDS
        calls.append((url, kwargs['json_body'], kwargs['headers']))
        return FetcherResponse(body=responses.pop(0), status=200, headers={})

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', _no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert [url for url, _payload, _headers in calls] == [
        search.DISCOVERY_URL,
        search.DISCOVERY_URL,
        search.SEARCH_URL,
        search.SEARCH_URL,
    ]
    assert calls[1][1]['cursor'] == 'discovery-next'
    assert calls[3][1]['cursor'] == 'search-next'
    assert calls[2][1]['filter_credentials'] is True
    assert calls[2][1]['additional_fields'] == ['sensitive_applications']
    assert all(headers['api-key'] == 'test-key' for _url, _payload, headers in calls)
    assert await search.get_hostnames() == {'portal.example.com'}
    assert await search.get_urls() == {'https://portal.example.com'}
    assert await search.get_emails() == {'employee@example.com'}
    assert await search.get_ips() == set()
    assert await search.get_credential_exposures() == [
        {
            'compromised_endpoint': {
                'antivirus_products': ['Defender'],
                'computer_name': 'WORKSTATION',
                'ip': '192.0.2.1',
                'operating_system': 'Windows 11',
            },
            'credential_count': 2,
            'credential_type': 'employee',
            'date_compromised': '2026-01-01T00:00:00Z',
            'date_uploaded': '2026-01-02T00:00:00Z',
            'domain': 'example.com',
            'employee_email': 'employee@example.com',
            'exposure_category': 'employee',
            'provider': 'hudsonrock-v3',
            'provider_record_id': 'abcdef0123456789abcdef01',
            'sensitive_applications': ['Okta'],
            'stealer_family': 'Lumma',
            'url': 'https://portal.example.com',
        }
    ]
    assert await search.get_infostealers() == [
        {
            'antiviruses': ['Defender'],
            'computer_name': 'WORKSTATION',
            'date_compromised': '2026-01-01T00:00:00Z',
            'email': 'employee@example.com',
            'ip': '192.0.2.1',
            'operating_system': 'Windows 11',
            'top_corporate_services': ['Okta'],
        }
    ]
    serialized = json.dumps(await search.get_credential_exposures())
    assert all(secret not in serialized for secret in ('never-export', 'secret-token', 'malware_path', 'description'))


def test_missing_hudsonrock_key_is_skipped_at_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: None))
    with pytest.raises(MissingKey):
        hudsonrocksearch.SearchHudsonRock('example.com')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('status', 'expected_status', 'expected_reason', 'expected_calls'),
    [
        (401, 'failed', 'access-denied', 1),
        (408, 'failed', 'timeout', 3),
        (429, 'rate-limited', 'rate-limit', 3),
        (500, 'failed', 'server-failure', 3),
    ],
)
async def test_v3_failure_outcomes_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    expected_status: str,
    expected_reason: str,
    expected_calls: int,
) -> None:
    calls = 0

    async def fake_post(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        nonlocal calls
        calls += 1
        return FetcherResponse(body={}, status=status, headers={})

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', fake_post)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', _no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert calls == expected_calls
    assert search.execution_status == expected_status
    assert search.stop_reason == expected_reason
    assert await search.get_credential_exposures() == []


@pytest.mark.asyncio
async def test_v3_retries_transport_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    responses: list[FetcherResponse | None] = [
        None,
        FetcherResponse(body={'data': []}, status=200, headers={}),
        FetcherResponse(body={'data': []}, status=200, headers={}),
    ]

    async def fake_post(*_args: Any, **_kwargs: Any) -> FetcherResponse | None:
        return responses.pop(0)

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', fake_post)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', _no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert not responses
    assert search.execution_status == 'completed'
    assert search.stop_reason == 'no-results'


@pytest.mark.asyncio
async def test_v3_rejected_credentials_discard_discovery_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        FetcherResponse(body={'data': [{'url': 'https://portal.example.com/private'}]}, status=200, headers={}),
        FetcherResponse(body={}, status=403, headers={}),
    ]

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'rejected-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', _no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'access-denied'
    assert await search.get_hostnames() == set()
    assert await search.get_urls() == set()


@pytest.mark.asyncio
async def test_v3_rejects_oversized_provider_response(monkeypatch: pytest.MonkeyPatch) -> None:
    async def too_large(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise hudsonrocksearch.ResponseStreamError('response-limit')

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', too_large)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'response-limit'


@pytest.mark.asyncio
async def test_v3_reports_malformed_json(monkeypatch: pytest.MonkeyPatch) -> None:
    async def malformed(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise hudsonrocksearch.ResponseStreamError('invalid-response')

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', malformed)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_v3_preserves_partial_evidence_on_malformed_follow_up(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        {'data': [{'url': 'https://portal.example.com/private'}], 'nextCursor': 'next'},
        {'data': 'not-a-list'},
    ]

    async def fake_post(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body=responses.pop(0), status=200, headers={})

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', fake_post)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', _no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert search.execution_status == 'partial'
    assert search.stop_reason == 'malformed-data'
    assert await search.get_urls() == {'https://portal.example.com'}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('data', 'expected_status'),
    [
        (['not-an-object'], 'failed'),
        ([{}], 'failed'),
        ([{'url': 'https://portal.example.com/private'}, 'not-an-object'], 'partial'),
    ],
)
async def test_v3_reports_malformed_provider_rows(
    monkeypatch: pytest.MonkeyPatch,
    data: list[object],
    expected_status: str,
) -> None:
    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body={'data': data}, status=200, headers={})

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert search.execution_status == expected_status
    assert search.stop_reason == 'malformed-data'


@pytest.mark.asyncio
async def test_v3_reports_malformed_search_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        FetcherResponse(body={'data': []}, status=200, headers={}),
        FetcherResponse(body={'data': [{'credentials': 'not-a-list'}]}, status=200, headers={}),
    ]

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', _no_sleep)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'malformed-data'


@pytest.mark.asyncio
async def test_v3_enforces_request_and_result_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def fake_post(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        nonlocal calls
        calls += 1
        return FetcherResponse(body={'data': [{'url': 'https://portal.example.com/private'}]}, status=200, headers={})

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', fake_post)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', _no_sleep)
    monkeypatch.setattr(hudsonrocksearch.SearchHudsonRock, 'MAX_REQUESTS', 1)
    request_limited = hudsonrocksearch.SearchHudsonRock('example.com')
    await request_limited.process()

    assert calls == 1
    assert request_limited.execution_status == 'partial'
    assert request_limited.stop_reason == 'request-limit'

    calls = 0
    monkeypatch.setattr(hudsonrocksearch.SearchHudsonRock, 'MAX_REQUESTS', 20)
    monkeypatch.setattr(hudsonrocksearch.SearchHudsonRock, 'MAX_RESULTS', 1)
    result_limited = hudsonrocksearch.SearchHudsonRock('example.com')
    await result_limited.process()

    assert calls == 1
    assert result_limited.execution_status == 'partial'
    assert result_limited.stop_reason == 'result-limit'


@pytest.mark.asyncio
async def test_v3_bounds_detailed_results_before_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        FetcherResponse(body={'data': []}, status=200, headers={}),
        FetcherResponse(
            body={
                'data': [
                    {
                        'credentials': [
                            {'url': 'https://outside.invalid/private', 'type': 'employee'},
                            *[
                                {'url': f'https://{name}.example.com/private', 'type': 'employee'}
                                for name in ('one', 'one', 'two', 'three')
                            ],
                        ]
                    }
                ]
            },
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch_json(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', fake_fetch_json)
    monkeypatch.setattr(hudsonrocksearch.asyncio, 'sleep', _no_sleep)
    monkeypatch.setattr(hudsonrocksearch.SearchHudsonRock, 'MAX_RESULTS', 2)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert search.execution_status == 'partial'
    assert search.stop_reason == 'result-limit'
    assert await search.get_hostnames() == {'one.example.com', 'two.example.com'}
    assert len(await search.get_credential_exposures()) == 2
    assert {item['exposure_category'] for item in await search.get_credential_exposures()} == {'employee'}


@pytest.mark.asyncio
async def test_v3_enforces_runtime_limit_during_request(monkeypatch: pytest.MonkeyPatch) -> None:
    async def never_returns(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        await asyncio.Event().wait()
        raise AssertionError('unreachable')

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', never_returns)
    monkeypatch.setattr(hudsonrocksearch.SearchHudsonRock, 'MAX_RUNTIME_SECONDS', 0.01)
    search = hudsonrocksearch.SearchHudsonRock('example.com')

    await search.process()

    assert search.execution_status == 'failed'
    assert search.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_v3_propagates_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    async def cancelled(*_args: Any, **_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(hudsonrocksearch.Core, 'hudsonrock_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(hudsonrocksearch.AsyncFetcher, 'fetch_json', cancelled)
    with pytest.raises(asyncio.CancelledError):
        await hudsonrocksearch.SearchHudsonRock('example.com').process()


@pytest.mark.asyncio
async def test_sanitized_exposure_keeps_separate_legacy_projection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed_results: list[CompletedResult] = []

    class FakeResultStore:
        async def initialize(self) -> None:
            return None

        async def record_observations(self, *_args: object) -> None:
            return None

        async def save_run(self, result: CompletedResult) -> None:
            completed_results.append(result)

    class FakeHudsonRock:
        def __init__(self, _target: str) -> None:
            return None

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return set()

        async def get_emails(self) -> set[str]:
            return set()

        async def get_urls(self) -> set[str]:
            return set()

        async def get_credential_exposures(self) -> list[dict[str, object]]:
            return [{'provider': 'hudsonrock-v3', 'url': 'https://portal.example.com'}]

        async def get_infostealers(self) -> list[dict[str, object]]:
            return [{'email': 'employee@example.com'}]

    report = tmp_path / 'hudsonrock-report'
    monkeypatch.setattr(theharvester_main, 'ResultStore', FakeResultStore)
    monkeypatch.setattr(source_runner.hudsonrocksearch, 'SearchHudsonRock', FakeHudsonRock)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'hudsonrock', '-f', str(report)])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert ('credential-exposure', '{"provider":"hudsonrock-v3","url":"https://portal.example.com"}') in completed_results[
        0
    ].results
    assert ('infostealer', '{"email":"employee@example.com"}') in completed_results[0].results
    assert completed_results[0].source_executions[0].source == 'hudsonrock'
    assert completed_results[0].source_executions[0].status == 'completed'
    assert completed_results[0].source_executions[0].result_count == 2
    assert {observation.source for observation in completed_results[0].observations} == {'hudsonrock'}
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert {record['type'] for record in records} >= {'credential-exposure', 'infostealer'}

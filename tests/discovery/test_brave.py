from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from theHarvester.discovery import bravesearch
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


def _result(index: int) -> dict[str, str]:
    return {
        'title': f'Result {index}',
        'description': f'host-{index}.example.com ops@example.com',
        'url': f'https://host-{index}.example.com',
    }


def _response(results: list[dict[str, str]], *, more: bool) -> dict[str, Any]:
    return {
        'query': {'more_results_available': more},
        'web': {'results': results},
    }


@pytest.fixture
def brave_credentials() -> InMemoryCredentialAdapter:
    return InMemoryCredentialAdapter({'brave': {'key': 'test-token'}})


@pytest.fixture(autouse=True)
def no_brave_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(bravesearch.asyncio, 'sleep', no_sleep)


@pytest.mark.asyncio
async def test_brave_uses_page_offsets_and_one_global_limit(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response([_result(index) for index in range(20)], more=True),
            _response([_result(index) for index in range(20, 30)], more=True),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(parse_qs(urlparse(url).query))
        assert _kwargs['raise_on_error'] is True
        return next(responses)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 25, credential_adapter=brave_credentials)
    await search.process()

    assert requests == [
        {
            'q': ['"example.com"'],
            'count': ['20'],
            'offset': ['0'],
            'safesearch': ['off'],
            'freshness': ['all'],
            'extra_snippets': ['true'],
            'text_decorations': ['true'],
            'spellcheck': ['true'],
        },
        {
            'q': ['"example.com"'],
            'count': ['5'],
            'offset': ['1'],
            'safesearch': ['off'],
            'freshness': ['all'],
            'extra_snippets': ['true'],
            'text_decorations': ['true'],
            'spellcheck': ['true'],
        },
    ]
    assert len(search.results) == 25
    assert set(await search.get_hostnames()) == {'example.com'} | {f'host-{index}.example.com' for index in range(25)}
    assert set(await search.get_emails()) == {'ops@example.com'}


@pytest.mark.asyncio
async def test_brave_requests_another_page_only_when_available(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response([_result(1)], more=False),
            _response([_result(2)], more=False),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(parse_qs(urlparse(url).query))
        return next(responses, _response([], more=False))

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 10, credential_adapter=brave_credentials)
    await search.process()

    assert [(request['q'], request['offset'], request['count']) for request in requests] == [
        (['"example.com"'], ['0'], ['10']),
        (['site:example.com'], ['0'], ['9']),
    ]


@pytest.mark.asyncio
async def test_brave_continues_sparse_pages_while_more_results_are_available(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    responses = iter(
        [
            _response([_result(1)], more=True),
            _response([_result(index) for index in range(2, 21)], more=False),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(parse_qs(urlparse(url).query))
        return next(responses)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials)
    await search.process()

    assert [(request['offset'], request['count']) for request in requests] == [
        (['0'], ['20']),
        (['1'], ['19']),
    ]
    assert len(search.results) == 20


@pytest.mark.asyncio
async def test_brave_stops_after_an_exact_full_page(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(parse_qs(urlparse(url).query))
        return _response([_result(index) for index in range(20)], more=True)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials)
    await search.process()

    assert [(request['offset'], request['count']) for request in requests] == [(['0'], ['20'])]


@pytest.mark.asyncio
async def test_brave_rate_limit_reports_failure_without_another_request(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(parse_qs(urlparse(url).query))
        return {'error': {'message': 'Rate limit exceeded', 'code': 'rate_limit_exceeded'}}

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'brave',
        lambda: bravesearch.SearchBrave('example.com', 40, credential_adapter=brave_credentials),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert [(request['q'], request['offset']) for request in requests] == [(['"example.com"'], ['0'])]


@pytest.mark.asyncio
async def test_brave_never_exceeds_maximum_page_offset(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(parse_qs(urlparse(url).query))
        return _response([_result(len(requests))], more=True)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 1_000, credential_adapter=brave_credentials)
    await search.process()

    assert [request['offset'] for request in requests] == [[str(offset)] for offset in range(10)] * 2


@pytest.mark.asyncio
async def test_brave_valid_empty_response_reports_empty(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[str] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(url)
        return _response([], more=False)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'brave',
        lambda: bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials),
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_brave_missing_credentials_skip_before_request(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[str] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(url)
        return _response([], more=False)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'brave',
        lambda: bravesearch.SearchBrave(
            'example.com',
            20,
            credential_adapter=InMemoryCredentialAdapter({'brave': {'key': ''}}),
        ),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'
    assert requests == []


@pytest.mark.asyncio
async def test_brave_malformed_first_page_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        return {'web': {}}

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'brave',
        lambda: bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'


@pytest.mark.asyncio
async def test_brave_empty_page_requires_pagination_signal(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        return {'web': {'results': []}}

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'brave',
        lambda: bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'


@pytest.mark.asyncio
async def test_brave_malformed_pagination_retains_page_results(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        return {'web': {'results': [_result(1)]}}

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'brave',
        lambda: bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials),
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'example.com', 'host-1.example.com'}
    assert result.route_values[ResultRoute.EMAILS] == ('ops@example.com',)


@pytest.mark.asyncio
async def test_brave_timeout_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> dict[str, Any]:
        raise TimeoutError('provider timed out')

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'brave',
        lambda: bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'TimeoutError'


@pytest.mark.asyncio
async def test_brave_later_page_failure_retains_results(
    monkeypatch: pytest.MonkeyPatch,
    brave_credentials: InMemoryCredentialAdapter,
) -> None:
    requests: list[str] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(url)
        if len(requests) == 1:
            return _response([_result(1)], more=True)
        raise RuntimeError('HTTP 503')

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'brave',
        lambda: bravesearch.SearchBrave('example.com', 20, credential_adapter=brave_credentials),
    )

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'RuntimeError'
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'example.com', 'host-1.example.com'}
    assert len(requests) == 2

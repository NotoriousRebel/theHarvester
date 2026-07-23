from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from theHarvester.discovery import bravesearch
from theHarvester.discovery.constants import MissingKey


def _result(index: int) -> dict[str, str]:
    return {
        'title': f'Result {index}',
        'description': f'host-{index}.example.com',
        'url': f'https://host-{index}.example.com',
    }


def _response(results: list[dict[str, str]], *, more: bool) -> dict[str, Any]:
    return {
        'query': {'more_results_available': more},
        'web': {'results': results},
    }


@pytest.fixture
def brave_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bravesearch.Core, 'brave_key', staticmethod(lambda: 'test-token'))


@pytest.fixture(autouse=True)
def no_brave_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(bravesearch.asyncio, 'sleep', no_sleep)


def test_brave_requires_an_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bravesearch.Core, 'brave_key', staticmethod(lambda: ''))

    with pytest.raises(MissingKey, match='Brave Search'):
        bravesearch.SearchBrave('example.com', 10)


@pytest.mark.asyncio
async def test_brave_normalizes_in_scope_evidence_and_handles_error_response(
    monkeypatch: pytest.MonkeyPatch,
    brave_key: None,
) -> None:
    responses = iter(
        [
            _response(
                [
                    {
                        'title': 'Contact Admin@Example.COM.',
                        'description': 'Ignore outsider@notexample.com and api.notexample.com',
                        'url': 'https://Blog.Example.COM./contact',
                    }
                ],
                more=False,
            ),
            {'error': {'message': 'Access denied', 'code': 'forbidden'}},
        ]
    )

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        return next(responses)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 10)
    await search.process(proxy=True)

    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == ['blog.example.com', 'example.com']


@pytest.mark.parametrize('response', [None, []], ids=['empty', 'malformed'])
@pytest.mark.asyncio
async def test_brave_unusable_response_returns_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    brave_key: None,
    response: list[Any] | None,
) -> None:
    async def fake_fetch(*, url: str, **_kwargs: Any) -> list[Any] | None:
        return response

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 10)
    await search.process()

    assert await search.get_emails() == set()
    assert await search.get_hostnames() == []


@pytest.mark.asyncio
async def test_brave_uses_page_offsets_and_one_global_limit(
    monkeypatch: pytest.MonkeyPatch,
    brave_key: None,
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
        return next(responses)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 25)
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


@pytest.mark.asyncio
async def test_brave_requests_another_page_only_when_available(
    monkeypatch: pytest.MonkeyPatch,
    brave_key: None,
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
    search = bravesearch.SearchBrave('example.com', 40)
    await search.process()

    assert [(request['q'], request['offset']) for request in requests] == [
        (['"example.com"'], ['0']),
        (['site:example.com'], ['0']),
    ]


@pytest.mark.asyncio
async def test_brave_continues_sparse_pages_while_more_results_are_available(
    monkeypatch: pytest.MonkeyPatch,
    brave_key: None,
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
    search = bravesearch.SearchBrave('example.com', 20)
    await search.process()

    assert [(request['offset'], request['count']) for request in requests] == [
        (['0'], ['20']),
        (['1'], ['19']),
    ]
    assert len(search.results) == 20


@pytest.mark.asyncio
async def test_brave_stops_after_an_exact_full_page(
    monkeypatch: pytest.MonkeyPatch,
    brave_key: None,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(parse_qs(urlparse(url).query))
        return _response([_result(index) for index in range(20)], more=True)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 20)
    await search.process()

    assert [(request['offset'], request['count']) for request in requests] == [(['0'], ['20'])]


@pytest.mark.asyncio
async def test_brave_rate_limit_does_not_skip_to_the_next_page(
    monkeypatch: pytest.MonkeyPatch,
    brave_key: None,
) -> None:
    responses = iter(
        [
            {'error': {'message': 'Rate limit exceeded', 'code': 'rate_limit_exceeded'}},
            _response([], more=False),
        ]
    )
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(parse_qs(urlparse(url).query))
        return next(responses)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 40)
    await search.process()

    assert [(request['q'], request['offset']) for request in requests] == [
        (['"example.com"'], ['0']),
        (['site:example.com'], ['0']),
    ]


@pytest.mark.asyncio
async def test_brave_never_exceeds_maximum_page_offset(
    monkeypatch: pytest.MonkeyPatch,
    brave_key: None,
) -> None:
    requests: list[dict[str, list[str]]] = []

    async def fake_fetch(*, url: str, **_kwargs: Any) -> dict[str, Any]:
        requests.append(parse_qs(urlparse(url).query))
        return _response([_result(len(requests))], more=True)

    monkeypatch.setattr(bravesearch.AsyncFetcher, 'fetch', fake_fetch)
    search = bravesearch.SearchBrave('example.com', 1_000)
    await search.process()

    assert [request['offset'] for request in requests] == [[str(offset)] for offset in range(10)] * 2

from typing import Any

import pytest

from theHarvester.discovery import githubcode
from theHarvester.discovery.constants import MissingKey


@pytest.fixture(autouse=True)
def github_code_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(githubcode.Core, 'github_key', staticmethod(lambda: 'test-token'))
    monkeypatch.setattr(githubcode.Core, 'get_user_agent', staticmethod(lambda: 'UA'))
    monkeypatch.setattr(githubcode.asyncio, 'sleep', no_sleep)


@pytest.mark.parametrize('api_key', [None, ''], ids=['missing', 'empty'])
def test_github_code_requires_a_nonempty_api_key(
    monkeypatch: pytest.MonkeyPatch,
    api_key: str | None,
) -> None:
    monkeypatch.setattr(githubcode.Core, 'github_key', staticmethod(lambda: api_key))

    with pytest.raises(MissingKey, match='Github'):
        githubcode.SearchGithubCode('example.com', limit=10)


@pytest.mark.asyncio
async def test_github_code_enforces_global_fragment_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_pages: list[int] = []
    responses: dict[int, tuple[str, dict[str, Any], int, dict[str, dict[str, str]]]] = {
        1: (
            '',
            {
                'items': [
                    {'text_matches': [{'fragment': 'Contact Admin@Example.COM.'}]},
                    {'text_matches': [{'fragment': 'API host api.example.com'}]},
                ]
            },
            200,
            {
                'next': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
                'last': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
            },
        ),
        2: (
            '',
            {
                'items': [
                    {'text_matches': [{'fragment': 'Docs host docs.example.com'}]},
                    {'text_matches': [{'fragment': 'Ignored host ignored.example.com'}]},
                ]
            },
            200,
            {},
        ),
    }

    async def fake_do_search(page: int) -> tuple[str, dict[str, Any], int, dict[str, dict[str, str]]]:
        requested_pages.append(page)
        return responses[page]

    search = githubcode.SearchGithubCode('example.com', limit=3)
    monkeypatch.setattr(search, 'do_search', fake_do_search)
    await search.process()

    assert requested_pages == [1, 2]
    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == [
        'api.example.com',
        'docs.example.com',
        'example.com',
    ]


@pytest.mark.asyncio
async def test_github_code_exact_limit_makes_no_extra_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_pages: list[int] = []

    async def fake_do_search(page: int) -> tuple[str, dict[str, Any], int, dict[str, dict[str, str]]]:
        requested_pages.append(page)
        return (
            '',
            {
                'items': [
                    {'text_matches': [{'fragment': 'api.example.com'}]},
                    {'text_matches': [{'fragment': 'docs.example.com'}]},
                ]
            },
            200,
            {
                'next': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
                'last': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
            },
        )

    search = githubcode.SearchGithubCode('example.com', limit=2)
    monkeypatch.setattr(search, 'do_search', fake_do_search)
    await search.process()

    assert requested_pages == [1]
    assert await search.get_hostnames() == ['api.example.com', 'docs.example.com']


@pytest.mark.asyncio
async def test_github_code_keeps_fragments_separate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_do_search(_page: int) -> tuple[str, dict[str, Any], int, dict[str, Any]]:
        return (
            '',
            {
                'items': [
                    {
                        'text_matches': [
                            {'fragment': 'admin'},
                            {'fragment': '@example.com'},
                        ]
                    }
                ]
            },
            200,
            {},
        )

    search = githubcode.SearchGithubCode('example.com', limit=10)
    monkeypatch.setattr(search, 'do_search', fake_do_search)
    await search.process()

    assert await search.get_emails() == set()


@pytest.mark.asyncio
async def test_github_code_ignores_non_string_fragments_without_retrying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_pages: list[int] = []

    async def fake_do_search(page: int) -> tuple[str, dict[str, Any], int, dict[str, Any]]:
        requested_pages.append(page)
        if len(requested_pages) > 1:
            return '', {}, 500, {}
        return (
            '',
            {
                'items': [
                    {
                        'text_matches': [
                            {'fragment': None},
                            {'fragment': 42},
                            {'fragment': ''},
                            {'fragment': 'API host api.example.com'},
                        ]
                    }
                ]
            },
            200,
            {},
        )

    search = githubcode.SearchGithubCode('example.com', limit=10)
    monkeypatch.setattr(search, 'do_search', fake_do_search)
    await search.process()

    assert requested_pages == [1]
    assert await search.get_hostnames() == ['api.example.com']


@pytest.mark.parametrize(
    ('status', 'payload'),
    [
        (200, {}),
        (200, {'items': 'not-a-list'}),
        (401, {'message': 'Bad credentials'}),
        (403, {'message': 'Resource not accessible by personal access token'}),
        (500, {'message': 'Server error'}),
    ],
    ids=['empty', 'malformed', 'unauthorized', 'forbidden', 'server-error'],
)
@pytest.mark.asyncio
async def test_github_code_terminal_responses_stop_after_one_request(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    payload: dict[str, Any],
) -> None:
    requested_pages: list[int] = []

    async def fake_do_search(page: int) -> tuple[str, dict[str, Any], int, dict[str, Any]]:
        requested_pages.append(page)
        return '', payload, status, {}

    search = githubcode.SearchGithubCode('example.com', limit=10)
    monkeypatch.setattr(search, 'do_search', fake_do_search)
    await search.process()

    assert requested_pages == [1]
    assert search.page == 0
    assert await search.get_emails() == set()
    assert await search.get_hostnames() == []


@pytest.mark.asyncio
async def test_github_code_empty_page_does_not_follow_provider_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_pages: list[int] = []

    async def fake_do_search(page: int) -> tuple[str, dict[str, Any], int, dict[str, dict[str, str]]]:
        requested_pages.append(page)
        if len(requested_pages) > 1:
            return '', {}, 500, {}
        return (
            '',
            {'items': []},
            200,
            {
                'next': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
                'last': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
            },
        )

    search = githubcode.SearchGithubCode('example.com', limit=10)
    monkeypatch.setattr(search, 'do_search', fake_do_search)
    await search.process()

    assert requested_pages == [1]
    assert search.page == 0


@pytest.mark.parametrize('status', [403, 429])
@pytest.mark.asyncio
async def test_github_code_quota_retries_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    requested_pages: list[int] = []

    async def fake_do_search(page: int) -> tuple[str, dict[str, Any], int, dict[str, Any]]:
        requested_pages.append(page)
        return '', {'message': 'Rate limit exceeded'}, status, {}

    search = githubcode.SearchGithubCode('example.com', limit=10)
    search.max_retries = 2
    monkeypatch.setattr(search, 'do_search', fake_do_search)
    await search.process()

    assert requested_pages == [1, 1, 1]
    assert search.retry_count == 3
    assert search.page == 0

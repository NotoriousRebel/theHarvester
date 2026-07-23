import json
from typing import Any

import pytest

from theHarvester.discovery import gitlabsearch


@pytest.mark.asyncio
async def test_gitlab_public_discovery_uses_explicit_caps_and_normalizes_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[dict[str, Any]] = []
    projects = [
        {
            'id': 42,
            'default_branch': 'feature/readme',
            'description': 'Blog.Example.COM. and foo.example.com.evil',
            'name': 'Example project',
            'path_with_namespace': 'group/example',
            'web_url': 'https://gitlab.com/group/example',
        }
    ]
    users = [
        {
            'name': 'Example user',
            'username': 'example',
            'bio': 'Status at Status.Example.COM.',
            'web_url': 'https://gitlab.com/example',
            'website_url': 'https://Docs.Example.COM./profile',
            'public_email': 'SECURITY@Example.COM',
        },
        {
            'name': 'Outsider',
            'username': 'outsider',
            'bio': 'api.notexample.com',
            'web_url': 'https://gitlab.com/outsider',
            'website_url': 'https://api.notexample.com',
            'public_email': 'outsider@notexample.com',
        },
    ]

    async def fake_fetch_all(
        urls: list[str] | set[str],
        headers: dict[str, str] | None = None,
        proxy: bool = False,
        **_kwargs: Any,
    ) -> list[str]:
        url = next(iter(urls))
        requests.append({'url': url, 'headers': headers, 'proxy': proxy})
        if url == 'https://gitlab.com/api/v4/projects?search=example.com&per_page=20':
            return [json.dumps(projects)]
        if url == 'https://gitlab.com/api/v4/projects?search=*.example.com&per_page=20':
            return ['[]']
        if url == 'https://gitlab.com/api/v4/projects/42/repository/files/README.md/raw?ref=feature%2Freadme':
            return ['Contact Admin@Example.COM. at api.example.com; ignore admin@notexample.com']
        if url == 'https://gitlab.com/api/v4/users?search=example.com&per_page=10':
            return [json.dumps(users)]
        raise AssertionError(f'unexpected GitLab request: {url}')

    monkeypatch.setattr(gitlabsearch.Core, 'get_user_agent', staticmethod(lambda: 'UA'))
    monkeypatch.setattr(gitlabsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = gitlabsearch.SearchGitlab('example.com')
    await search.process(proxy=True)

    assert requests == [
        {
            'url': 'https://gitlab.com/api/v4/projects?search=example.com&per_page=20',
            'headers': {'User-agent': 'UA'},
            'proxy': True,
        },
        {
            'url': 'https://gitlab.com/api/v4/projects/42/repository/files/README.md/raw?ref=feature%2Freadme',
            'headers': {'User-agent': 'UA'},
            'proxy': True,
        },
        {
            'url': 'https://gitlab.com/api/v4/projects?search=*.example.com&per_page=20',
            'headers': {'User-agent': 'UA'},
            'proxy': True,
        },
        {
            'url': 'https://gitlab.com/api/v4/users?search=example.com&per_page=10',
            'headers': {'User-agent': 'UA'},
            'proxy': True,
        },
    ]
    assert await search.get_emails() == {
        'admin@example.com',
        'security@example.com',
    }
    assert await search.get_hostnames() == {
        'api.example.com',
        'blog.example.com',
        'docs.example.com',
        'example.com',
        'status.example.com',
    }


@pytest.mark.asyncio
async def test_gitlab_handles_decoded_lists_and_malformed_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_fetch_all(
        urls: list[str] | set[str],
        **_kwargs: Any,
    ) -> list[Any]:
        url = next(iter(urls))
        if '/projects?' in url and 'search=example.com&' in url:
            return [
                [
                    None,
                    {
                        'id': 7,
                        'default_branch': None,
                        'description': 'api.example.com',
                        'name': 42,
                        'path_with_namespace': [],
                        'web_url': None,
                    },
                ]
            ]
        if '/projects?' in url:
            return ['not-json']
        if '/users?' in url:
            return [
                [
                    None,
                    {
                        'name': {},
                        'username': [],
                        'bio': None,
                        'web_url': None,
                        'website_url': 42,
                        'public_email': 'Admin@Example.COM',
                    },
                ]
            ]
        raise AssertionError(f'unexpected GitLab request: {url}')

    monkeypatch.setattr(gitlabsearch.Core, 'get_user_agent', staticmethod(lambda: 'UA'))
    monkeypatch.setattr(gitlabsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = gitlabsearch.SearchGitlab('example.com')
    await search.process()

    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == {'api.example.com'}


@pytest.mark.parametrize('payload', ['', 'null', '{}'], ids=['empty', 'null', 'mapping'])
@pytest.mark.asyncio
async def test_gitlab_unusable_payloads_return_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    async def fake_fetch_all(
        urls: list[str] | set[str],
        **_kwargs: Any,
    ) -> list[str]:
        return [payload]

    monkeypatch.setattr(gitlabsearch.Core, 'get_user_agent', staticmethod(lambda: 'UA'))
    monkeypatch.setattr(gitlabsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = gitlabsearch.SearchGitlab('example.com')
    await search.process()

    assert await search.get_emails() == set()
    assert await search.get_hostnames() == set()

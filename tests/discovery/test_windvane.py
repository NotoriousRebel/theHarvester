from typing import Any

import pytest

from theHarvester.discovery import windvane


@pytest.mark.asyncio
async def test_authenticated_search_sends_json_bodies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(windvane.Core, 'windvane_key', lambda: 'test-key')
    monkeypatch.setattr(windvane.Core, 'get_user_agent', lambda: 'test-agent')
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake_post_fetch(url: str, **kwargs: Any) -> str:
        calls.append((url, kwargs))
        return '{"code": 1}'

    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fake_post_fetch)

    search = windvane.SearchWindvane('example.com')
    await search.do_search()

    assert [url.rsplit('/', 1)[-1] for url, _ in calls] == ['ListSubDomain', 'ListDNS', 'ListEmail']
    assert [kwargs['json_body'] for _, kwargs in calls] == [
        {'domain': 'example.com', 'page_request': {'page': 1, 'count': 30}},
        {'domain': 'example.com', 'page_request': {'page': 1, 'count': 30}},
        {'email': 'example.com', 'page_request': {'page': 1, 'count': 50}},
    ]
    assert all('data' not in kwargs for _, kwargs in calls)


@pytest.mark.asyncio
async def test_limited_search_sends_json_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(windvane.Core, 'windvane_key', lambda: None)
    monkeypatch.setattr(windvane.Core, 'get_user_agent', lambda: 'test-agent')
    captured: dict[str, Any] = {}

    async def fake_post_fetch(url: str, **kwargs: Any) -> str:
        captured.update(kwargs)
        return '{"code": 0, "data": {"list": []}}'

    monkeypatch.setattr(windvane.AsyncFetcher, 'post_fetch', fake_post_fetch)

    search = windvane.SearchWindvane('example.com')
    await search.do_search()

    assert captured['json_body'] == {
        'domain': 'example.com',
        'page_request': {'page': 1, 'count': 10},
    }
    assert 'data' not in captured

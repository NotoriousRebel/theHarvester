from typing import Any

import pytest

from theHarvester.discovery import baidusearch


class TestBaiduSearch:
    @pytest.mark.asyncio
    async def test_contract_uses_exact_pages_and_normalizes_evidence(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        request: dict[str, Any] = {}

        async def fake_fetch_all(
            urls: list[str] | set[str],
            headers: dict[str, str] | None = None,
            proxy: bool = False,
            **_kwargs: Any,
        ) -> list[str]:
            request['urls'] = list(urls)
            request['headers'] = headers
            request['proxy'] = proxy
            return [
                'Contact Admin@Example.COM. at Blog.Example.COM.',
                '<html><div>Access denied for outsider@notexample.com and api.notexample.com',
                '',
            ]

        monkeypatch.setattr(baidusearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        monkeypatch.setattr(baidusearch.Core, 'get_user_agent', staticmethod(lambda: 'UA'))

        search = baidusearch.SearchBaidu(word='example.com', limit=21)
        await search.process(proxy=True)

        assert request == {
            'urls': [
                'https://www.baidu.com/s?wd=%40example.com&pn=0&oq=example.com',
                'https://www.baidu.com/s?wd=%40example.com&pn=10&oq=example.com',
                'https://www.baidu.com/s?wd=%40example.com&pn=20&oq=example.com',
            ],
            'headers': {'Host': 'www.baidu.com', 'User-agent': 'UA'},
            'proxy': True,
        }
        assert await search.get_emails() == {'admin@example.com'}
        assert await search.get_hostnames() == ['blog.example.com', 'example.com']

    @pytest.mark.asyncio
    async def test_pagination_limit_exclusive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, list[str]] = {}

        async def fake_fetch_all(
            urls: list[str] | set[str],
            **_kwargs: Any,
        ) -> list[str]:
            captured['urls'] = list(urls)
            return [''] * len(urls)

        monkeypatch.setattr(baidusearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        monkeypatch.setattr(baidusearch.Core, 'get_user_agent', staticmethod(lambda: 'UA'))

        search = baidusearch.SearchBaidu(word='example.com', limit=20)
        await search.process()

        assert captured['urls'] == [
            'https://www.baidu.com/s?wd=%40example.com&pn=0&oq=example.com',
            'https://www.baidu.com/s?wd=%40example.com&pn=10&oq=example.com',
        ]

#!/usr/bin/env python3
# coding=utf-8
from typing import Any

import httpx
import pytest

from theHarvester.discovery import otxsearch
from theHarvester.lib.core import Core


class TestOtx(object):
    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.live_network
    def test_api(self) -> None:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.domain()}/passive_dns'
        response = httpx.get(url, headers={'User-Agent': Core.get_user_agent()}, timeout=30)

        assert response.status_code == 200
        assert isinstance(response.json().get('passive_dns'), list)

    @pytest.mark.asyncio
    async def test_search(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[dict[str, Any]]:
            assert urls == ['https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns']
            return [
                {
                    'passive_dns': [
                        {'hostname': 'API.EXAMPLE.COM.', 'address': '192.0.2.1'},
                        {'hostname': 'www.example.com', 'address': '2001:db8::1'},
                        {'hostname': 'outside.test', 'address': '192.0.2.2'},
                    ]
                }
            ]

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = otxsearch.SearchOtx(TestOtx.domain())
        await search.process()
        assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
        assert await search.get_ips() == {'192.0.2.1', '2001:db8::1'}

    @pytest.mark.asyncio
    @pytest.mark.parametrize('payload', [None, [], {}, {'passive_dns': None}])
    async def test_malformed_results_return_no_evidence(
        self,
        monkeypatch: pytest.MonkeyPatch,
        payload: Any,
    ) -> None:
        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[Any]:
            return [payload]

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = otxsearch.SearchOtx(TestOtx.domain())
        await search.process()
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()

    @pytest.mark.asyncio
    async def test_provider_failures_are_attributed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[Any]:
            raise OSError('provider unavailable')

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', failed_fetch)
        search = otxsearch.SearchOtx(TestOtx.domain())
        await search.process()
        assert await search.get_hostnames() == set()
        assert await search.get_ips() == set()
        assert 'OTX' in capsys.readouterr().out


if __name__ == "__main__":
    pytest.main()

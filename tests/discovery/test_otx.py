#!/usr/bin/env python3
# coding=utf-8
from typing import Any

import httpx
import pytest

from theHarvester.discovery import otxsearch
from theHarvester.lib.core import Core
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


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
        async def fake_fetch(*_args: Any, **_kwargs: Any) -> dict[str, list[dict[str, str]]]:
            return {
                'passive_dns': [
                    {'hostname': 'api.example.com', 'address': '192.0.2.1'},
                    {'hostname': 'www.example.com', 'address': 'NXDOMAIN'},
                ]
            }

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch', fake_fetch)
        result = await execute_collection(
            TestOtx.domain(),
            'otx',
            lambda: otxsearch.SearchOtx(TestOtx.domain()),
        )

        assert result.outcome.status is SourceStatus.SUCCEEDED
        assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'api.example.com', 'www.example.com'}
        assert result.route_values[ResultRoute.IPS] == ('192.0.2.1',)


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(*, url: str, **kwargs: Any) -> dict[str, list[Any]]:
        assert url == 'https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns'
        assert kwargs['json'] is True
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return {'passive_dns': []}

    async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError('legacy fetch_all called')

    monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', reject_fetch_all)
    result = await execute_collection(
        'example.com',
        'otx',
        lambda: otxsearch.SearchOtx('example.com'),
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: (),
        ResultRoute.IPS: (),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('response', 'error_type'),
    [
        ({'error': 'rate limited', 'passive_dns': []}, 'RuntimeError'),
        ({}, 'ValueError'),
        ({'passive_dns': {}}, 'ValueError'),
        ([], 'ValueError'),
        (ConnectionError('provider unavailable'), 'ConnectionError'),
        (TimeoutError('provider timed out'), 'TimeoutError'),
        (RuntimeError('HTTP 503'), 'RuntimeError'),
    ],
)
async def test_collection_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    response: Any,
    error_type: str,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> Any:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch', fake_fetch)
    result = await execute_collection(
        'example.com',
        'otx',
        lambda: otxsearch.SearchOtx('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: (),
        ResultRoute.IPS: (),
    }


if __name__ == "__main__":
    pytest.main()

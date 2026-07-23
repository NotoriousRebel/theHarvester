from typing import Any

import pytest

from theHarvester.discovery import robtex


@pytest.mark.asyncio
async def test_robtex_does_not_send_domain_to_reverse_ip_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[str]:
        requested_urls.extend(urls)
        return ['{"rrname":"api.example.com","rrtype":"A","rrdata":"192.0.2.1"}']

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')
    await search.process()

    assert requested_urls == ['https://freeapi.robtex.com/pdns/forward/example.com']
    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.1'}


@pytest.mark.asyncio
async def test_robtex_skips_malformed_json_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[str]:
        return ['not-json\n{}\n[]']

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')
    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()


@pytest.mark.asyncio
async def test_robtex_attributes_provider_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[str]:
        raise OSError('provider unavailable')

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', failed_fetch)
    search = robtex.SearchRobtex('example.com')
    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()
    assert 'Robtex API error' in capsys.readouterr().out

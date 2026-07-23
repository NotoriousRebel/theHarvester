from typing import Any

import pytest

from theHarvester.discovery import rapiddns


@pytest.mark.asyncio
async def test_rapid_dns_handles_malformed_html(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[str]:
        return ['<html><p>no results</p></html>']

    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = rapiddns.SearchRapidDns('example.com')
    await search.process()

    assert await search.get_hostnames() == []


@pytest.mark.asyncio
async def test_rapid_dns_attributes_provider_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[str]:
        raise OSError('provider unavailable')

    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch_all', failed_fetch)
    search = rapiddns.SearchRapidDns('example.com')
    await search.process()

    assert await search.get_hostnames() == []
    assert 'RapidDNS' in capsys.readouterr().out

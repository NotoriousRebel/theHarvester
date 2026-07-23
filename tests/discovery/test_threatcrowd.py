from typing import Any

import pytest

from theHarvester.discovery import threatcrowd


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', ['', 'not-json', '[]', '{"subdomains":"wrong-shape"}'])
async def test_threat_crowd_handles_empty_or_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[str]:
        return [payload]

    monkeypatch.setattr(threatcrowd.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = threatcrowd.SearchThreatcrowd('example.com')
    await search.process()

    assert await search.get_hostnames() == set()
    assert await search.get_ips() == set()


@pytest.mark.asyncio
async def test_threat_crowd_attributes_provider_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[dict[str, str]]:
        return [{'response_code': '0'}]

    monkeypatch.setattr(threatcrowd.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = threatcrowd.SearchThreatcrowd('example.com')
    await search.process()

    assert await search.get_hostnames() == set()
    assert 'ThreatCrowd API returned error code' in capsys.readouterr().out

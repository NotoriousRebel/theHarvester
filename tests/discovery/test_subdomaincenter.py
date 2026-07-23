from typing import Any

import pytest

from theHarvester.discovery import subdomaincenter


async def _run_search(monkeypatch: pytest.MonkeyPatch, payload: Any) -> set[str]:
    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[Any]:
        assert urls == ['https://api.subdomain.center/?domain=example.com']
        return [payload]

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = subdomaincenter.SubdomainCenter('example.com')
    await search.process()
    return await search.get_hostnames()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('payload', 'expected'),
    [
        (None, set()),
        ({}, set()),
        ('api.example.com', set()),
        (['api.example.com', None], {'api.example.com'}),
    ],
)
async def test_subdomain_center_rejects_malformed_results(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
    expected: set[str],
) -> None:
    assert await _run_search(monkeypatch, payload) == expected


@pytest.mark.asyncio
async def test_subdomain_center_attributes_provider_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def failed_fetch(*_args: Any, **_kwargs: Any) -> list[Any]:
        raise OSError('provider unavailable')

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', failed_fetch)
    search = subdomaincenter.SubdomainCenter('example.com')
    await search.process()

    assert await search.get_hostnames() == set()
    assert 'SubdomainCenter' in capsys.readouterr().out

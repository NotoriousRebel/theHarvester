from typing import Any

import pytest

from theHarvester.discovery import shodanct
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.run import SourceIncompleteError, SourceRateLimitedError
from theHarvester.lib.source_catalog import ResultRoute, get_source_spec


@pytest.mark.asyncio
async def test_process_returns_only_normalized_in_scope_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_fetch(*, url: str, **kwargs: Any) -> FetcherResponse:
        requested_urls.append(url)
        assert kwargs['json'] is True
        assert kwargs['include_metadata'] is True
        return FetcherResponse(
            [
                'API.Example.COM.',
                '*.wild.example.com',
                'example.com',
                'outside.test',
                'not valid.example.com',
                '-bad.example.com',
                'bad..example.com',
            ],
            200,
        )

    monkeypatch.setattr(shodanct.AsyncFetcher, 'fetch', fake_fetch)

    search = shodanct.SearchShodanCt(' Example.COM. ')
    await search.process()

    assert requested_urls == ['https://ctl.shodan.io/api/v1/domain/example.com/hostnames']
    assert await search.get_hostnames() == {'api.example.com', 'example.com', 'wild.example.com'}


@pytest.mark.asyncio
async def test_process_reports_an_invalid_response_as_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse('service unavailable', 200)

    monkeypatch.setattr(shodanct.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(SourceIncompleteError):
        await shodanct.SearchShodanCt('example.com').process()


@pytest.mark.asyncio
async def test_process_reports_transport_failure_as_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(shodanct.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(SourceIncompleteError):
        await shodanct.SearchShodanCt('example.com').process()


@pytest.mark.asyncio
async def test_process_preserves_provider_rate_limit_status(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse('any provider body', 429)

    monkeypatch.setattr(shodanct.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(SourceRateLimitedError):
        await shodanct.SearchShodanCt('example.com').process()


@pytest.mark.asyncio
async def test_process_preserves_valid_names_from_a_malformed_list(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(['api.example.com', None], 200)

    monkeypatch.setattr(shodanct.AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(SourceIncompleteError) as error:
        await shodanct.SearchShodanCt('example.com').process()

    assert error.value.findings == ('api.example.com',)


def test_shodanct_is_registered_as_a_subdomain_source() -> None:
    assert 'shodanct' in Core.get_supportedengines()
    assert get_source_spec('shodanct').routes == {ResultRoute.HOSTS}


@pytest.mark.asyncio
async def test_process_reports_non_success_http_status_as_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        nonlocal called
        called = True
        return FetcherResponse(['api.example.com'], 500)

    monkeypatch.setattr(AsyncFetcher, 'fetch', fake_fetch)

    with pytest.raises(SourceIncompleteError):
        await shodanct.SearchShodanCt('example.com').process()
    assert called is True

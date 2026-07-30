import logging
from urllib.parse import parse_qs, urlparse

import pytest

from theHarvester.discovery import certspottersearch


@pytest.mark.asyncio
async def test_process_collects_normalized_scoped_names_across_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        [
            {
                'id': 'issuance-1',
                'dns_names': [
                    'WWW.Example.COM.',
                    '*.API.example.com',
                    'example.com',
                    'outside.test',
                    None,
                    ' ',
                ],
            },
            {'id': 'issuance-2', 'dns_names': ['www.example.com']},
        ],
        [{'id': 'issuance-3', 'dns_names': ['mail.example.com', '*.deep.example.com']}],
        [],
    ]
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        requested_urls.extend(urls)
        return [pages.pop(0)]

    monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = certspottersearch.SearchCertspoter('Example.COM.')
    await search.process(proxy=True)

    assert await search.get_hostnames() == {
        'api.example.com',
        'deep.example.com',
        'example.com',
        'mail.example.com',
        'www.example.com',
    }
    assert [parse_qs(urlparse(url).query) for url in requested_urls] == [
        {'domain': ['example.com'], 'include_subdomains': ['true'], 'expand': ['dns_names']},
        {
            'domain': ['example.com'],
            'include_subdomains': ['true'],
            'expand': ['dns_names'],
            'after': ['issuance-2'],
        },
        {
            'domain': ['example.com'],
            'include_subdomains': ['true'],
            'expand': ['dns_names'],
            'after': ['issuance-3'],
        },
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize('response', [[], [''], [None], [{'code': 'rate_limited'}]])
async def test_process_returns_empty_results_for_empty_malformed_or_error_responses(
    monkeypatch: pytest.MonkeyPatch, response: list[object]
) -> None:
    async def fake_fetch_all(_urls: list[str], **_kwargs: object) -> list[object]:
        return response

    monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = certspottersearch.SearchCertspoter('example.com')
    await search.process()

    assert await search.get_hostnames() == set()


@pytest.mark.asyncio
async def test_process_skips_malformed_entries_but_keeps_valid_page_results(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        [
            None,
            {'id': 'ignored', 'dns_names': 'not-a-list'},
            {'id': 'cursor-1', 'dns_names': ['valid.example.com']},
        ],
        [],
    ]

    async def fake_fetch_all(_urls: list[str], **_kwargs: object) -> list[object]:
        return [pages.pop(0)]

    monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = certspottersearch.SearchCertspoter('example.com')
    await search.process()

    assert await search.get_hostnames() == {'valid.example.com'}


@pytest.mark.asyncio
async def test_process_preserves_completed_pages_when_a_later_request_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    call_count = 0

    async def fake_fetch_all(_urls: list[str], **_kwargs: object) -> list[object]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [[{'id': 'cursor-1', 'dns_names': ['valid.example.com']}]]
        raise ConnectionError

    monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = certspottersearch.SearchCertspoter('example.com')
    await search.process()

    assert await search.get_hostnames() == {'valid.example.com'}


@pytest.mark.asyncio
async def test_process_stops_when_the_provider_repeats_a_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        [{'id': 'repeated', 'dns_names': ['first.example.com']}],
        [{'id': 'repeated', 'dns_names': ['second.example.com']}],
    ]
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        requested_urls.extend(urls)
        return [pages.pop(0)]

    monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = certspottersearch.SearchCertspoter('example.com')
    await search.process()

    assert await search.get_hostnames() == {'first.example.com', 'second.example.com'}
    assert len(requested_urls) == 2


@pytest.mark.asyncio
async def test_process_reports_incomplete_results_at_the_request_safety_limit(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=certspottersearch.__name__)
    monkeypatch.setattr(certspottersearch.SearchCertspoter, 'MAX_PAGES', 2)
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: object) -> list[object]:
        requested_urls.extend(urls)
        page_number = len(requested_urls)
        return [[{'id': f'cursor-{page_number}', 'dns_names': [f'page-{page_number}.example.com']}]]

    monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = certspottersearch.SearchCertspoter('example.com')
    await search.process()

    assert await search.get_hostnames() == {'page-1.example.com', 'page-2.example.com'}
    assert len(requested_urls) == 2
    assert any('results may be incomplete' in message for message in caplog.messages)

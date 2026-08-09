import pytest

from theHarvester.discovery import takeover


@pytest.mark.asyncio
async def test_takeover_reports_empty_transport_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    search = takeover.TakeOver(['api.example.com'])
    monkeypatch.setattr(search, 'fingerprints', {'No such app': 'Heroku'})

    async def fake_fetch_all(urls, **_kwargs):
        assert set(urls) == {'https://api.example.com', 'http://api.example.com'}
        return [('https://api.example.com', 'No such app'), ('http://api.example.com', '')]

    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_all', fake_fetch_all)

    await search.process()

    assert search.request_count == 2
    assert search.error_count == 1
    assert search.error_type == 'EmptyResponse'
    assert await search.get_takeover_results() == {'https://api.example.com': [{'No such app': 'Heroku'}]}

import pytest

from theHarvester.discovery import intelxsearch


@pytest.mark.asyncio
async def test_interesting_urls_match_the_shared_result_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intelxsearch.Core, 'intelx_key', lambda: 'test-key')
    search = intelxsearch.SearchIntelx('example.com')
    search.info = ([], ['https://api.example.com/path'], [])

    assert await search.get_interestingurls() == ['https://api.example.com/path']

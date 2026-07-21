import pytest

from theHarvester.discovery import bufferoverun
from theHarvester.lib.core import Core


@pytest.mark.asyncio
async def test_bufferover_parses_documented_four_column_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Core, 'bufferoverun_key', lambda: 'test-key')

    async def fake_fetch_all(*_args, **_kwargs):
        return [
            {
                'Results': [
                    '192.0.2.10,hash-1,"Example, Inc.",api.example.com',
                    '2001:db8::10,hash-2,Example Org,ipv6.example.com',
                    'malformed,row',
                ]
            }
        ]

    monkeypatch.setattr(bufferoverun.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = bufferoverun.SearchBufferover('example.com')

    await search.do_search()

    assert await search.get_hostnames() == {'api.example.com', 'ipv6.example.com'}
    assert await search.get_ips() == {'192.0.2.10', '2001:db8::10'}

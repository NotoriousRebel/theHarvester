import json
from types import TracebackType
from typing import Any, ClassVar, Self

import pytest

from theHarvester.discovery import crtsh, otxsearch, rapiddns, robtex, subdomaincenter, thc, threatcrowd


@pytest.mark.asyncio
async def test_crtsh_retains_scoped_numeric_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[list[dict[str, str]]]:
        return [
            [
                {'name_value': '1234.EXAMPLE.COM.'},
                {'name_value': 'outside.test'},
            ]
        ]

    monkeypatch.setattr(crtsh.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = crtsh.SearchCrtsh('example.com')
    await search.process()

    assert await search.get_hostnames() == ['1234.example.com']


@pytest.mark.asyncio
async def test_otx_returns_scoped_hosts_and_valid_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        return [
            {
                'passive_dns': [
                    {'hostname': 'API.EXAMPLE.COM.', 'address': '2001:db8::1'},
                    {'hostname': 'outside.test', 'address': '192.0.2.2'},
                    {'hostname': 'invalid.example.com', 'address': '999.0.0.1'},
                ]
            }
        ]

    monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = otxsearch.SearchOtx('example.com')
    await search.process()

    assert await search.get_hostnames() == {'api.example.com', 'invalid.example.com'}
    assert await search.get_ips() == {'2001:db8::1'}


@pytest.mark.asyncio
async def test_rapid_dns_rejects_out_of_scope_and_invalid_address_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    html = """
    <table><tbody>
      <tr><td>API.Example.COM.</td><td>192.0.2.1</td><td>A</td></tr>
      <tr><td>invalid.example.com</td><td>999.0.0.1</td><td>A</td></tr>
      <tr><td>outside.test</td><td>192.0.2.2</td><td>A</td></tr>
      <tr><td>alias.example.com</td><td>target.example.com</td><td>CNAME</td></tr>
    </tbody></table>
    """

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[str]:
        return [html]

    monkeypatch.setattr(rapiddns.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = rapiddns.SearchRapidDns('Example.COM.')
    await search.process()

    assert await search.get_hostnames() == ['alias.example.com', 'api.example.com:192.0.2.1']


@pytest.mark.asyncio
async def test_robtex_returns_only_scoped_hostnames_and_valid_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = '\n'.join(
        [
            '{"rrname":"api.example.com","rrtype":"A","rrdata":"192.0.2.1"}',
            '{"rrname":"alias.example.com","rrtype":"CNAME","rrdata":"TARGET.EXAMPLE.COM."}',
            '{"rrname":"badexample.com","rrtype":"A","rrdata":"192.0.2.2"}',
            '{"rrname":"invalid.example.com","rrtype":"A","rrdata":"999.0.0.1"}',
        ]
    )

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[str]:
        return [payload]

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')
    await search.process()

    assert await search.get_hostnames() == {
        'api.example.com',
        'alias.example.com',
        'invalid.example.com',
        'target.example.com',
    }
    assert await search.get_ips() == {'192.0.2.1'}


@pytest.mark.asyncio
async def test_subdomain_center_preserves_scoped_www_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[list[str]]:
        return [['WWW.EXAMPLE.COM.', 'outside.test']]

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = subdomaincenter.SubdomainCenter('example.com')
    await search.process()

    assert await search.get_hostnames() == {'www.example.com'}


class _ThcResponse:
    status = 200
    headers: ClassVar[dict[str, str]] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> bool:
        return False

    async def text(self) -> str:
        return 'API.EXAMPLE.COM.\nnotexample.com\n'


class _ThcSession:
    def __init__(self, **_kwargs: Any) -> None:
        pass

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> bool:
        return False

    def get(self, _url: str) -> _ThcResponse:
        return _ThcResponse()


@pytest.mark.asyncio
async def test_thc_rejects_suffix_collisions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(thc.aiohttp, 'ClientSession', _ThcSession)
    search = thc.SearchThc('example.com')
    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}


@pytest.mark.asyncio
async def test_threat_crowd_normalizes_scoped_hosts_and_valid_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps(
        {
            'response_code': '1',
            'subdomains': ['API.EXAMPLE.COM.', 'outside.test'],
            'resolutions': [{'ip_address': '192.0.2.1'}, {'ip_address': 'not-an-ip'}],
        }
    )

    async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[str]:
        return [payload]

    monkeypatch.setattr(threatcrowd.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = threatcrowd.SearchThreatcrowd('example.com')
    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.1'}

from __future__ import annotations

import pytest

from theHarvester.discovery import dnsdb


def _install_response(
    monkeypatch: pytest.MonkeyPatch,
    lines: tuple[bytes, ...],
    *,
    status: int = 200,
) -> dict[str, object]:
    requested: dict[str, object] = {}
    lines_left = list(lines)

    class FakeContent:
        def __aiter__(self):
            return self

        async def __anext__(self):
            if not lines_left:
                raise StopAsyncIteration
            return lines_left.pop(0)

    class FakeResponse:
        def __init__(self) -> None:
            self.status = status

        content = FakeContent()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class FakeSession:
        def __init__(self, **kwargs):
            requested['session'] = kwargs

        def get(self, url: str, **kwargs):
            requested['url'] = url
            requested['request'] = kwargs
            return FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    monkeypatch.setattr(dnsdb.aiohttp, 'ClientSession', FakeSession)
    return requested


@pytest.mark.asyncio
async def test_process_collects_normalized_in_scope_rrset_owners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    requested = _install_response(
        monkeypatch,
        (
            b'{"cond":"begin"}\n',
            b'{"obj":{"rrname":"API.Example.COM.","rrtype":"A","rdata":["192.0.2.10"]}}\n',
            b'{"obj":{"rrname":"example.com.","rrtype":"NS","rdata":["ns.example.net."]}}\n',
            b'{"obj":{"rrname":"*.wild.example.com.","rrtype":"A","rdata":["192.0.2.11"]}}\n',
            b'{"obj":{"rrname":"_WILDCARD_.junk.example.com.","rrtype":"A","rdata":["192.0.2.12"]}}\n',
            b'{"obj":{"rrname":"outside.test.","rrtype":"A","rdata":["192.0.2.13"]}}\n',
            b'{"cond":"succeeded"}\n',
        ),
    )

    search = dnsdb.SearchDNSDB(' Example.COM. ')
    await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert requested['url'] == 'https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.example.com?limit=0'
    assert 'offset=' not in str(requested['url'])
    assert requested['session']['headers'] == {
        'Accept': 'application/x-ndjson',
        'User-Agent': f'theHarvester/{dnsdb.__version__}',
        'X-API-Key': 'dnsdb-test-key',
    }


@pytest.mark.parametrize(
    ('lines', 'expected_warning'),
    [
        (
            (
                b'{"cond":"begin"}\n',
                b'{"obj":{"rrname":"first.example.com."}}\n',
                b'{"cond":"limited","msg":"Result limit reached"}\n',
            ),
            'DNSDB reached its account result limit; partial results were preserved.',
        ),
        (
            (
                b'{"cond":"begin"}\n',
                b'{"obj":{"rrname":"first.example.com."}}\n',
                b'not-json\n',
                b'{"obj":{"rrname":"discarded.example.com."}}\n',
                b'{"cond":"succeeded"}\n',
            ),
            'DNSDB returned malformed NDJSON; partial results were preserved.',
        ),
    ],
)
@pytest.mark.asyncio
async def test_process_preserves_results_before_incomplete_streams(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    lines: tuple[bytes, ...],
    expected_warning: str,
) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(monkeypatch, lines)

    search = dnsdb.SearchDNSDB('example.com')
    await search.process()

    assert await search.get_hostnames() == {'first.example.com'}
    assert expected_warning in capsys.readouterr().out


@pytest.mark.asyncio
async def test_process_exposes_rate_limits_to_the_run_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(monkeypatch, (), status=429)

    with pytest.raises(dnsdb.SourceRateLimitedError):
        await dnsdb.SearchDNSDB('example.com').process()

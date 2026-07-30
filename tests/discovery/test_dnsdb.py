from __future__ import annotations

import logging

import pytest

from theHarvester.discovery import dnsdb
from theHarvester.lib.run import LegacyHostnameSource, SourceStatus, execute_run


def _install_response(
    monkeypatch: pytest.MonkeyPatch,
    lines: tuple[bytes, ...],
    *,
    status: int = 200,
) -> dict[str, object]:
    requested: dict[str, object] = {}
    lines_left = list(lines)

    class FakeContent:
        def __aiter__(self) -> FakeContent:
            return self

        async def __anext__(self) -> bytes:
            if not lines_left:
                raise StopAsyncIteration
            return lines_left.pop(0)

    class FakeResponse:
        def __init__(self) -> None:
            self.status = status

        content = FakeContent()

        async def __aenter__(self) -> FakeResponse:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    class FakeSession:
        def __init__(self, **kwargs: object) -> None:
            requested['session'] = kwargs

        def get(self, url: str, **kwargs: object) -> FakeResponse:
            requested['url'] = url
            requested['request'] = kwargs
            return FakeResponse()

        async def __aenter__(self) -> FakeSession:
            return self

        async def __aexit__(self, *_args: object) -> None:
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
    ('lines', 'expected_warning', 'expected_error'),
    [
        (
            (
                b'{"cond":"begin"}\n',
                b'{"obj":{"rrname":"first.example.com."}}\n',
                b'{"cond":"limited","msg":"Result limit reached"}\n',
            ),
            'DNSDB reached its account result limit; partial results were preserved.',
            dnsdb.SourceRateLimitedError,
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
            dnsdb.SourceIncompleteError,
        ),
    ],
)
@pytest.mark.asyncio
async def test_process_preserves_results_before_incomplete_streams(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    lines: tuple[bytes, ...],
    expected_warning: str,
    expected_error: type[Exception],
) -> None:
    caplog.set_level(logging.INFO, logger=dnsdb.__name__)
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(monkeypatch, lines)

    search = dnsdb.SearchDNSDB('example.com')
    with pytest.raises(expected_error):
        await search.process()

    assert await search.get_hostnames() == {'first.example.com'}
    assert expected_warning in caplog.messages


@pytest.mark.parametrize(
    ('terminal_condition', 'expected_status'),
    [
        ('limited', SourceStatus.RATE_LIMITED),
        ('failed', SourceStatus.FAILED),
    ],
)
@pytest.mark.asyncio
async def test_incomplete_stream_status_keeps_partial_results_in_completed_run(
    monkeypatch: pytest.MonkeyPatch,
    terminal_condition: str,
    expected_status: SourceStatus,
) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(
        monkeypatch,
        (
            b'{"cond":"begin"}\n',
            b'{"obj":{"rrname":"first.example.com."}}\n',
            f'{{"cond":"{terminal_condition}"}}\n'.encode(),
        ),
    )
    search = dnsdb.SearchDNSDB('example.com')

    result = await execute_run(
        'example.com',
        LegacyHostnameSource('dnsdb', 'passive-dns', search),
        persist=False,
    )

    assert {observation.value for observation in result.observations} == {'first.example.com'}
    assert result.source_executions[0].status is expected_status


@pytest.mark.asyncio
async def test_process_exposes_rate_limits_to_the_run_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnsdb.Core, 'dnsdb_key', lambda: 'dnsdb-test-key')
    _install_response(monkeypatch, (), status=429)

    with pytest.raises(dnsdb.SourceRateLimitedError):
        await dnsdb.SearchDNSDB('example.com').process()

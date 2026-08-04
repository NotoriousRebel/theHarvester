import socket
import sys

import pytest

from theHarvester.discovery import shodansearch
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
@pytest.mark.parametrize('key', [None, '', ' '])
async def test_shodan_missing_key_reports_skipped(monkeypatch: pytest.MonkeyPatch, key: object) -> None:
    monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: key)
    monkeypatch.setattr(
        shodansearch,
        'Shodan',
        lambda _key: pytest.fail('Shodan client must not be created without a key'),
    )

    result = await execute_collection(
        'example.com',
        'shodan',
        lambda: shodansearch.SearchShodan('example.com'),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
async def test_shodan_dns_failure_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnexpectedClient:
        def host(self, _ip: str) -> object:
            pytest.fail('Shodan request must not run after DNS failure')

    monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
    monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: UnexpectedClient())

    def fail_resolution(_domain: str) -> str:
        raise socket.gaierror('offline DNS failure')

    monkeypatch.setattr(socket, 'gethostbyname', fail_resolution)
    result = await execute_collection(
        'example.com',
        'shodan',
        lambda: shodansearch.SearchShodan('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'gaierror'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


@pytest.mark.asyncio
async def test_shodan_success_preserves_ip_and_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        def host(self, ip: str) -> object:
            assert ip == '192.0.2.10'
            return {
                'data': [{'ip_str': ip}],
                'hostnames': ['api.example.com', 'www.example.com'],
            }

    monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
    monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: Client())
    monkeypatch.setattr(shodansearch.socket, 'gethostbyname', lambda _domain: '192.0.2.10')

    result = await execute_collection(
        'example.com',
        'shodan',
        lambda: shodansearch.SearchShodan('example.com'),
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {
        '192.0.2.10',
        'api.example.com',
        'www.example.com',
    }


@pytest.mark.asyncio
async def test_shodan_invalid_remote_key_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        def host(self, _ip: str) -> object:
            raise shodansearch.exception.APIError('invalid remote credential')

    monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'invalid-key')
    monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: Client())
    monkeypatch.setattr(shodansearch.socket, 'gethostbyname', lambda _domain: '192.0.2.10')

    result = await execute_collection(
        'example.com',
        'shodan',
        lambda: shodansearch.SearchShodan('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'APIError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


@pytest.mark.asyncio
async def test_shodan_completed_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        calls = 0

        def host(self, _ip: str) -> object:
            self.calls += 1
            return {'data': []}

    client = Client()
    monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
    monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: client)
    monkeypatch.setattr(shodansearch.socket, 'gethostbyname', lambda _domain: '192.0.2.10')

    result = await execute_collection(
        'example.com',
        'shodan',
        lambda: shodansearch.SearchShodan('example.com'),
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}
    assert client.calls == 1


@pytest.mark.asyncio
async def test_shodan_malformed_response_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        def host(self, _ip: str) -> object:
            return {}

    monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
    monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: Client())
    monkeypatch.setattr(shodansearch.socket, 'gethostbyname', lambda _domain: '192.0.2.10')

    result = await execute_collection(
        'example.com',
        'shodan',
        lambda: shodansearch.SearchShodan('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('error', 'error_type'),
    [
        pytest.param(shodansearch.exception.APIError('HTTP 503'), 'APIError', id='http-error'),
        pytest.param(shodansearch.exception.APITimeout('timed out'), 'APITimeout', id='timeout'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
    ],
)
async def test_shodan_request_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    error_type: str,
) -> None:
    class Client:
        def host(self, _ip: str) -> object:
            raise error

    monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
    monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: Client())
    monkeypatch.setattr(shodansearch.socket, 'gethostbyname', lambda _domain: '192.0.2.10')

    result = await execute_collection(
        'example.com',
        'shodan',
        lambda: shodansearch.SearchShodan('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


class TestShodanEngine:
    @pytest.mark.asyncio
    async def test_shodan_engine_reports_sdk_failure_through_collection_seam(self, monkeypatch, capsys):
        import theHarvester.__main__ as main_module

        class Client:
            def host(self, _ip: str) -> object:
                raise shodansearch.exception.APIError('provider rejected request')

        class DummyStashManager:
            async def do_init(self) -> None:
                return None

            async def store_all(self, domain, all, res_type, source) -> None:
                return None

        monkeypatch.setattr(main_module.shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(main_module.shodansearch, 'Shodan', lambda _key: Client())
        monkeypatch.setattr(main_module.shodansearch.socket, 'gethostbyname', lambda _domain: '192.0.2.10')
        monkeypatch.setattr(main_module.stash, 'StashManager', DummyStashManager, raising=True)
        monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'shodan'], raising=True)

        with pytest.raises(SystemExit) as excinfo:
            await main_module.start()
        assert excinfo.value.code == 0

        out = capsys.readouterr().out
        assert 'Source shodan failed: APIError' in out
        assert 'Source shodan skipped' not in out

    @pytest.mark.asyncio
    async def test_shodan_engine_processes_without_work_item_error_and_yields_hostnames(self, monkeypatch, capsys):
        # Import inside the test so monkeypatching affects the already-imported module namespace.
        import theHarvester.__main__ as main_module

        # Make DNS resolution deterministic and offline.
        monkeypatch.setattr(socket, 'gethostbyname', lambda _domain: '192.0.2.10', raising=True)

        # Avoid filesystem/sqlite side effects.
        class DummyStashManager:
            async def do_init(self) -> None:
                return None

            async def store_all(self, domain, all, res_type, source) -> None:
                return None

        monkeypatch.setattr(main_module.stash, 'StashManager', DummyStashManager, raising=True)

        class Client:
            def host(self, ip: str) -> object:
                return {
                    'data': [{'ip_str': ip}],
                    'hostnames': ['a.example.com', 'b.example.com'],
                }

        monkeypatch.setattr(main_module.shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(main_module.shodansearch, 'Shodan', lambda _key: Client())

        # Run the CLI path that uses the engine queue/worker (`-b shodan`).
        monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'shodan'], raising=True)

        with pytest.raises(SystemExit) as excinfo:
            await main_module.start()
        assert excinfo.value.code == 0

        out = capsys.readouterr().out
        assert 'An error occurred while processing a "work item"' not in out
        assert 'a.example.com' in out
        assert 'b.example.com' in out

    @pytest.mark.asyncio
    async def test_shodan_internetdb_ignores_non_string_resolved_addresses(self, monkeypatch):
        from theHarvester.discovery import shodan_internetdb

        monkeypatch.setattr(
            shodan_internetdb.socket,
            'getaddrinfo',
            lambda *_args: [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('203.0.113.1', 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', (12345, 0)),
            ],
            raising=True,
        )

        async def fake_fetch(**kwargs):
            assert kwargs['url'] == 'https://internetdb.shodan.io/203.0.113.1'
            assert kwargs['json'] is True
            assert kwargs['fail_on_http_error'] is True
            assert kwargs['raise_on_error'] is True
            return {
                'ip': '203.0.113.1',
                'hostnames': ['www.example.com'],
                'ports': [443],
                'vulns': ['CVE-TEST-0001'],
                'tags': ['example-tag'],
                'cpes': ['cpe:/a:example:service:1.0'],
            }

        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch', fake_fetch, raising=True)

        search = shodan_internetdb.SearchShodanInternetDB('example.com')
        await search.process()

        assert await search.get_hostnames() == {'www.example.com'}
        assert await search.get_ips() == {'203.0.113.1'}
        assert await search.get_ports() == {443}
        assert await search.get_vulns() == {'CVE-TEST-0001'}
        assert await search.get_tags() == {'example-tag'}
        assert await search.get_cpes() == {'cpe:/a:example:service:1.0'}

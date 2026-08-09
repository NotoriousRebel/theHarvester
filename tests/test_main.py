import asyncio
import hashlib
import json
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.lib.completed_result import ActionObservation, CompletedResult
from theHarvester.lib.dns_consensus import Addressability
from theHarvester.lib.enumeration import EnumerationOptions
from theHarvester.lib.hostchecker import HostDnsRecords
from theHarvester.lib.recursive_dns import RecursiveDNSClassification, RecursiveDNSFinding, RecursiveDNSResult
from theHarvester.screenshot.screenshot import ScreenshotCapture


@pytest.mark.asyncio
async def test_cli_help_explains_proxy_and_direct_action_scope(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '--help'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    help_text = ' '.join(capsys.readouterr().out.split())
    assert exit_info.value.code == 0
    assert 'Use proxies.yaml for supported discovery-source and takeover requests.' in help_text
    assert 'Accepted for compatibility but currently unused; use --dns-resolve to select resolvers.' in help_text
    assert 'Perform PTR lookups across the /24 network containing each discovered IPv4 address.' in help_text
    assert 'Multiple capabilities select the union of matching sources; they do not filter returned fields.' in help_text
    assert 'Check common API paths with GET, HEAD, and OPTIONS.' in help_text
    assert 'Requests follow redirects.' in help_text


@pytest.mark.parametrize('target', ['Example.COM.', 'WWW.Example.COM.'])
def test_normalize_hosts_for_storage_uses_the_parser_scope(target: str) -> None:
    discovered_hosts: set[object] = {
        'API.Example.COM.',
        'example.com',
        'badexample.com',
        'example.com.attacker.test',
        123,
    }

    assert theharvester_main._normalize_hosts_for_storage(discovered_hosts, target) == {'api.example.com'}


@pytest.mark.asyncio
async def test_rapiddns_hostnames_honor_explicit_dns_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    completed: list[CompletedResult] = []
    output_directory = tmp_path / 'reports.v1'
    output_directory.mkdir()
    output_path = output_directory / 'rapiddns'

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, domain: str, values: list[str] | set[str], kind: str, source: str) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com', 'reported.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {('reported.example.com', '192.0.2.20')}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.20'}

    class FakeCrtsh:
        execution_status = 'partial'
        stop_reason = 'invalid-response'

        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'crt.example.com'}

    class FakeChecker:
        def __init__(self, hosts: list[str], nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']
            self.hosts = hosts

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            if self.hosts == ['crt.example.com']:
                return ['crt.example.com:192.0.2.30'], ['crt.example.com'], ['192.0.2.30']
            assert self.hosts == ['api.example.com']
            return (
                ['api.example.com:192.0.2.10', 'reported.example.com:192.0.2.21'],
                ['api.example.com', 'reported.example.com'],
                ['192.0.2.10', '192.0.2.21'],
            )

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)

    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh,rapiddns',
            '-r',
            '192.0.2.53',
            '-f',
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert ('hostname', 'api.example.com') in completed[0].results
    assert ('hostname', 'crt.example.com') in completed[0].results
    assert ('hostname', 'reported.example.com') in completed[0].results
    assert ('ip-address', '192.0.2.10') in completed[0].results
    assert ('ip-address', '192.0.2.20') in completed[0].results
    assert ('ip-address', '192.0.2.21') in completed[0].results
    assert ('ip-address', '192.0.2.30') in completed[0].results
    assert {execution.source for execution in completed[0].source_executions} == {'crtsh', 'rapiddns'}
    crtsh_execution = next(execution for execution in completed[0].source_executions if execution.source == 'crtsh')
    assert crtsh_execution.status == 'partial'
    assert crtsh_execution.stop_reason == 'invalid-response'
    assert completed[0].evidence_dict()['status'] == 'partial'
    assert {(observation.source, observation.kind, observation.value) for observation in completed[0].observations} >= {
        ('crtsh', 'hostname', 'crt.example.com'),
        ('rapiddns', 'hostname', 'api.example.com'),
        ('rapiddns', 'hostname', 'reported.example.com'),
        ('rapiddns', 'ip-address', '192.0.2.20'),
    }
    assert 'reported.example.com:192.0.2.21' in json.loads(output_path.with_suffix('.json').read_text())['hosts']
    assert output_path.with_suffix('.jsonl').is_file()
    xml_pairs = [
        (element.findtext('hostname'), element.findtext('ip'))
        for element in ElementTree.parse(output_path.with_suffix('.xml')).getroot().findall('host')
    ]
    assert xml_pairs.count(('reported.example.com', '192.0.2.20')) == 1
    assert xml_pairs.count(('reported.example.com', '192.0.2.21')) == 1


@pytest.mark.asyncio
async def test_recursive_dns_requires_canonically_distinct_resolvers(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStash:
        async def do_init(self) -> None:
            return None

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '2001:db8::1,2001:0db8:0:0:0:0:0:1,192.0.2.53',
            '--dns-recursive-depth',
            '1',
        ],
    )

    with pytest.raises(ValueError, match='exactly three resolver vantages'):
        await theharvester_main.start()


@pytest.mark.asyncio
async def test_dns_proven_cname_hosts_reach_screenshot_filter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    visited: set[str] = set()

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

        async def store_completed_result(self, _result: CompletedResult) -> None:
            return None

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'address.example.com', 'alias.example.com', 'unresolved.example.com'}

    class FakeChecker:
        def __init__(self, hosts: list[str], _nameservers: list[str]) -> None:
            assert set(hosts) == {'address.example.com', 'alias.example.com', 'unresolved.example.com'}

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return (
                ['address.example.com:192.0.2.1', 'alias.example.com'],
                ['address.example.com', 'alias.example.com'],
                ['192.0.2.1'],
            )

    class FakeScreenShotter:
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            return None

        async def visit(self, host: str) -> tuple[str, str]:
            visited.add(host)
            return host, 'https'

        @staticmethod
        def chunk_list(values: list[str], _size: int) -> list[list[str]]:
            return [values]

        async def take_screenshot(self, host: str) -> ScreenshotCapture:
            return ScreenshotCapture(host, f'{host}.png', 3, hashlib.sha256(b'png').hexdigest())

    class FakePool:
        def __init__(self, _workers: int) -> None:
            pass

        async def __aenter__(self) -> 'FakePool':
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def map(self, function, values):
            return [await function(value) for value in values]

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(theharvester_main, 'Pool', FakePool)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53',
            '--screenshot',
            str(tmp_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert visited == {'address.example.com', 'alias.example.com'}


@pytest.mark.asyncio
async def test_direct_action_evidence_reaches_completed_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            pytest.fail('active results must not be stored as passive observations')

        async def store(self, *_args) -> None:
            pytest.fail('active results must not be stored as passive observations')

        async def store_completed_result(self, _result: CompletedResult) -> None:
            return None

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, proxy: bool) -> None:
            assert proxy is True
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class FakeChecker:
        def __init__(self, hosts: list[str], _nameservers: list[str]) -> None:
            self.hosts = hosts

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            if not self.hosts:
                return [], [], []
            return ['api.example.com:192.0.2.10'], ['api.example.com'], ['192.0.2.10']

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {
                ('api.example.com', '192.0.2.10'),
                ('api.example.com', '192.0.2.11'),
            }

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10', '192.0.2.11'}

    class FakeTakeOver:
        def __init__(self, hosts: list[str]) -> None:
            assert hosts == ['api.example.com']
            self.request_count = 2
            self.error_count = 1
            self.error_type = 'EmptyResponse'

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is True

        async def get_takeover_results(self) -> dict[str, list[dict[str, str]]]:
            return {'https://api.example.com': [{'No such app': 'Heroku'}]}

    class FakeScreenShotter:
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            return None

        async def visit(self, host: str) -> tuple[str, str]:
            return host, 'reachable'

        @staticmethod
        def chunk_list(values: list[str], _size: int) -> list[list[str]]:
            return [values]

        async def take_screenshot(self, host: str) -> ScreenshotCapture:
            path = tmp_path / f'{host}.png'
            path.write_bytes(b'png')  # noqa: ASYNC240 - tiny in-memory browser fixture
            return ScreenshotCapture(host, str(path), 3, hashlib.sha256(b'png').hexdigest())

    class FakeShodan:
        async def search_ip(self, ip: str) -> dict[str, dict[str, list[int]] | str]:
            if ip == '192.0.2.11':
                return {ip: 'request failed'}
            return {ip: {'ports': [443]}}

    class FakeApiScanner:
        execution_error_type = None
        request_error_count = 1

        def __init__(self, word: str, wordlist: str) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')

        async def do_search(self) -> None:
            return None

        def get_found_endpoints(self) -> set[str]:
            return {'/api/v1'}

        def get_interesting_endpoints(self) -> set[str]:
            return {'/api/v1'}

        def get_auth_required(self) -> set[str]:
            return set()

        def get_api_versions(self) -> set[str]:
            return {'v1'}

        def get_rate_limits(self) -> dict:
            return {}

        def get_methods(self) -> set[str]:
            return {'GET'}

        def get_status_codes(self) -> set[int]:
            return {200}

    class FakePool:
        def __init__(self, _workers: int) -> None:
            pass

        async def __aenter__(self) -> 'FakePool':
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def map(self, function, values):
            return [await function(value) for value in values]

    async def no_sleep(_seconds: float) -> None:
        return None

    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api/v1\n', encoding='utf-8')
    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeOver', FakeTakeOver)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', FakeShodan)
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', FakeApiScanner)
    monkeypatch.setattr(theharvester_main, 'Pool', FakePool)
    monkeypatch.setattr(theharvester_main.asyncio, 'sleep', no_sleep)

    result = await theharvester_main.start(
        EnumerationOptions(
            api_scan=True,
            dns_resolve='192.0.2.53',
            domain='example.com',
            proxies=True,
            quiet=True,
            screenshot=str(tmp_path),
            shodan=True,
            source='crtsh,rapiddns',
            take_over=True,
            wordlist=str(wordlist),
        ),
        include_breaches=True,
        return_completed_result=True,
    )

    completed = result[-1]
    assert isinstance(completed, CompletedResult)
    assert ('api-endpoint', '/api/v1') in completed.results
    assert ('screenshot', 'api.example.com') in completed.results
    assert ('shodan', '{"ip":"192.0.2.10","result":{"ports":[443]}}') in completed.results
    assert (
        'takeover',
        '{"matches":[{"No such app":"Heroku"}],"url":"https://api.example.com"}',
    ) in completed.results
    assert {execution.action for execution in completed.action_executions} == {
        'api-scan',
        'dns-resolve',
        'screenshot',
        'shodan',
        'takeover',
    }
    executions = {execution.action: execution for execution in completed.action_executions}
    assert executions['api-scan'].status == 'partial'
    assert executions['api-scan'].result_count == 3
    assert executions['shodan'].status == 'partial'
    assert executions['takeover'].status == 'partial'
    assert {(observation.action, observation.kind, observation.value) for observation in completed.action_observations} >= {
        ('api-scan', 'api-endpoint', '/api/v1'),
        ('api-scan', 'interesting-url', 'https://example.com/api/v1'),
        ('api-scan', 'url', 'https://example.com/api/v1'),
        ('dns-resolve', 'hostname', 'api.example.com'),
        ('dns-resolve', 'ip-address', '192.0.2.10'),
        ('screenshot', 'screenshot', 'api.example.com'),
        ('shodan', 'shodan', '{"ip":"192.0.2.10","result":{"ports":[443]}}'),
        (
            'takeover',
            'takeover',
            '{"matches":[{"No such app":"Heroku"}],"url":"https://api.example.com"}',
        ),
    }
    assert [artifact.to_dict() for artifact in completed.artifacts] == [
        {
            'action': 'screenshot',
            'result_kind': 'screenshot',
            'result_value': 'api.example.com',
            'path': str(tmp_path / 'api.example.com.png'),
            'media_type': 'image/png',
            'size_bytes': 3,
            'sha256': hashlib.sha256(b'png').hexdigest(),
        }
    ]


@pytest.mark.asyncio
async def test_dns_resolution_transport_failure_is_persisted_as_failed_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed: list[CompletedResult] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class FailedChecker:
        error_count = 3
        error_types = {'TimeoutError'}

        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            pass

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return [], [], []

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FailedChecker)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='crtsh', dns_resolve='192.0.2.53', quiet=True),
        return_completed_result=True,
    )

    returned = result[-1]
    assert isinstance(returned, CompletedResult)
    assert completed == [returned]
    execution = next(item for item in returned.action_executions if item.action == 'dns-resolve')
    assert execution.status == 'failed'
    assert execution.error_type == 'TimeoutError'
    assert execution.stop_reason == '3-query-errors'


@pytest.mark.asyncio
async def test_rest_dns_brute_result_is_persisted_before_early_return(monkeypatch: pytest.MonkeyPatch) -> None:
    completed: list[CompletedResult] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'seed.example.com'}

    class FakeDnsForce:
        error_count = 0
        error_types: set[str] = set()

        def __init__(self, _domain: str, _resolvers: list[str], verbose: bool) -> None:
            assert verbose is True

        async def run(self) -> tuple[list[str], list[str], list[str]]:
            return ['brute.example.com:192.0.2.55'], ['brute.example.com'], ['192.0.2.55']

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.dnssearch, 'DnsForce', FakeDnsForce)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='crtsh', dns_brute=True, quiet=True),
        return_dns_brute_result=True,
    )

    assert result == ['brute.example.com:192.0.2.55']
    assert len(completed) == 1
    assert ActionObservation('dns-brute', 'hostname', 'brute.example.com') in completed[0].action_observations
    assert next(item for item in completed[0].action_executions if item.action == 'dns-brute').status == 'succeeded'


@pytest.mark.asyncio
async def test_dns_brute_failure_is_persisted_before_propagating(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed: list[CompletedResult] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'seed.example.com'}

    class FailedDnsForce:
        def __init__(self, _domain: str, _resolvers: list[str], verbose: bool) -> None:
            assert verbose is True

        async def run(self) -> tuple[list[str], list[str], list[str]]:
            raise RuntimeError('brute resolver failed')

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.dnssearch, 'DnsForce', FailedDnsForce)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-c',
            '-f',
            str(tmp_path / 'failed'),
            '-q',
        ],
    )

    with pytest.raises(RuntimeError, match='brute resolver failed'):
        await theharvester_main.start(return_completed_result=True)

    assert len(completed) == 1
    execution = next(item for item in completed[0].action_executions if item.action == 'dns-brute')
    assert execution.status == 'failed'
    assert execution.error_type == 'RuntimeError'
    summary = json.loads((tmp_path / 'failed.jsonl').read_text().splitlines()[0])
    assert summary['action_executions'][0]['status'] == 'failed'


@pytest.mark.asyncio
async def test_dns_brute_cancellation_is_persisted_before_propagating(monkeypatch: pytest.MonkeyPatch) -> None:
    completed: list[CompletedResult] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'seed.example.com'}

    class CancelledDnsForce:
        def __init__(self, _domain: str, _resolvers: list[str], verbose: bool) -> None:
            assert verbose is True

        async def run(self) -> tuple[list[str], list[str], list[str]]:
            raise asyncio.CancelledError

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.dnssearch, 'DnsForce', CancelledDnsForce)

    with pytest.raises(asyncio.CancelledError):
        await theharvester_main.start(
            EnumerationOptions(domain='example.com', source='crtsh', dns_brute=True, quiet=True),
            return_completed_result=True,
        )

    assert len(completed) == 1
    execution = next(item for item in completed[0].action_executions if item.action == 'dns-brute')
    assert execution.status == 'partial'
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['api-scan', 'dns-reverse', 'screenshot', 'shodan', 'takeover'])
async def test_selected_action_cancellation_is_persisted_before_propagating(
    action: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed: list[CompletedResult] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {('api.example.com', '192.0.2.10')}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10'}

    options = {'domain': 'example.com', 'quiet': True, 'source': 'rapiddns'}
    expected_count = 0
    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.rapiddns, 'SearchRapidDns', FakeRapidDNS)

    if action == 'api-scan':
        wordlist = tmp_path / 'api.txt'
        wordlist.write_text('/api\n', encoding='utf-8')

        class CancelledApiScanner:
            def __init__(self, word: str, wordlist: str) -> None:
                assert word == 'example.com'
                assert wordlist == str(tmp_path / 'api.txt')

            async def do_search(self) -> None:
                raise asyncio.CancelledError

            def get_found_endpoints(self) -> set[str]:
                return {'/api'}

        monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', CancelledApiScanner)
        options.update(api_scan=True, wordlist=str(wordlist))
        expected_count = 1
    elif action == 'dns-reverse':

        async def cancelled_reverse(*, iprange: str, callback, nameservers) -> None:
            assert iprange == '192.0.2.0/24'
            assert nameservers is None
            callback('partial.example.com')
            raise asyncio.CancelledError

        monkeypatch.setattr(theharvester_main.dnssearch, 'serialize_ip_range', lambda **_kwargs: '192.0.2.0/24')
        monkeypatch.setattr(theharvester_main.dnssearch, 'reverse_all_ips_in_range', cancelled_reverse)
        options['dns_lookup'] = True
        expected_count = 1
    elif action == 'screenshot':

        class CancelledScreenShotter:
            def __init__(self, _output: str) -> None:
                pass

            def verify_path(self) -> bool:
                return True

            async def verify_installation(self) -> None:
                raise asyncio.CancelledError

        monkeypatch.setattr(theharvester_main, 'ScreenShotter', CancelledScreenShotter)
        options['screenshot'] = str(tmp_path)
    elif action == 'shodan':

        class CancelledShodan:
            async def search_ip(self, _ip: str) -> dict:
                raise asyncio.CancelledError

        monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', CancelledShodan)
        options['shodan'] = True
    else:

        class CancelledTakeOver:
            def __init__(self, _hosts: list[str]) -> None:
                pass

            async def populate_fingerprints(self) -> None:
                return None

            async def process(self, proxy: bool = False) -> None:
                assert proxy is False
                raise asyncio.CancelledError

            async def get_takeover_results(self) -> dict[str, list[str]]:
                return {'https://api.example.com': ['fingerprint']}

        monkeypatch.setattr(theharvester_main.takeover, 'TakeOver', CancelledTakeOver)
        options['take_over'] = True
        expected_count = 1

    with pytest.raises(asyncio.CancelledError):
        await theharvester_main.start(EnumerationOptions(**options), return_completed_result=True)

    assert len(completed) == 1
    execution = next(item for item in completed[0].action_executions if item.action == action)
    assert execution.status == 'partial'
    assert execution.result_count == expected_count
    assert execution.error_type == 'CancelledError'
    assert execution.stop_reason == 'cancelled'


@pytest.mark.asyncio
async def test_takeover_failure_is_persisted_before_propagating(monkeypatch: pytest.MonkeyPatch) -> None:
    completed: list[CompletedResult] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'seed.example.com'}

    class FailedTakeOver:
        def __init__(self, hosts: list[str]) -> None:
            assert hosts == ['seed.example.com']

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False
            raise RuntimeError('takeover transport failed')

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeOver', FailedTakeOver)

    with pytest.raises(RuntimeError, match='takeover transport failed'):
        await theharvester_main.start(
            EnumerationOptions(domain='example.com', source='crtsh', quiet=True, take_over=True),
            return_completed_result=True,
        )

    assert len(completed) == 1
    execution = next(item for item in completed[0].action_executions if item.action == 'takeover')
    assert execution.status == 'failed'
    assert execution.error_type == 'RuntimeError'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('execution_error_type', 'request_error_count'),
    [('RuntimeError', 0), (None, 1)],
)
async def test_api_scan_errors_without_results_are_persisted_as_failed_action(
    execution_error_type: str | None,
    request_error_count: int,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed: list[CompletedResult] = []
    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api\n', encoding='utf-8')

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'seed.example.com'}

    class FailedApiScanner:
        def __init__(self, word: str, wordlist: str) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')

        async def do_search(self) -> None:
            return None

        def get_found_endpoints(self) -> set[str]:
            return set()

        def get_interesting_endpoints(self) -> set[str]:
            return set()

        def get_auth_required(self) -> set[str]:
            return set()

        def get_api_versions(self) -> set[str]:
            return set()

        def get_rate_limits(self) -> dict:
            return {}

        def get_methods(self) -> set[str]:
            return set()

        def get_status_codes(self) -> set[int]:
            return set()

    FailedApiScanner.execution_error_type = execution_error_type
    FailedApiScanner.request_error_count = request_error_count

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', FailedApiScanner)

    result = await theharvester_main.start(
        EnumerationOptions(
            api_scan=True,
            domain='example.com',
            quiet=True,
            source='crtsh',
            wordlist=str(wordlist),
        ),
        return_completed_result=True,
    )

    returned = result[-1]
    assert isinstance(returned, CompletedResult)
    assert completed == [returned]
    execution = next(item for item in returned.action_executions if item.action == 'api-scan')
    assert execution.status == 'failed'
    assert execution.error_type == execution_error_type


@pytest.mark.asyncio
async def test_rest_no_filename_runs_requested_post_passive_actions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed: list[CompletedResult] = []
    wordlist = tmp_path / 'api.txt'
    wordlist.write_text('/api\n', encoding='utf-8')

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {('api.example.com', '192.0.2.10')}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10'}

    class FakeTakeOver:
        request_count = 2
        error_count = 0
        error_type = None

        def __init__(self, _hosts: list[str]) -> None:
            pass

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False

        async def get_takeover_results(self) -> dict:
            return {}

    class FakeShodan:
        async def search_ip(self, ip: str) -> dict:
            return {ip: {'ports': [443]}}

    class FakeApiScanner:
        execution_error_type = None
        request_error_count = 0

        def __init__(self, word: str, wordlist: str) -> None:
            assert word == 'example.com'
            assert wordlist == str(tmp_path / 'api.txt')

        async def do_search(self) -> None:
            return None

        def get_found_endpoints(self) -> set[str]:
            return {'/api'}

        def get_interesting_endpoints(self) -> set[str]:
            return set()

        def get_auth_required(self) -> set[str]:
            return set()

        def get_api_versions(self) -> set[str]:
            return set()

        def get_rate_limits(self) -> dict:
            return {}

        def get_methods(self) -> set[str]:
            return {'GET'}

        def get_status_codes(self) -> set[int]:
            return {200}

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(theharvester_main.takeover, 'TakeOver', FakeTakeOver)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', FakeShodan)
    monkeypatch.setattr(theharvester_main.api_endpoints, 'SearchApiEndpoints', FakeApiScanner)
    monkeypatch.setattr(theharvester_main.asyncio, 'sleep', no_sleep)

    result = await theharvester_main.start(
        EnumerationOptions(
            api_scan=True,
            domain='example.com',
            quiet=True,
            shodan=True,
            source='rapiddns',
            take_over=True,
            wordlist=str(wordlist),
        )
    )

    assert len(result) == 9
    assert len(completed) == 1
    assert {item.action for item in completed[0].action_executions} == {'api-scan', 'shodan', 'takeover'}


@pytest.mark.asyncio
async def test_invalid_dns_resolver_is_recorded_as_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, _result: CompletedResult) -> None:
            return None

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='crtsh', dns_resolve='not-an-ip', quiet=True),
        return_completed_result=True,
    )

    completed = result[-1]
    assert isinstance(completed, CompletedResult)
    execution = next(item for item in completed.action_executions if item.action == 'dns-resolve')
    assert execution.status == 'skipped'
    assert execution.stop_reason == 'no-valid-resolvers'


@pytest.mark.asyncio
async def test_shodan_all_target_errors_are_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, _result: CompletedResult) -> None:
            return None

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {('api.example.com', '192.0.2.10')}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10'}

    class FailedShodan:
        async def search_ip(self, ip: str) -> dict[str, str]:
            return {ip: 'request failed'}

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(theharvester_main.shodansearch, 'SearchShodan', FailedShodan)
    monkeypatch.setattr(theharvester_main.asyncio, 'sleep', no_sleep)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='rapiddns', shodan=True, quiet=True),
        return_completed_result=True,
    )

    completed = result[-1]
    assert isinstance(completed, CompletedResult)
    execution = next(item for item in completed.action_executions if item.action == 'shodan')
    assert execution.status == 'failed'
    assert execution.result_count == 0


@pytest.mark.asyncio
async def test_screenshot_redirect_deduplication_is_not_a_capture_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, _result: CompletedResult) -> None:
            return None

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'one.example.com', 'two.example.com'}

    class FakeScreenShotter:
        output = str(tmp_path)
        slash = '/'

        def __init__(self, _output: str) -> None:
            pass

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            return None

        async def visit(self, _host: str) -> tuple[str, str]:
            return 'https://canonical.example.com', 'reachable'

        @staticmethod
        def chunk_list(values: list[str], _size: int) -> list[list[str]]:
            return [values]

        async def take_screenshot(self, url: str) -> ScreenshotCapture:
            return ScreenshotCapture(url, str(tmp_path / 'canonical.png'), 3, hashlib.sha256(b'png').hexdigest())

    class FakePool:
        def __init__(self, _workers: int) -> None:
            pass

        async def __aenter__(self) -> 'FakePool':
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def map(self, function, values):
            return [await function(value) for value in values]

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FakeScreenShotter)
    monkeypatch.setattr(theharvester_main, 'Pool', FakePool)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='crtsh', screenshot=str(tmp_path), quiet=True),
        return_completed_result=True,
    )

    completed = result[-1]
    assert isinstance(completed, CompletedResult)
    execution = next(item for item in completed.action_executions if item.action == 'screenshot')
    assert execution.status == 'succeeded'
    assert execution.result_count == 1


@pytest.mark.asyncio
async def test_dns_brute_results_are_normalized_and_attributed(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

        async def store_completed_result(self, _result: CompletedResult) -> None:
            return None

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'seed.example.com'}

    class FakeDnsForce:
        def __init__(self, domain: str, resolvers: list[str], verbose: bool) -> None:
            assert domain == 'example.com'
            assert resolvers == []
            assert verbose is True

        async def run(self) -> tuple[list[str], list[str], list[str]]:
            return (
                ['brute.example.com:192.0.2.55'],
                ['brute.example.com'],
                ['192.0.2.55'],
            )

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.dnssearch, 'DnsForce', FakeDnsForce)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='crtsh', dns_brute=True, quiet=True),
        return_completed_result=True,
    )

    completed = result[-1]
    assert isinstance(completed, CompletedResult)
    assert ('hostname', 'brute.example.com') in completed.results
    assert ('ip-address', '192.0.2.55') in completed.results
    dns_brute_execution = next(execution for execution in completed.action_executions if execution.action == 'dns-brute')
    assert dns_brute_execution.status == 'succeeded'
    assert dns_brute_execution.result_count == 2
    assert {
        (observation.kind, observation.value)
        for observation in completed.action_observations
        if observation.action == 'dns-brute'
    } == {
        ('hostname', 'brute.example.com'),
        ('ip-address', '192.0.2.55'),
    }


@pytest.mark.asyncio
async def test_reverse_dns_results_are_attributed(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

        async def store_completed_result(self, _result: CompletedResult) -> None:
            return None

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'seed.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {('seed.example.com', '192.0.2.10')}

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10'}

    async def fake_reverse(*, iprange: str, callback, nameservers) -> None:
        assert iprange == '192.0.2.0/24'
        assert nameservers is None
        callback('ptr.example.com')

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(theharvester_main.dnssearch, 'serialize_ip_range', lambda **_kwargs: '192.0.2.0/24')
    monkeypatch.setattr(theharvester_main.dnssearch, 'reverse_all_ips_in_range', fake_reverse)

    result = await theharvester_main.start(
        EnumerationOptions(domain='example.com', source='rapiddns', dns_lookup=True, quiet=True),
        return_completed_result=True,
    )

    completed = result[-1]
    assert isinstance(completed, CompletedResult)
    assert ('hostname', 'ptr.example.com') in completed.results
    reverse_execution = next(execution for execution in completed.action_executions if execution.action == 'dns-reverse')
    assert reverse_execution.status == 'succeeded'
    assert reverse_execution.result_count == 1
    assert ActionObservation('dns-reverse', 'hostname', 'ptr.example.com') in completed.action_observations


@pytest.mark.asyncio
async def test_reverse_dns_failure_cancels_siblings_and_persists_before_propagating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed: list[CompletedResult] = []
    sibling_started = asyncio.Event()
    sibling_cancelled = asyncio.Event()

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeRapidDNS:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'one.example.com', 'two.example.com'}

        async def get_host_ip_pairs(self) -> set[tuple[str, str]]:
            return {
                ('one.example.com', '192.0.2.10'),
                ('two.example.com', '198.51.100.10'),
            }

        async def get_ips(self) -> set[str]:
            return {'192.0.2.10', '198.51.100.10'}

    async def fake_reverse(*, iprange: str, callback, nameservers) -> None:
        assert nameservers is None
        if iprange == '198.51.100.0/24':
            await sibling_started.wait()
            raise RuntimeError('resolver failed')
        sibling_started.set()
        callback('partial.example.com')
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            sibling_cancelled.set()
            raise

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.rapiddns, 'SearchRapidDns', FakeRapidDNS)
    monkeypatch.setattr(theharvester_main.dnssearch, 'reverse_all_ips_in_range', fake_reverse)

    with pytest.raises(RuntimeError, match='resolver failed'):
        await theharvester_main.start(
            EnumerationOptions(domain='example.com', source='rapiddns', dns_lookup=True, quiet=True),
            return_completed_result=True,
        )

    assert sibling_cancelled.is_set()
    assert len(completed) == 1
    execution = next(item for item in completed[0].action_executions if item.action == 'dns-reverse')
    assert execution.status == 'partial'
    assert execution.result_count == 1
    assert execution.error_type == 'RuntimeError'
    assert ActionObservation('dns-reverse', 'hostname', 'partial.example.com') in completed[0].action_observations


@pytest.mark.asyncio
async def test_screenshot_setup_failure_is_persisted_before_propagating(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed: list[CompletedResult] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class FailedScreenShotter:
        def __init__(self, _output: str) -> None:
            pass

        def verify_path(self) -> bool:
            return True

        async def verify_installation(self) -> None:
            raise RuntimeError('browser unavailable')

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main, 'ScreenShotter', FailedScreenShotter)

    with pytest.raises(RuntimeError, match='browser unavailable'):
        await theharvester_main.start(
            EnumerationOptions(
                domain='example.com',
                source='crtsh',
                quiet=True,
                screenshot=str(tmp_path),
            ),
            return_completed_result=True,
        )

    assert len(completed) == 1
    execution = next(item for item in completed[0].action_executions if item.action == 'screenshot')
    assert execution.status == 'failed'
    assert execution.error_type == 'RuntimeError'


@pytest.mark.parametrize(
    ('recursive_stop_reason', 'expected_execution_status'),
    [('depth-limit', 'succeeded'), ('query-limit', 'partial')],
)
@pytest.mark.asyncio
async def test_recursive_dns_results_reach_completed_output_without_changing_legacy_shapes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    recursive_stop_reason: str,
    expected_execution_status: str,
) -> None:
    completed: list[CompletedResult] = []
    captured: list[tuple[str, tuple[str, ...], int, int]] = []
    output_path = tmp_path / 'recursive-dns'

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            pytest.fail('recursive DNS must not be stored as passive observations')

        async def store(self, *_args) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed.append(result)

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class FakeChecker:
        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            pass

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['api.example.com:192.0.2.1'], ['api.example.com'], ['192.0.2.1']

    class FakeResolver:
        def __init__(self, nameserver: str, target: str) -> None:
            self.name = nameserver
            assert target == 'example.com'

        async def close(self) -> None:
            return None

    async def fake_recursive(target, seeds, _labels, _resolvers, limits):
        captured.append((target, tuple(seeds), limits.depth, limits.query_limit))
        return RecursiveDNSResult(
            findings=(
                RecursiveDNSFinding(
                    'dev.api.example.com',
                    'api.example.com',
                    HostDnsRecords(ipv4=('192.0.2.2',), ipv6=('2001:db8::2',)),
                    ('ptr.example.net',),
                ),
            ),
            query_count=24,
            depth_reached=1,
            zero_yield_batches=0,
            stop_reason=recursive_stop_reason,
            classifications=(
                RecursiveDNSClassification(
                    'unused.api.example.com',
                    'api.example.com',
                    Addressability.NOT_CURRENT,
                    HostDnsRecords(cnames=('missing.vendor.test',)),
                    ('legacy-ptr.example.net',),
                ),
            ),
        )

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main, 'AioDNSResolverVantage', FakeResolver)
    monkeypatch.setattr(theharvester_main, 'discover_recursive_dns', fake_recursive)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53,192.0.2.54,192.0.2.55',
            '--dns-recursive-depth',
            '1',
            '-f',
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert captured == [('example.com', ('api.example.com',), 1, 3_000)]
    assert completed
    assert ('hostname', 'dev.api.example.com') in completed[0].results
    assert ('ip-address', '192.0.2.2') in completed[0].results
    assert ('ip-address', '2001:db8::2') in completed[0].results
    assert (
        'dns-recursive-finding',
        json.dumps(
            {
                'addresses': ['192.0.2.2', '2001:db8::2'],
                'hostname': 'dev.api.example.com',
                'parent': 'api.example.com',
                'ptrs': ['ptr.example.net'],
            },
            separators=(',', ':'),
            sort_keys=True,
        ),
    ) in completed[0].results
    assert set(json.loads(output_path.with_suffix('.json').read_text())['hosts']) >= {
        'dev.api.example.com:192.0.2.2',
        'dev.api.example.com:2001:db8::2',
    }
    xml_pairs = [
        (element.findtext('hostname'), element.findtext('ip'))
        for element in ElementTree.parse(output_path.with_suffix('.xml')).getroot().findall('host')
    ]
    assert xml_pairs.count(('dev.api.example.com', '192.0.2.2')) == 1
    assert xml_pairs.count(('dev.api.example.com', '2001:db8::2')) == 1
    assert not any(ip is not None and ',' in ip for _host, ip in xml_pairs)
    assert (
        'dns-recursive-summary',
        json.dumps(
            {
                'depth_reached': 1,
                'query_count': 24,
                'stop_reason': recursive_stop_reason,
                'zero_yield_batches': 0,
            },
            separators=(',', ':'),
            sort_keys=True,
        ),
    ) in completed[0].results
    assert (
        'dns-recursive-classification',
        json.dumps(
            {
                'addressability': 'not-currently-addressable',
                'addresses': [],
                'cnames': ['missing.vendor.test'],
                'hostname': 'unused.api.example.com',
                'parent': 'api.example.com',
                'ptrs': ['legacy-ptr.example.net'],
            },
            separators=(',', ':'),
            sort_keys=True,
        ),
    ) in completed[0].results
    recursive_execution = next(execution for execution in completed[0].action_executions if execution.action == 'dns-recursive')
    assert recursive_execution.status == expected_execution_status
    assert recursive_execution.result_count == 6
    assert recursive_execution.stop_reason == recursive_stop_reason
    recursive_observations = {
        (observation.kind, observation.value)
        for observation in completed[0].action_observations
        if observation.action == 'dns-recursive'
    }
    assert {
        ('hostname', 'dev.api.example.com'),
        ('ip-address', '192.0.2.2'),
        ('ip-address', '2001:db8::2'),
    } <= recursive_observations
    assert {kind for kind, _value in recursive_observations} >= {
        'dns-recursive-finding',
        'dns-recursive-classification',
        'dns-recursive-summary',
    }


@pytest.mark.parametrize('error_type', [RuntimeError, asyncio.CancelledError])
@pytest.mark.asyncio
async def test_recursive_dns_closes_resolvers_on_failure_and_preserves_cancellation(
    monkeypatch: pytest.MonkeyPatch, error_type: type[BaseException]
) -> None:
    closed: list[str] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

        async def store_completed_result(self, _result: CompletedResult) -> None:
            return None

    class FakeCrtsh:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'api.example.com'}

    class FakeChecker:
        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            pass

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['api.example.com:192.0.2.1'], ['api.example.com'], ['192.0.2.1']

    class FakeResolver:
        def __init__(self, nameserver: str, _target: str) -> None:
            self.name = nameserver

        async def close(self) -> None:
            closed.append(self.name)

    async def fail_recursive(*_args, **_kwargs):
        raise error_type()

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtsh)
    monkeypatch.setattr(theharvester_main.hostchecker, 'Checker', FakeChecker)
    monkeypatch.setattr(theharvester_main, 'AioDNSResolverVantage', FakeResolver)
    monkeypatch.setattr(theharvester_main, 'discover_recursive_dns', fail_recursive)
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53,192.0.2.54,192.0.2.55',
            '--dns-recursive-depth',
            '1',
        ],
    )

    if issubclass(error_type, asyncio.CancelledError):
        with pytest.raises(asyncio.CancelledError):
            await theharvester_main.start()
    else:
        with pytest.raises(SystemExit) as exit_info:
            await theharvester_main.start()
        assert exit_info.value.code == 0

    assert sorted(closed) == ['192.0.2.53', '192.0.2.54', '192.0.2.55']

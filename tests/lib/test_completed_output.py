from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING, ClassVar
from xml.etree import ElementTree

import pytest

from theHarvester.lib.output import (
    evidence_xml_fragment,
    format_run_terminal,
    legacy_json_result,
    run_result_jsonl,
)
from theHarvester.lib.run import (
    Derivation,
    DNSResponse,
    RunResult,
    SourceFinding,
    SourceRateLimitedError,
    SourceStatus,
    SQLiteRunStore,
    StageFinding,
    StageFindingKind,
    StageResult,
    complete_run,
    execute_run,
)

if TYPE_CHECKING:
    from pathlib import Path


class CompletedRunSource:
    name = 'fixture'
    family = 'fixture-family'

    async def collect(self, _target: str) -> list[SourceFinding]:
        return [
            SourceFinding(
                'api.example.com',
                observed_at=datetime(2026, 7, 15, 12, tzinfo=UTC),
            ),
            SourceFinding('old.example.com'),
            SourceFinding('related.example.net', Derivation.RELATED),
            SourceFinding('cdn.vendor.test', Derivation.EXTERNAL_RELATIONSHIP),
            SourceFinding('mixed.example.net', Derivation.RELATED),
            SourceFinding('mixed.example.net', Derivation.EXTERNAL_RELATIONSHIP),
        ]


class CompletedRunResolver:
    def __init__(self, name: str) -> None:
        self.name = name

    async def query(self, hostname: str) -> DNSResponse:
        if hostname == 'api.example.com':
            return DNSResponse(ipv4=('192.0.2.10',), ttl=60)
        return DNSResponse(rcode='NXDOMAIN')


class IncompleteRunSource:
    name = 'fixture'
    family = 'fixture-family'

    def __init__(self, error: Exception) -> None:
        self.error = error

    async def collect(self, _target: str) -> list[SourceFinding]:
        raise self.error


@pytest.mark.asyncio
async def test_one_completed_run_drives_every_output_surface_without_losing_legacy_fields(
    tmp_path: Path,
) -> None:
    store = SQLiteRunStore(tmp_path / 'evidence.sqlite')
    result = await execute_run(
        'example.com',
        CompletedRunSource(),
        resolver_vantages=tuple(CompletedRunResolver(f'resolver-{index}') for index in range(3)),
        persist=False,
    )
    result = complete_run(
        result,
        (
            StageResult(
                'action:dns-brute',
                SourceStatus.SUCCEEDED,
                1,
                1,
                (StageFinding(StageFindingKind.HOSTNAME, 'late.example.com:192.0.2.11'),),
            ),
            StageResult(
                'action:take-over',
                SourceStatus.SUCCEEDED,
                1,
                1,
                (StageFinding(StageFindingKind.TAKEOVER, 'api.example.com', 'not vulnerable'),),
            ),
            StageResult(
                'action:api-scan',
                SourceStatus.SUCCEEDED,
                1,
                1,
                (StageFinding(StageFindingKind.API_ENDPOINT, '/v1/status', '200'),),
            ),
        ),
    )
    await store.save(result)

    terminal = format_run_terminal(result)
    records = [json.loads(line) for line in run_result_jsonl(result).splitlines()]
    legacy_json = legacy_json_result(result, {'cmd': 'theHarvester -d example.com', 'emails': ['ops@example.com']})
    evidence_xml = ElementTree.fromstring(evidence_xml_fragment(result))
    rest = legacy_json_result(result, {'emails': ['ops@example.com']})

    assert terminal.count('api.example.com') == 1
    assert terminal.count('old.example.com') == 1
    assert terminal.count('related.example.net') == 1
    assert terminal.count('cdn.vendor.test') == 1
    assert terminal.count('mixed.example.net') == 1
    assert terminal.count('late.example.com') == 1
    assert 'takeover=not vulnerable' in terminal
    assert '/v1/status [api-endpoint=200; source=action:api-scan]' in terminal
    assert 'Currently addressable subdomains (1)' in terminal
    assert 'Secondary evidence / needs review (4)' in terminal
    assert 'Scope-extension candidates (1)' in terminal
    assert 'status=currently-addressable; sources=fixture' in terminal
    assert 'Run status: complete' in terminal

    assert {record['record_type'] for record in records} == {
        'run',
        'source_execution',
        'discovery_observation',
        'dns_validation_observation',
        'merged_result',
        'selected_observation',
    }
    assert all(record['schema_version'] == 'theharvester-evidence-v1' for record in records)
    assert all(record['run_id'] == result.run_id for record in records)
    assert all(record['target'] == 'example.com' for record in records)
    run_record = next(record['data'] for record in records if record['record_type'] == 'run')
    assert run_record['record_counts'] == {
        'source_executions': sum(record['record_type'] == 'source_execution' for record in records),
        'discovery_observations': sum(record['record_type'] == 'discovery_observation' for record in records),
        'dns_validation_observations': sum(record['record_type'] == 'dns_validation_observation' for record in records),
        'merged_results': sum(record['record_type'] == 'merged_result' for record in records),
        'selected_observations': sum(record['record_type'] == 'selected_observation' for record in records),
    }
    discovery_records = [record['data'] for record in records if record['record_type'] == 'discovery_observation']
    assert all(record['collected_at'] for record in discovery_records)
    assert discovery_records[0]['provider_observed_at'] == '2026-07-15T12:00:00+00:00'
    assert 'provider_observed_at' not in discovery_records[1]
    validation_records = [record['data'] for record in records if record['record_type'] == 'dns_validation_observation']
    assert all(record['validated_at'] for record in validation_records)

    assert legacy_json['cmd'] == 'theHarvester -d example.com'
    assert legacy_json['emails'] == ['ops@example.com']
    assert legacy_json['hosts'] == ['api.example.com']
    assert legacy_json['evidence_run']['status'] == 'complete'
    selected_records = [record['data'] for record in records if record['record_type'] == 'selected_observation']
    assert {(record['kind'], record['value'], record['detail']) for record in selected_records} == {
        ('takeover', 'api.example.com', 'not vulnerable'),
        ('api-endpoint', '/v1/status', '200'),
    }
    assert evidence_xml.attrib['status'] == 'complete'
    assert {item.attrib['kind'] for item in evidence_xml.findall('selected_observation')} == {
        'takeover',
        'api-endpoint',
    }
    assert rest['emails'] == ['ops@example.com']
    assert rest['hosts'] == ['api.example.com']
    assert rest['evidence_run']['run_id'] == result.run_id
    assert await store.load(result.run_id) == result.to_dict()


def test_filename_help_names_every_report_format() -> None:
    from theHarvester.__main__ import build_parser

    assert 'Save XML, legacy JSON, and normalized JSONL reports.' in build_parser().format_help()


@pytest.mark.parametrize(
    ('error', 'expected_run_status', 'expected_source_status'),
    [
        (RuntimeError('provider failed'), 'failed', 'failed'),
        (SourceRateLimitedError(), 'partial', 'rate-limited'),
    ],
)
@pytest.mark.asyncio
async def test_incomplete_source_states_are_visible_on_every_completed_output(
    tmp_path: Path,
    error: Exception,
    expected_run_status: str,
    expected_source_status: str,
) -> None:
    result = await execute_run(
        'example.com',
        IncompleteRunSource(error),
        store=SQLiteRunStore(tmp_path / f'{expected_source_status}.sqlite'),
    )

    terminal = format_run_terminal(result)
    records = [json.loads(line) for line in run_result_jsonl(result).splitlines()]

    assert f'Run status: {expected_run_status}' in terminal
    assert f'fixture [status={expected_source_status}' in terminal
    assert records[0]['data']['status'] == expected_run_status
    assert legacy_json_result(result)['evidence_run']['status'] == expected_run_status
    assert legacy_json_result(result)['evidence_run']['source_executions'][0]['status'] == expected_source_status
    assert ElementTree.fromstring(evidence_xml_fragment(result)).attrib['status'] == expected_run_status


@pytest.mark.asyncio
async def test_empty_and_failed_selected_stages_remain_visible() -> None:
    result = await execute_run('example.com', CompletedRunSource(), persist=False)
    result = complete_run(
        result,
        (
            StageResult('action:api-scan', SourceStatus.EMPTY, 2, 0),
            StageResult(
                'action:take-over',
                SourceStatus.FAILED,
                3,
                0,
                error_type='RuntimeError',
            ),
        ),
    )

    executions = {execution.source: execution for execution in result.source_executions}
    assert executions['action:api-scan'].status is SourceStatus.EMPTY
    assert executions['action:take-over'].status is SourceStatus.FAILED
    assert result.status == 'partial'
    assert 'action:take-over [status=failed' in format_run_terminal(result)


@pytest.mark.asyncio
async def test_cli_adapts_and_persists_the_run_only_after_selected_direct_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import theHarvester.__main__ as main_module
    import theHarvester.lib.output as output_module
    import theHarvester.lib.run as run_module

    events: list[str] = []

    class FakeParser:
        def parse_args(self):
            return SimpleNamespace(
                api_scan=True,
                dns_brute=True,
                dns_lookup=True,
                dns_resolve='192.0.2.53,192.0.2.54,192.0.2.55',
                dns_server=None,
                domain='example.com',
                filename=str(tmp_path / 'completed-run'),
                limit=500,
                proxies=False,
                quiet=False,
                screenshot='',
                shodan=False,
                source='crtsh',
                start=0,
                take_over=True,
                wordlist='',
            )

    class FakeCrtshSearch:
        def __init__(self, _target: str) -> None:
            return None

        async def process(self, _proxy: bool = False) -> None:
            events.append('collect')

        async def get_hostnames(self) -> list[str]:
            return ['api.example.com']

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store(self, *_args) -> None:
            return None

    class FakeRunStore:
        saved: ClassVar[list[RunResult]] = []

        async def save(self, _result) -> None:
            events.append('persist')
            self.saved.append(_result)

    class FakeHostChecker:
        def __init__(self, _hosts: list[str], _nameservers: list[str]) -> None:
            return None

        async def check(self):
            return ['api.example.com:192.0.2.10'], ['api.example.com'], ['192.0.2.10']

    class FakeResolver:
        def __init__(self, nameserver: str) -> None:
            self.name = nameserver

        async def query(self, hostname: str) -> DNSResponse:
            if hostname == 'api.example.com':
                return DNSResponse(ipv4=('192.0.2.10',))
            return DNSResponse(rcode='NXDOMAIN')

        async def close(self) -> None:
            return None

    class FakeDnsForce:
        def __init__(self, *_args, **_kwargs) -> None:
            return None

        async def run(self):
            events.append('dns-brute')
            return (
                ['late.example.com:192.0.2.11', 'late.example.com:192.0.2.11'],
                ['late.example.com'],
                ['192.0.2.11'],
            )

    class FakeTakeOver:
        def __init__(self, _hosts: list[str]) -> None:
            return None

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, *, proxy: bool) -> None:
            assert proxy is False
            events.append('direct')

        async def get_takeover_results(self) -> dict[str, str]:
            return {'api.example.com': 'not vulnerable'}

    async def fake_reverse_all_ips_in_range(*, callback, **_kwargs) -> None:
        events.append('reverse')
        callback('ptr.example.com')

    class FakeApiScanner:
        def __init__(self, *_args, **_kwargs) -> None:
            return None

        async def do_search(self) -> None:
            events.append('api-scan')

        def get_found_endpoints(self):
            return {'https://example.com/v1/status': SimpleNamespace(status_code=200)}

        def get_interesting_endpoints(self):
            return {}

        def get_auth_required(self):
            return {}

        def get_api_versions(self):
            return set()

        def get_rate_limits(self):
            return {}

        def get_methods(self):
            return {'GET'}

        def get_status_codes(self):
            return {200}

    def capture_terminal(result) -> str:
        events.append('terminal')
        return output_module.format_run_terminal(result)

    def capture_legacy_json(result, existing):
        events.append('legacy-json')
        return output_module.legacy_json_result(result, existing)

    def capture_jsonl(result) -> str:
        events.append('jsonl')
        return output_module.run_result_jsonl(result)

    monkeypatch.setattr(main_module, 'build_parser', lambda: FakeParser())
    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module.hostchecker, 'Checker', FakeHostChecker)
    monkeypatch.setattr(main_module, 'AioDNSResolverVantage', FakeResolver)
    monkeypatch.setattr(main_module.dnssearch, 'DnsForce', FakeDnsForce)
    monkeypatch.setattr(main_module.dnssearch, 'serialize_ip_range', lambda **_kwargs: '192.0.2.0/24')
    monkeypatch.setattr(main_module.dnssearch, 'reverse_all_ips_in_range', fake_reverse_all_ips_in_range)
    monkeypatch.setattr(main_module.takeover, 'TakeOver', FakeTakeOver)
    monkeypatch.setattr(main_module.api_endpoints, 'SearchApiEndpoints', FakeApiScanner)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', FakeRunStore)
    monkeypatch.setattr(run_module, 'SQLiteRunStore', FakeRunStore)
    monkeypatch.setattr(main_module, 'format_run_terminal', capture_terminal)
    monkeypatch.setattr(main_module, 'legacy_json_result', capture_legacy_json)
    monkeypatch.setattr(main_module, 'run_result_jsonl', capture_jsonl)

    with pytest.raises(SystemExit) as exit_info:
        await main_module.start()

    assert exit_info.value.code == 0
    assert events == [
        'collect',
        'dns-brute',
        'reverse',
        'direct',
        'api-scan',
        'persist',
        'terminal',
        'legacy-json',
        'jsonl',
    ]
    persisted = FakeRunStore.saved[0]
    assert {entity.value for entity in persisted.entities} >= {
        'late.example.com',
        'ptr.example.com',
    }
    assert {(item.kind, item.value, item.detail) for item in persisted.selected_observations} == {
        ('takeover', 'api.example.com', 'not vulnerable'),
        ('api-endpoint', 'https://example.com/v1/status', '200'),
    }
    dns_execution = next(item for item in persisted.source_executions if item.source == 'action:dns-brute')
    assert dns_execution.result_count == 2
    assert dns_execution.observation_count == 1


@pytest.mark.asyncio
async def test_mixed_rest_sources_share_one_completed_persisted_run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import theHarvester.__main__ as main_module

    class FakeCrtshSearch:
        def __init__(self, _target: str) -> None:
            return None

        async def process(self, _proxy: bool = False) -> None:
            return None

        async def get_hostnames(self) -> list[str]:
            return ['red.example.com']

    class FakeBaiduSearch:
        def __init__(self, _target: str, _limit: int) -> None:
            return None

        async def process(self, _proxy: bool = False) -> None:
            return None

        async def get_hostnames(self) -> list[str]:
            return ['blue.example.com']

        async def get_emails(self) -> list[str]:
            return ['blue-team@example.com']

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

    saved: list[RunResult] = []

    class FakeRunStore:
        async def save(self, result: RunResult) -> None:
            saved.append(result)

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module.baidusearch, 'SearchBaidu', FakeBaiduSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', FakeRunStore)

    response = await main_module.start(
        SimpleNamespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=500,
            proxies=False,
            quiet=False,
            screenshot='',
            shodan=False,
            source='baidu,crtsh',
            start=0,
            take_over=False,
            wordlist='',
        ),
        return_evidence_run=True,
    )

    result = response[-1]
    assert result is saved[0]
    assert {entity.value for entity in result.entities} == {'blue.example.com', 'red.example.com'}
    assert {execution.source.casefold() for execution in result.source_executions} == {'baidu', 'crtsh'}
    assert {execution.source_family for execution in result.source_executions} == {
        'web-search',
        'certificate-transparency',
    }
    assert {(item.kind, item.value) for item in result.selected_observations} == {
        (StageFindingKind.EMAIL, 'blue-team@example.com')
    }
    assert response[8] == ['blue.example.com', 'red.example.com']
    records = [json.loads(line) for line in run_result_jsonl(result).splitlines()]
    assert {record['data']['source'].casefold() for record in records if record['record_type'] == 'source_execution'} == {
        'baidu',
        'crtsh',
    }
    rest = legacy_json_result(result, {'hosts': response[8]})
    assert rest['evidence_run']['run_id'] == result.run_id
    terminal = capsys.readouterr().out
    assert terminal.count('blue.example.com') == 1
    assert terminal.count('red.example.com') == 1
    assert terminal.count('blue-team@example.com') == 1


@pytest.mark.asyncio
async def test_rest_dns_brute_finishes_and_returns_the_same_persisted_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import theHarvester.__main__ as main_module

    class FakeDnsForce:
        def __init__(self, *_args, **_kwargs) -> None:
            return None

        async def run(self):
            return ['late.example.com:192.0.2.11'], ['late.example.com'], ['192.0.2.11']

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

    saved: list[RunResult] = []

    class FakeRunStore:
        async def save(self, result: RunResult) -> None:
            saved.append(result)

    monkeypatch.setattr(main_module.dnssearch, 'DnsForce', FakeDnsForce)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'SQLiteRunStore', FakeRunStore)

    response = await main_module.start(
        SimpleNamespace(
            api_scan=False,
            dns_brute=True,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=500,
            proxies=False,
            quiet=False,
            screenshot='',
            shodan=False,
            source='',
            start=0,
            take_over=False,
            wordlist='',
        ),
        return_evidence_run=True,
    )

    result = response[-1]
    assert result is saved[0]
    assert response[8] == ['late.example.com:192.0.2.11']
    assert {entity.value for entity in result.entities} == {'late.example.com'}
    execution = next(item for item in result.source_executions if item.source == 'action:dns-brute')
    assert execution.status is SourceStatus.SUCCEEDED
    assert legacy_json_result(result, {'hosts': response[8]})['evidence_run']['status'] == 'complete'

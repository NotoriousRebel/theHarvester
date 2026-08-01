from __future__ import annotations

import asyncio
from uuid import UUID

import pytest

from theHarvester.lib.dns_validation import Addressability, DnsResponse, DnsValidator
from theHarvester.lib.run import (
    Derivation,
    ScopeClass,
    SourceRateLimitedError,
    SourceStatus,
    execute_run,
    legacy_dns_results,
    legacy_hostnames,
)


class FakePassiveSource:
    name = 'fixture'

    async def collect(self, target: str) -> list[str]:
        assert target == 'example.com'
        return [
            'WWW.Example.COM.',
            'www.example.com',
            'example.com.evil.test',
            'cdn.vendor.test',
        ]


@pytest.mark.asyncio
async def test_execute_run_propagates_cancellation() -> None:
    class CancelledSource:
        name = 'cancelled'

        async def collect(self, _target: str) -> list[str]:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await execute_run('example.com', (CancelledSource(),))


@pytest.mark.asyncio
async def test_execute_run_records_scoped_normalized_evidence_end_to_end() -> None:
    result = await execute_run('Example.COM.', (FakePassiveSource(),))
    next_result = await execute_run('example.com', (FakePassiveSource(),))

    assert UUID(result.run_id)
    assert result.run_id != next_result.run_id
    assert result.target == 'example.com'
    assert len(result.source_executions) == 1
    execution = result.source_executions[0]
    assert execution.status is SourceStatus.SUCCEEDED
    assert execution.duration_ms >= 0
    assert execution.result_count == 4
    assert execution.observation_count == 4
    assert execution.entity_count == 3

    assert [(item.value, item.scope_class) for item in result.observations] == [
        ('www.example.com', ScopeClass.IN_SCOPE),
        ('www.example.com', ScopeClass.IN_SCOPE),
        ('example.com.evil.test', ScopeClass.SCOPE_EXTENSION),
        ('cdn.vendor.test', ScopeClass.SCOPE_EXTENSION),
    ]
    assert all(item.source == 'fixture' for item in result.observations)
    assert all(item.collected_at.tzinfo is not None for item in result.observations)
    assert [item.derivation for item in result.observations] == [
        Derivation.PROVIDER,
        Derivation.PROVIDER,
        Derivation.PROVIDER,
        Derivation.PROVIDER,
    ]

    merged = {item.value: item for item in result.entities}
    assert len(merged['www.example.com'].observations) == 2
    assert merged['www.example.com'].scope_classes == (ScopeClass.IN_SCOPE,)
    assert legacy_hostnames(result) == ['www.example.com']


@pytest.mark.asyncio
async def test_execute_run_does_not_persist_implicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    import theHarvester.lib.run as run_module

    def fail_on_stash_access():
        raise AssertionError('execute_run must remain an in-memory operation')

    monkeypatch.setattr(run_module, 'StashManager', fail_on_stash_access, raising=False)

    result = await execute_run('example.com', (FakePassiveSource(),))

    assert result.target == 'example.com'


class OutcomeSource:
    name = 'outcome'

    def __init__(self, outcome: list[str] | Exception) -> None:
        self.outcome = outcome

    async def collect(self, _target: str) -> list[str]:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.mark.parametrize(
    ('outcome', 'expected'),
    [
        ([], SourceStatus.EMPTY),
        (RuntimeError('provider failed'), SourceStatus.FAILED),
    ],
)
@pytest.mark.asyncio
async def test_execute_run_records_non_success_source_outcomes(
    caplog: pytest.LogCaptureFixture,
    outcome: list[str] | Exception,
    expected: SourceStatus,
) -> None:
    result = await execute_run('example.com', (OutcomeSource(outcome),))

    assert len(result.source_executions) == 1
    execution = result.source_executions[0]
    assert execution.status is expected
    assert execution.duration_ms >= 0
    assert execution.result_count == 0
    assert execution.observation_count == 0
    assert execution.entity_count == 0
    assert result.observations == ()
    assert result.entities == ()
    if expected is SourceStatus.FAILED:
        assert 'Source outcome failed' in caplog.text


@pytest.mark.asyncio
async def test_execute_run_groups_multiple_sources_under_one_run() -> None:
    class CorroboratingSource:
        name = 'corroborating'

        async def collect(self, _target: str) -> list[str]:
            return ['www.example.com', 'example.com', '']

    result = await execute_run('example.com', (FakePassiveSource(), CorroboratingSource()))

    assert [execution.source for execution in result.source_executions] == ['fixture', 'corroborating']
    corroborating_execution = result.source_executions[1]
    assert corroborating_execution.status is SourceStatus.SUCCEEDED
    assert corroborating_execution.result_count == 3
    assert corroborating_execution.observation_count == 2
    assert legacy_hostnames(result) == ['www.example.com']


@pytest.mark.asyncio
async def test_execute_run_classifies_once_and_bridges_current_dns_results() -> None:
    candidate = 'api.example.com'

    class CandidateSource:
        name = 'fixture'

        async def collect(self, _target: str) -> list[str]:
            return [candidate]

    class Vantage:
        def __init__(self, name: str, address: str) -> None:
            self.name = name
            self.address = address

        async def query(self, hostname: str) -> DnsResponse:
            return DnsResponse(ipv4=(self.address,)) if hostname == candidate else DnsResponse(rcode='NXDOMAIN')

    validator = DnsValidator(
        (
            Vantage('resolver-a', '192.0.2.10'),
            Vantage('resolver-b', '192.0.2.11'),
            Vantage('resolver-c', '192.0.2.12'),
        )
    )

    result = await execute_run('example.com', (CandidateSource(),), dns_validator=validator)

    assert result.entities[0].addressability is Addressability.CURRENT
    assert legacy_hostnames(result, 'fixture') == [candidate]
    assert legacy_dns_results(result, 'fixture') == (
        ['api.example.com:192.0.2.10,192.0.2.11,192.0.2.12'],
        [candidate],
        ['192.0.2.10', '192.0.2.11', '192.0.2.12'],
    )
    control_names = {
        observation.query_name for observation in result.dns_validations if observation.is_wildcard_control
    }
    assert not control_names.intersection(observation.value for observation in result.observations)
    assert not control_names.intersection(entity.value for entity in result.entities)


@pytest.mark.asyncio
async def test_crtsh_bridge_executes_once_and_feeds_legacy_consumers(monkeypatch: pytest.MonkeyPatch) -> None:
    import argparse

    import theHarvester.__main__ as main_module
    import theHarvester.lib.run as run_module

    process_calls: list[bool] = []

    class FakeCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, proxy: bool = False) -> None:
            process_calls.append(proxy)

        async def get_hostnames(self) -> list[str]:
            return ['WWW.EXAMPLE.COM.', 'www.example.com', 'example.com.evil.test']

    stored: list[tuple[str, tuple[str, ...], str, str]] = []

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_run(self, _run: run_module.RunResult, *, legacy_results=()) -> None:
            stored.extend((domain, tuple(items), result_type, source) for domain, items, result_type, source in legacy_results)

    captured: list[run_module.RunResult] = []

    async def execute_with_temporary_store(target, sources, **kwargs):
        result = await run_module.execute_run(target, sources, **kwargs)
        captured.append(result)
        return result

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'execute_run', execute_with_temporary_store, raising=True)

    await main_module.start(
        argparse.Namespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=500,
            proxies=False,
            quiet=True,
            shodan=False,
            source='crtsh',
            start=0,
            take_over=False,
            wordlist='',
        )
    )

    assert process_calls == [False]
    assert len(captured) == 1
    assert captured[0].source_executions[0].status is SourceStatus.SUCCEEDED
    assert captured[0].source_executions[0].source == 'crtsh'
    assert legacy_hostnames(captured[0]) == ['www.example.com']
    assert stored == [('example.com', ('www.example.com',), 'host', 'CRTsh')]


@pytest.mark.asyncio
async def test_crtsh_bridge_uses_three_resolvers_without_legacy_requery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import theHarvester.__main__ as main_module
    import theHarvester.lib.run as run_module

    candidate = 'www.example.com'
    secondary = 'old.example.com'

    class FakeCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, _proxy: bool = False) -> None:
            return None

        async def get_hostnames(self) -> list[str]:
            return [candidate, secondary]

    created: list[str] = []
    closed: list[str] = []

    class FakeVantage:
        def __init__(self, nameserver: str) -> None:
            self.name = nameserver
            created.append(nameserver)

        async def query(self, hostname: str) -> DnsResponse:
            return DnsResponse(ipv4=('192.0.2.10',)) if hostname == candidate else DnsResponse(rcode='NXDOMAIN')

        async def close(self) -> None:
            closed.append(self.name)

    class FailOnLegacyChecker:
        def __init__(self, *_args, **_kwargs) -> None:
            raise AssertionError('validated evidence must not be queried again')

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args: object) -> None:
            return None

        async def store(self, *_args: object) -> None:
            return None

        async def store_run(self, run: run_module.RunResult, **_kwargs) -> None:
            completed.append(run)

    captured: list[run_module.RunResult] = []
    completed: list[run_module.RunResult] = []
    output: list[object] = []

    async def capture_run(target, sources, **kwargs):
        result = await run_module.execute_run(target, sources, **kwargs)
        captured.append(result)
        return result

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module, 'AioDnsResolverVantage', FakeVantage, raising=False)
    monkeypatch.setattr(main_module.hostchecker, 'Checker', FailOnLegacyChecker)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'execute_run', capture_run, raising=True)
    monkeypatch.setattr(main_module.output_logger, 'info', output.append)

    monkeypatch.setattr(
        main_module.sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'example.com',
            '-b',
            'crtsh',
            '-r',
            '192.0.2.53,192.0.2.54,192.0.2.55',
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await main_module.start()

    assert exit_info.value.code == 0
    assert set(created) == {'192.0.2.53', '192.0.2.54', '192.0.2.55'}
    assert set(closed) == set(created)
    assert captured[0].entities[0].addressability is None
    assert {entity.value: entity.addressability for entity in completed[0].entities} == {
        candidate: Addressability.CURRENT,
        secondary: Addressability.NOT_CURRENT,
    }
    assert {record.value for record in completed[0].results if record.type == 'subdomain'} == {
        candidate,
        secondary,
    }
    dns_execution = next(execution for execution in completed[0].executions if execution.name == 'dns-resolution')
    assert dns_execution.observation_count == len(completed[0].dns_validations)
    assert dns_execution.entity_count == 2
    terminal = '\n'.join(map(str, output))
    assert terminal.count(candidate) == 1
    assert terminal.count(secondary) == 1
    assert 'DNS resolution: consensus via 192.0.2.53, 192.0.2.54, 192.0.2.55' in terminal


@pytest.mark.asyncio
async def test_dnsdb_bridge_preserves_partial_results_and_status(monkeypatch: pytest.MonkeyPatch) -> None:
    import argparse

    import theHarvester.__main__ as main_module
    import theHarvester.lib.run as run_module

    class FakeDNSDBSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, _proxy: bool = False) -> None:
            raise SourceRateLimitedError(
                'DNSDB result limit reached',
                findings=('partial.example.com',),
            )

        async def get_hostnames(self) -> list[str]:
            raise AssertionError('partial findings must come from the incomplete source result')

    stored: list[tuple[str, tuple[str, ...], str, str]] = []

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_run(self, _run: run_module.RunResult, *, legacy_results=()) -> None:
            stored.extend((domain, tuple(items), result_type, source) for domain, items, result_type, source in legacy_results)

    captured: list[run_module.RunResult] = []

    async def capture_run(target, sources, **kwargs):
        result = await run_module.execute_run(target, sources, **kwargs)
        captured.append(result)
        return result

    monkeypatch.setattr(main_module.dnsdb, 'SearchDNSDB', FakeDNSDBSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module, 'execute_run', capture_run, raising=True)

    await main_module.start(
        argparse.Namespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=500,
            proxies=False,
            quiet=True,
            shodan=False,
            source='dnsdb',
            start=0,
            take_over=False,
            wordlist='',
        )
    )

    assert len(captured) == 1
    assert captured[0].source_executions[0].status is SourceStatus.RATE_LIMITED
    assert {observation.value for observation in captured[0].observations} == {'partial.example.com'}
    assert stored == [('example.com', ('partial.example.com',), 'host', 'dnsdb')]

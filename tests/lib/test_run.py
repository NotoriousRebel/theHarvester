from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

import pytest

from theHarvester.lib.run import (
    Addressability,
    Derivation,
    ScopeClass,
    SourceFinding,
    SourceRateLimitedError,
    SourceSkippedError,
    SourceStatus,
    SQLiteRunStore,
    execute_run,
    legacy_hostnames,
)

if TYPE_CHECKING:
    from pathlib import Path


class FakePassiveSource:
    name = 'fixture'
    family = 'certificate-transparency'
    raw_payload = 'provider-secret-that-must-not-be-persisted'

    async def collect(self, target: str) -> list[SourceFinding]:
        assert target == 'example.com'
        return [
            SourceFinding('WWW.Example.COM.', Derivation.PROVIDER),
            SourceFinding('www.example.com', Derivation.PROVIDER),
            SourceFinding('example.com.evil.test', Derivation.RELATED),
            SourceFinding('cdn.vendor.test', Derivation.EXTERNAL_RELATIONSHIP),
        ]


@pytest.mark.asyncio
async def test_execute_run_records_scoped_normalized_evidence_end_to_end(tmp_path: Path) -> None:
    database = tmp_path / 'evidence.sqlite'
    store = SQLiteRunStore(database)

    result = await execute_run('Example.COM.', FakePassiveSource(), store=store)
    next_result = await execute_run('example.com', FakePassiveSource(), store=store)

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
        ('cdn.vendor.test', ScopeClass.EXTERNAL_RELATIONSHIP),
    ]
    assert all(item.target == 'example.com' for item in result.observations)
    assert all(item.source == 'fixture' for item in result.observations)
    assert all(item.source_family == 'certificate-transparency' for item in result.observations)
    assert all(item.collected_at.tzinfo is not None for item in result.observations)
    assert [item.derivation for item in result.observations] == [
        Derivation.PROVIDER,
        Derivation.PROVIDER,
        Derivation.RELATED,
        Derivation.EXTERNAL_RELATIONSHIP,
    ]

    merged = {item.value: item for item in result.entities}
    assert len(merged['www.example.com'].observations) == 2
    assert merged['www.example.com'].independent_corroboration_count == 1
    assert merged['www.example.com'].addressability is Addressability.UNVERIFIED
    assert merged['www.example.com'].scope_classes == (ScopeClass.IN_SCOPE,)
    assert legacy_hostnames(result) == ['www.example.com']

    assert await store.load(result.run_id) == result.to_dict()
    assert FakePassiveSource.raw_payload.encode() not in database.read_bytes()


class OutcomeSource:
    name = 'outcome'
    family = 'fixture-family'

    def __init__(self, outcome: list[SourceFinding] | Exception) -> None:
        self.outcome = outcome

    async def collect(self, _target: str) -> list[SourceFinding]:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.mark.parametrize(
    ('outcome', 'expected'),
    [
        ([], SourceStatus.EMPTY),
        (RuntimeError('provider failed'), SourceStatus.FAILED),
        (SourceRateLimitedError(), SourceStatus.RATE_LIMITED),
        (SourceSkippedError(), SourceStatus.SKIPPED),
    ],
)
@pytest.mark.asyncio
async def test_execute_run_records_non_success_source_outcomes(
    tmp_path: Path, outcome: list[SourceFinding] | Exception, expected: SourceStatus
) -> None:
    result = await execute_run(
        'example.com',
        OutcomeSource(outcome),
        store=SQLiteRunStore(tmp_path / f'{expected}.sqlite'),
    )

    assert len(result.source_executions) == 1
    execution = result.source_executions[0]
    assert execution.status is expected
    assert execution.duration_ms >= 0
    assert execution.result_count == 0
    assert execution.observation_count == 0
    assert execution.entity_count == 0
    assert result.observations == ()
    assert result.entities == ()


@pytest.mark.asyncio
async def test_crtsh_bridge_executes_once_and_feeds_legacy_consumers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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

        async def store_all(self, domain: str, items: list[str], result_type: str, source: str) -> None:
            stored.append((domain, tuple(items), result_type, source))

    evidence_store = SQLiteRunStore(tmp_path / 'evidence.sqlite')
    captured: list[run_module.RunResult] = []

    async def execute_with_temporary_store(target, source):
        result = await run_module.execute_run(target, source, store=evidence_store)
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
    assert legacy_hostnames(captured[0]) == ['www.example.com']
    assert await evidence_store.load(captured[0].run_id) == captured[0].to_dict()
    assert stored == [('example.com', ('www.example.com',), 'host', 'CRTsh')]

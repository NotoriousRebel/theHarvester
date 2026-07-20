from __future__ import annotations

import asyncio
import json
import time
from argparse import Namespace
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import ClassVar
from xml.etree import ElementTree

import pytest

from theHarvester.lib.output import evidence_xml_fragment, format_run_terminal, legacy_json_result, run_result_jsonl
from theHarvester.lib.run import (
    Addressability,
    Derivation,
    DNSResponse,
    RecursiveDNSLimits,
    ScopeClass,
    SourceFinding,
    execute_run,
    run_recursive_dns,
)


class SeedSource:
    name = 'fixture'
    family = 'fixture-family'

    async def collect(self, _target: str) -> list[SourceFinding]:
        return [
            SourceFinding('api.example.com'),
            SourceFinding('empty.example.com'),
            SourceFinding('outside.example.net', Derivation.RELATED),
            SourceFinding('cdn.vendor.test', Derivation.EXTERNAL_RELATIONSHIP),
        ]


class SingleSeedSource:
    name = 'fixture'
    family = 'fixture-family'

    async def collect(self, _target: str) -> list[SourceFinding]:
        return [SourceFinding('api.example.com')]


class FakeRecursiveResolver:
    current: ClassVar[set[str]] = {
        'api.example.com',
        'empty.example.com',
        'dev.api.example.com',
        'v2.dev.api.example.com',
    }

    def __init__(self, name: str) -> None:
        self.name = name
        self.queries: list[str] = []

    async def query(self, hostname: str) -> DNSResponse:
        self.queries.append(hostname)
        if hostname in self.current:
            return DNSResponse(ipv4=('192.0.2.10',), ttl=60)
        return DNSResponse(rcode='NXDOMAIN')


class BlockingResolver:
    def __init__(self, name: str) -> None:
        self.name = name
        self.started = asyncio.Event()
        self.cancelled = 0

    async def query(self, _hostname: str) -> DNSResponse:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            raise


class NestedWildcardResolver(FakeRecursiveResolver):
    current: ClassVar[set[str]] = {
        'api.example.com',
        'dev.api.example.com',
        'v2.dev.api.example.com',
    }

    async def query(self, hostname: str) -> DNSResponse:
        self.queries.append(hostname)
        if hostname.startswith('th-') and hostname.endswith('.dev.api.example.com'):
            return DNSResponse(ipv4=('192.0.2.99',), ttl=60)
        if hostname in self.current:
            return DNSResponse(ipv4=('192.0.2.10',), ttl=60)
        return DNSResponse(rcode='NXDOMAIN')


class DisputedResolver(FakeRecursiveResolver):
    async def query(self, hostname: str) -> DNSResponse:
        self.queries.append(hostname)
        if hostname == 'api.example.com':
            return DNSResponse(ipv4=('192.0.2.10',), ttl=60)
        if hostname == 'dev.api.example.com':
            if self.name == 'resolver-0':
                return DNSResponse(ipv4=('192.0.2.11',), ttl=60)
            if self.name == 'resolver-1':
                return DNSResponse(rcode='NXDOMAIN')
            return DNSResponse(rcode='ERROR', error='timeout')
        return DNSResponse(rcode='NXDOMAIN')


class ExpiringLabels(Sequence[str]):
    def __len__(self) -> int:
        return 1

    def __getitem__(self, index: int) -> str:
        if index:
            raise IndexError
        time.sleep(0.01)
        return 'dev'


@pytest.mark.asyncio
async def test_recursive_dns_expands_current_parents_breadth_first_with_parent_provenance() -> None:
    resolvers = tuple(FakeRecursiveResolver(f'resolver-{index}') for index in range(3))
    result = await execute_run('example.com', SeedSource(), resolver_vantages=resolvers, persist=False)
    for resolver in resolvers:
        resolver.queries.clear()

    result = await run_recursive_dns(
        result,
        resolvers,
        ('dev', 'v2'),
        RecursiveDNSLimits(depth=2, query_limit=1_000, runtime_seconds=5),
    )

    recursive = [observation for observation in result.observations if observation.derivation is Derivation.RECURSIVE_DNS]
    assert {(observation.value, observation.parent) for observation in recursive} == {
        ('dev.api.example.com', 'api.example.com'),
        ('v2.api.example.com', 'api.example.com'),
        ('dev.empty.example.com', 'empty.example.com'),
        ('v2.empty.example.com', 'empty.example.com'),
        ('dev.dev.api.example.com', 'dev.api.example.com'),
        ('v2.dev.api.example.com', 'dev.api.example.com'),
    }
    entities = {entity.value: entity for entity in result.entities}
    assert entities['dev.api.example.com'].addressability is Addressability.CURRENT
    assert entities['v2.dev.api.example.com'].addressability is Addressability.CURRENT
    assert entities['v2.api.example.com'].addressability is Addressability.NOT_CURRENT
    assert all(ScopeClass.IN_SCOPE in entities[observation.value].scope_classes for observation in recursive)
    assert all(
        entity.value != 'outside.example.net' or entity.addressability is Addressability.UNVERIFIED for entity in result.entities
    )
    assert not any('outside.example.net' in query for resolver in resolvers for query in resolver.queries)
    assert not any('cdn.vendor.test' in query for resolver in resolvers for query in resolver.queries)
    execution = result.source_executions[-1]
    assert execution.source == 'action:dns-recursive'
    assert execution.result_count == 2
    assert execution.query_count == 45
    assert execution.depth_reached == 2
    assert execution.stop_reason == 'depth-limit'
    assert result.completed_at >= datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.asyncio
async def test_recursive_dns_stops_before_exceeding_the_query_budget() -> None:
    resolvers = tuple(FakeRecursiveResolver(f'resolver-{index}') for index in range(3))
    result = await execute_run('example.com', SeedSource(), resolver_vantages=resolvers, persist=False)
    for resolver in resolvers:
        resolver.queries.clear()

    result = await run_recursive_dns(
        result,
        resolvers,
        ('dev',),
        RecursiveDNSLimits(depth=2, query_limit=11, runtime_seconds=5),
    )

    execution = result.source_executions[-1]
    assert execution.query_count == 0
    assert execution.depth_reached == 0
    assert execution.stop_reason == 'query-limit'
    assert not [observation for observation in result.observations if observation.derivation is Derivation.RECURSIVE_DNS]
    assert not any(resolver.queries for resolver in resolvers)


@pytest.mark.asyncio
async def test_recursive_dns_runtime_limit_cancels_queries_and_preserves_the_cost() -> None:
    seed_resolvers = tuple(FakeRecursiveResolver(f'seed-{index}') for index in range(3))
    result = await execute_run('example.com', SeedSource(), resolver_vantages=seed_resolvers, persist=False)
    resolvers = tuple(BlockingResolver(f'resolver-{index}') for index in range(3))

    result = await run_recursive_dns(
        result,
        resolvers,
        ('dev',),
        RecursiveDNSLimits(depth=2, query_limit=100, runtime_seconds=0.01),
    )

    execution = result.source_executions[-1]
    assert execution.query_count == 9
    assert execution.depth_reached == 0
    assert execution.stop_reason == 'runtime-limit'
    assert sum(resolver.cancelled for resolver in resolvers) == 9


@pytest.mark.asyncio
async def test_recursive_dns_runtime_limit_includes_label_preprocessing() -> None:
    resolvers = tuple(FakeRecursiveResolver(f'resolver-{index}') for index in range(3))
    result = await execute_run('example.com', SingleSeedSource(), resolver_vantages=resolvers, persist=False)
    for resolver in resolvers:
        resolver.queries.clear()

    result = await run_recursive_dns(
        result,
        resolvers,
        ExpiringLabels(),
        RecursiveDNSLimits(depth=2, query_limit=100, runtime_seconds=0.001),
    )

    execution = result.source_executions[-1]
    assert execution.query_count == 0
    assert execution.stop_reason == 'runtime-limit'
    assert not any(resolver.queries for resolver in resolvers)


@pytest.mark.asyncio
async def test_recursive_dns_external_cancellation_propagates_after_cancelling_queries() -> None:
    seed_resolvers = tuple(FakeRecursiveResolver(f'seed-{index}') for index in range(3))
    result = await execute_run('example.com', SeedSource(), resolver_vantages=seed_resolvers, persist=False)
    resolvers = tuple(BlockingResolver(f'resolver-{index}') for index in range(3))
    task = asyncio.create_task(
        run_recursive_dns(
            result,
            resolvers,
            ('dev',),
            RecursiveDNSLimits(depth=2, query_limit=100, runtime_seconds=60),
        )
    )
    await asyncio.gather(*(resolver.started.wait() for resolver in resolvers))

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert sum(resolver.cancelled for resolver in resolvers) == 9


@pytest.mark.asyncio
async def test_recursive_dns_stops_after_three_consecutive_zero_yield_batches() -> None:
    resolvers = tuple(FakeRecursiveResolver(f'resolver-{index}') for index in range(3))
    result = await execute_run('example.com', SingleSeedSource(), resolver_vantages=resolvers, persist=False)
    for resolver in resolvers:
        resolver.queries.clear()

    result = await run_recursive_dns(
        result,
        resolvers,
        tuple(f'unused{index}' for index in range(151)),
        RecursiveDNSLimits(depth=2, query_limit=1_000, runtime_seconds=5),
    )

    execution = result.source_executions[-1]
    recursive = [observation for observation in result.observations if observation.derivation is Derivation.RECURSIVE_DNS]
    assert len(recursive) == 150
    assert execution.query_count == 459
    assert execution.depth_reached == 0
    assert execution.zero_yield_batches == 3
    assert execution.stop_reason == 'zero-yield'
    assert 'unused150.api.example.com' not in {observation.value for observation in recursive}


@pytest.mark.asyncio
async def test_recursive_dns_nested_wildcard_never_advances_or_queries_out_of_scope_labels() -> None:
    resolvers = tuple(NestedWildcardResolver(f'resolver-{index}') for index in range(3))
    result = await execute_run('example.com', SingleSeedSource(), resolver_vantages=resolvers, persist=False)
    for resolver in resolvers:
        resolver.queries.clear()

    result = await run_recursive_dns(
        result,
        resolvers,
        ('dev', 'v2', 'escape.example.net'),
        RecursiveDNSLimits(depth=3, query_limit=1_000, runtime_seconds=5),
    )

    entities = {entity.value: entity for entity in result.entities}
    assert entities['v2.dev.api.example.com'].addressability is Addressability.WILDCARD_UNCERTAIN
    assert 'dev.v2.dev.api.example.com' not in entities
    assert not any('escape.example.net' in query for resolver in resolvers for query in resolver.queries)
    execution = result.source_executions[-1]
    assert execution.depth_reached == 2
    assert execution.stop_reason == 'frontier-exhausted'


@pytest.mark.asyncio
async def test_recursive_dns_disputed_names_never_advance_the_frontier() -> None:
    seed_resolvers = tuple(FakeRecursiveResolver(f'seed-{index}') for index in range(3))
    result = await execute_run('example.com', SingleSeedSource(), resolver_vantages=seed_resolvers, persist=False)
    resolvers = tuple(DisputedResolver(f'resolver-{index}') for index in range(3))

    result = await run_recursive_dns(
        result,
        resolvers,
        ('dev',),
        RecursiveDNSLimits(depth=2, query_limit=100, runtime_seconds=5),
    )

    entities = {entity.value: entity for entity in result.entities}
    assert entities['dev.api.example.com'].addressability is Addressability.RESOLVER_DISPUTED
    assert 'dev.dev.api.example.com' not in entities
    assert not any('dev.dev.api.example.com' in query for resolver in resolvers for query in resolver.queries)


@pytest.mark.asyncio
async def test_recursive_dns_provenance_and_cost_are_visible_on_every_output_surface() -> None:
    resolvers = tuple(FakeRecursiveResolver(f'resolver-{index}') for index in range(3))
    result = await execute_run('example.com', SingleSeedSource(), resolver_vantages=resolvers, persist=False)
    result = await run_recursive_dns(
        result,
        resolvers,
        ('dev',),
        RecursiveDNSLimits(depth=1, query_limit=100, runtime_seconds=5),
    )

    terminal = format_run_terminal(result)
    records = [json.loads(line) for line in run_result_jsonl(result).splitlines()]
    legacy = legacy_json_result(result)
    xml = ElementTree.fromstring(evidence_xml_fragment(result))

    assert 'dev.api.example.com [status=currently-addressable; sources=action:dns-recursive; ' in terminal
    assert 'derivation=recursive-dns; parent=api.example.com]' in terminal
    assert 'queries=12; depth=1; zero-yield=0; stop=depth-limit' in terminal
    discovery = next(
        record['data']
        for record in records
        if record['record_type'] == 'discovery_observation' and record['data']['value'] == 'dev.api.example.com'
    )
    assert discovery['derivation'] == 'recursive-dns'
    assert discovery['parent'] == 'api.example.com'
    assert legacy['evidence_run']['recursive_observations'] == [discovery]
    xml_observation = xml.find("discovery_observation[@value='dev.api.example.com']")
    assert xml_observation is not None
    assert xml_observation.attrib['derivation'] == 'recursive-dns'
    assert xml_observation.attrib['parent'] == 'api.example.com'
    xml_source = xml.find("source[@name='action:dns-recursive']")
    assert xml_source is not None
    assert xml_source.attrib['query_count'] == '12'
    assert result.to_dict()['source_executions'][-1]['stop_reason'] == 'depth-limit'


@pytest.mark.asyncio
async def test_cli_and_rest_select_recursive_dns_as_bounded_p1_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from theHarvester import __main__
    from theHarvester.lib.api import api
    from theHarvester.lib.source_catalog import describe_activity, resolve_sources

    cli_args = __main__.build_parser().parse_args(
        [
            '-d',
            'example.com',
            '--dns-recursive-depth',
            '2',
            '--dns-recursive-query-limit',
            '321',
            '--dns-recursive-runtime-seconds',
            '4.5',
        ]
    )
    assert __main__.selected_actions(cli_args) == ('dns-recursive',)
    assert describe_activity(resolve_sources(()), actions=__main__.selected_actions(cli_args)) == (
        'Activity: P0 passive=disabled; P1 DNS=enabled; P2 direct=disabled.'
    )

    captured: Namespace | None = None

    async def fake_start(args: Namespace, *, return_evidence_run: bool = False) -> tuple[object, ...]:
        nonlocal captured
        assert return_evidence_run is True
        captured = args
        return ([], [], [], [], [], [], [], [], [], None)

    monkeypatch.setattr(api.__main__, 'start', fake_start)
    response = await api.query.__wrapped__(
        None,
        [],
        'example.com',
        dns_recursive_depth=2,
        dns_recursive_query_limit=321,
        dns_recursive_runtime_seconds=4.5,
    )

    assert response.status_code == 200
    assert captured is not None
    assert __main__.selected_actions(captured) == ('dns-recursive',)
    assert captured.dns_recursive_depth == cli_args.dns_recursive_depth == 2
    assert captured.dns_recursive_query_limit == cli_args.dns_recursive_query_limit == 321
    assert captured.dns_recursive_runtime_seconds == cli_args.dns_recursive_runtime_seconds == 4.5

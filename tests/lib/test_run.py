from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING
from uuid import UUID

import pytest

from theHarvester.lib.run import (
    Addressability,
    AioDNSResolverVantage,
    Derivation,
    DNSResponse,
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
    from collections.abc import Callable
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


class OneCandidateSource:
    name = 'fixture'
    family = 'fixture-family'

    def __init__(self, candidate: str) -> None:
        self.candidate = candidate

    async def collect(self, _target: str) -> list[SourceFinding]:
        return [SourceFinding(self.candidate)]


class FakeResolverVantage:
    def __init__(self, name: str, candidate: str, response: DNSResponse) -> None:
        self.name = name
        self.candidate = candidate
        self.response = response

    async def query(self, hostname: str) -> DNSResponse:
        if hostname == self.candidate:
            return self.response
        return DNSResponse(rcode='NXDOMAIN')


class RuleResolverVantage:
    def __init__(self, name: str, handler: Callable[[str], DNSResponse]) -> None:
        self.name = name
        self.handler = handler

    async def query(self, hostname: str) -> DNSResponse:
        return self.handler(hostname)


class RotatingResolverVantage:
    def __init__(
        self,
        name: str,
        candidate: str,
        candidate_response: DNSResponse,
        control_responses: tuple[DNSResponse, ...],
    ) -> None:
        self.name = name
        self.candidate = candidate
        self.candidate_response = candidate_response
        self.control_responses = control_responses
        self.control_index = 0

    async def query(self, hostname: str) -> DNSResponse:
        if hostname == self.candidate:
            return self.candidate_response
        response = self.control_responses[self.control_index % len(self.control_responses)]
        self.control_index += 1
        return response


@pytest.mark.asyncio
async def test_execute_run_records_dns_consensus_without_requiring_identical_addresses(tmp_path: Path) -> None:
    candidate = 'api.example.com'
    resolvers = (
        FakeResolverVantage(
            'resolver-a',
            candidate,
            DNSResponse(
                ipv4=('192.0.2.10',),
                cnames=('Edge.Example.NET.',),
                rcode='NOERROR',
                ttl=300,
                cname_chain=('Edge.Example.NET.',),
            ),
        ),
        FakeResolverVantage(
            'resolver-b',
            candidate,
            DNSResponse(ipv6=('2001:0db8::10',), rcode='NOERROR', ttl=120),
        ),
        FakeResolverVantage('resolver-c', candidate, DNSResponse(rcode='NXDOMAIN', ttl=60)),
    )

    result = await execute_run(
        'example.com',
        OneCandidateSource(candidate),
        resolver_vantages=resolvers,
        store=SQLiteRunStore(tmp_path / 'evidence.sqlite'),
    )

    entity = result.entities[0]
    candidate_observations = [item for item in result.dns_validations if not item.is_wildcard_control]
    assert entity.addressability is Addressability.CURRENT
    assert entity.dns_validations[:3] == tuple(candidate_observations)
    assert len(candidate_observations) == 3
    assert candidate_observations[0].candidate == candidate
    assert candidate_observations[0].query_name == candidate
    assert candidate_observations[0].resolver == 'resolver-a'
    assert candidate_observations[0].ipv4 == ('192.0.2.10',)
    assert candidate_observations[0].cnames == ('edge.example.net',)
    assert candidate_observations[0].rcode == 'NOERROR'
    assert candidate_observations[0].ttl == 300
    assert candidate_observations[0].cname_chain == ('edge.example.net',)
    assert candidate_observations[0].queried_at.tzinfo is not None
    assert candidate_observations[0].latency_ms >= 0
    assert candidate_observations[0].error is None
    assert candidate_observations[1].ipv6 == ('2001:db8::10',)


@pytest.mark.asyncio
async def test_execute_run_keeps_resolver_disagreement_as_secondary_evidence(tmp_path: Path) -> None:
    candidate = 'api.example.com'
    resolvers = (
        FakeResolverVantage('resolver-a', candidate, DNSResponse(ipv4=('192.0.2.10',))),
        FakeResolverVantage('resolver-b', candidate, DNSResponse(rcode='NXDOMAIN')),
        FakeResolverVantage('resolver-c', candidate, DNSResponse(rcode='ERROR', error='timeout')),
    )

    result = await execute_run(
        'example.com',
        OneCandidateSource(candidate),
        resolver_vantages=resolvers,
        store=SQLiteRunStore(tmp_path / 'evidence.sqlite'),
    )

    assert result.entities[0].addressability is Addressability.RESOLVER_DISPUTED
    assert legacy_hostnames(result) == []
    assert len(result.observations) == 1
    assert result.observations[0].value == candidate
    assert len([item for item in result.dns_validations if not item.is_wildcard_control]) == 3


@pytest.mark.asyncio
async def test_execute_run_detects_nested_wildcards_without_promoting_control_names(tmp_path: Path) -> None:
    candidate = 'api.dev.example.com'

    def nested_wildcard(hostname: str) -> DNSResponse:
        if hostname == candidate or hostname.endswith('.dev.example.com'):
            return DNSResponse(ipv4=('192.0.2.20',), ttl=30)
        return DNSResponse(rcode='NXDOMAIN')

    result = await execute_run(
        'example.com',
        OneCandidateSource(candidate),
        resolver_vantages=tuple(RuleResolverVantage(f'resolver-{suffix}', nested_wildcard) for suffix in ('a', 'b', 'c')),
        store=SQLiteRunStore(tmp_path / 'evidence.sqlite'),
    )

    controls = [item for item in result.dns_validations if item.is_wildcard_control]
    controls_by_name: dict[str, list[str]] = {}
    for control in controls:
        controls_by_name.setdefault(control.query_name, []).append(control.resolver)
    assert result.entities[0].addressability is Addressability.WILDCARD_UNCERTAIN
    assert {item.wildcard_depth for item in controls} == {'example.com', 'dev.example.com'}
    assert len(controls_by_name) == 6
    assert all(len(resolvers) == 3 for resolvers in controls_by_name.values())
    assert [item.value for item in result.observations] == [candidate]
    assert [item.value for item in result.entities] == [candidate]


@pytest.mark.asyncio
async def test_execute_run_respects_empty_non_terminal_exact_overrides(tmp_path: Path) -> None:
    candidate = 'api.empty.example.com'

    def exact_below_empty_non_terminal(hostname: str) -> DNSResponse:
        if hostname == candidate:
            return DNSResponse(ipv4=('192.0.2.10',))
        if hostname.endswith('.empty.example.com'):
            return DNSResponse(rcode='NXDOMAIN')
        return DNSResponse(ipv4=('192.0.2.10',))

    result = await execute_run(
        'example.com',
        OneCandidateSource(candidate),
        resolver_vantages=tuple(
            RuleResolverVantage(f'resolver-{suffix}', exact_below_empty_non_terminal) for suffix in ('a', 'b', 'c')
        ),
        store=SQLiteRunStore(tmp_path / 'evidence.sqlite'),
    )

    assert result.entities[0].addressability is Addressability.CURRENT


@pytest.mark.asyncio
async def test_execute_run_detects_rotating_root_wildcard_cname_on_any_vantage(tmp_path: Path) -> None:
    candidate = 'www.example.com'
    resolvers = (
        RotatingResolverVantage(
            'resolver-a',
            candidate,
            DNSResponse(ipv4=('192.0.2.90',)),
            (
                DNSResponse(ipv4=('192.0.2.1',)),
                DNSResponse(ipv6=('2001:db8::1',)),
                DNSResponse(cnames=('other.example.net',)),
            ),
        ),
        RotatingResolverVantage(
            'resolver-b',
            candidate,
            DNSResponse(ipv4=('192.0.2.91',), cnames=('exact.example.net',)),
            (
                DNSResponse(ipv4=('192.0.2.2',)),
                DNSResponse(ipv6=('2001:0db8::2',)),
                DNSResponse(cnames=('wildcard.example.net',)),
            ),
        ),
        RotatingResolverVantage(
            'resolver-c',
            candidate,
            DNSResponse(ipv4=('192.0.2.92',)),
            (
                DNSResponse(ipv4=('192.0.2.3',)),
                DNSResponse(ipv6=('2001:db8::3',)),
                DNSResponse(cnames=('third.example.net',)),
            ),
        ),
    )

    result = await execute_run(
        'example.com',
        OneCandidateSource(candidate),
        resolver_vantages=resolvers,
        store=SQLiteRunStore(tmp_path / 'evidence.sqlite'),
    )

    controls = [item for item in result.dns_validations if item.is_wildcard_control]
    assert result.entities[0].addressability is Addressability.WILDCARD_UNCERTAIN
    assert {address for item in controls for address in item.ipv4} >= {'192.0.2.1', '192.0.2.2', '192.0.2.3'}
    assert {address for item in controls for address in item.ipv6} >= {
        '2001:db8::1',
        '2001:db8::2',
        '2001:db8::3',
    }
    assert 'wildcard.example.net' in {cname for item in controls for cname in item.cnames}


@pytest.mark.asyncio
async def test_aiodns_vantage_follows_and_normalizes_multi_hop_cname_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    import theHarvester.lib.run as run_module

    closed: list[bool] = []
    aliases = {
        'alias.example.com': ('Edge.Example.NET.', 90),
        'edge.example.net': ('Origin.Example.NET.', 60),
    }

    class FakeDNSResolver:
        def __init__(self, *, nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']

        async def query_dns(self, hostname: str, record_type: str):
            if record_type == 'CNAME' and hostname in aliases:
                cname, ttl = aliases[hostname]
                return SimpleNamespace(answer=[SimpleNamespace(ttl=ttl, data=SimpleNamespace(cname=cname))])
            if record_type == 'A' and hostname == 'origin.example.net':
                return SimpleNamespace(answer=[SimpleNamespace(ttl=30, data=SimpleNamespace(addr='192.0.2.10'))])
            raise run_module.aiodns.error.DNSError(run_module.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(run_module.aiodns, 'DNSResolver', FakeDNSResolver)
    vantage = AioDNSResolverVantage('192.0.2.53')

    response = await vantage.query('alias.example.com')
    await vantage.close()

    assert response.ipv4 == ('192.0.2.10',)
    assert response.cnames == ('edge.example.net', 'origin.example.net')
    assert response.cname_chain == ('edge.example.net', 'origin.example.net')
    assert response.ttl == 30
    assert response.error is None
    assert closed == [True]


@pytest.mark.asyncio
async def test_aiodns_vantage_stops_cname_loops(monkeypatch: pytest.MonkeyPatch) -> None:
    import theHarvester.lib.run as run_module

    aliases = {'loop-a.example.com': 'loop-b.example.com', 'loop-b.example.com': 'loop-a.example.com'}
    queries: list[tuple[str, str]] = []

    class FakeDNSResolver:
        def __init__(self, *, nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']

        async def query_dns(self, hostname: str, record_type: str):
            queries.append((hostname, record_type))
            if record_type == 'CNAME':
                return SimpleNamespace(answer=[SimpleNamespace(ttl=60, data=SimpleNamespace(cname=aliases[hostname]))])
            raise run_module.aiodns.error.DNSError(run_module.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            return None

    monkeypatch.setattr(run_module.aiodns, 'DNSResolver', FakeDNSResolver)

    response = await AioDNSResolverVantage('192.0.2.53').query('loop-a.example.com')

    assert response.cname_chain == ('loop-b.example.com', 'loop-a.example.com')
    assert response.error == 'CNAME loop detected at loop-a.example.com'
    assert len(queries) == 6


@pytest.mark.asyncio
async def test_aiodns_vantage_bounds_cname_chain_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    import theHarvester.lib.run as run_module

    queries: list[tuple[str, str]] = []

    class FakeDNSResolver:
        def __init__(self, *, nameservers: list[str]) -> None:
            assert nameservers == ['192.0.2.53']

        async def query_dns(self, hostname: str, record_type: str):
            queries.append((hostname, record_type))
            if record_type == 'CNAME':
                label = int(hostname.removeprefix('node-').removesuffix('.example.com'))
                cname = f'node-{label + 1}.example.com'
                return SimpleNamespace(answer=[SimpleNamespace(ttl=60, data=SimpleNamespace(cname=cname))])
            raise run_module.aiodns.error.DNSError(run_module.aiodns.error.ARES_ENODATA, 'no data')

        async def close(self) -> None:
            return None

    monkeypatch.setattr(run_module.aiodns, 'DNSResolver', FakeDNSResolver)

    response = await AioDNSResolverVantage('192.0.2.53').query('node-0.example.com')

    assert response.error == 'CNAME chain exceeded 16 links'
    assert len(response.cname_chain) == 16
    assert len(queries) == 48


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


@pytest.mark.parametrize(
    'dns_resolve',
    [None, '192.0.2.53', '192.0.2.53,192.0.2.54', '192.0.2.53,192.0.2.54,192.0.2.55,192.0.2.56'],
)
@pytest.mark.asyncio
async def test_start_rejects_explicit_resolver_counts_other_than_three(
    dns_resolve: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import argparse

    import theHarvester.__main__ as main_module

    class NoNetworkCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, _proxy: bool = False) -> None:
            raise AssertionError('invalid resolver policy must fail before source execution')

        async def get_hostnames(self) -> list[str]:
            return []

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', NoNetworkCrtshSearch)

    with pytest.raises(ValueError, match='exactly three distinct resolver vantages'):
        await main_module.start(
            argparse.Namespace(
                api_scan=False,
                dns_brute=False,
                dns_lookup=False,
                dns_resolve=dns_resolve,
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


@pytest.mark.asyncio
async def test_crtsh_bridge_closes_constructed_vantages_after_partial_constructor_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import argparse

    import theHarvester.__main__ as main_module

    class FakeCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

    attempted: list[str] = []
    closed: list[str] = []

    class PartiallyFailingVantage:
        def __init__(self, nameserver: str) -> None:
            attempted.append(nameserver)
            if len(attempted) == 2:
                raise RuntimeError('resolver construction failed')
            self.name = nameserver

        async def close(self) -> None:
            closed.append(self.name)

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module, 'AioDNSResolverVantage', PartiallyFailingVantage, raising=True)

    await main_module.start(
        argparse.Namespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='192.0.2.53,192.0.2.54,192.0.2.55',
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

    assert len(attempted) == 2
    assert closed == [attempted[0]]


@pytest.mark.asyncio
async def test_crtsh_bridge_uses_three_explicit_resolver_vantages(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import argparse

    import theHarvester.__main__ as main_module
    import theHarvester.lib.run as run_module

    class FakeCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False

        async def get_hostnames(self) -> list[str]:
            return ['www.example.com']

    created: list[str] = []
    closed: list[str] = []

    class FakeProductionVantage:
        def __init__(self, nameserver: str) -> None:
            self.name = nameserver
            created.append(nameserver)

        async def query(self, hostname: str) -> DNSResponse:
            return DNSResponse(ipv4=('192.0.2.10',)) if hostname == 'www.example.com' else DNSResponse(rcode='NXDOMAIN')

        async def close(self) -> None:
            closed.append(self.name)

    class FakeHostChecker:
        def __init__(self, hosts: list[str], nameservers: list[str]) -> None:
            assert hosts == ['www.example.com']
            assert set(nameservers) == {'192.0.2.53', '192.0.2.54', '192.0.2.55'}

        async def check(self) -> tuple[list[str], list[str], list[str]]:
            return ['www.example.com:192.0.2.10'], ['www.example.com'], ['192.0.2.10']

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, _domain: str, _items: list[str], _result_type: str, _source: str) -> None:
            return None

    evidence_store = SQLiteRunStore(tmp_path / 'evidence.sqlite')
    captured: list[run_module.RunResult] = []

    async def execute_with_temporary_store(
        target: str,
        source: run_module.PassiveSource,
        *,
        resolver_vantages: tuple[run_module.ResolverVantage, ...] | None = None,
    ) -> run_module.RunResult:
        result = await run_module.execute_run(
            target,
            source,
            resolver_vantages=resolver_vantages,
            store=evidence_store,
        )
        captured.append(result)
        return result

    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module.hostchecker, 'Checker', FakeHostChecker)
    monkeypatch.setattr(main_module, 'AioDNSResolverVantage', FakeProductionVantage, raising=True)
    monkeypatch.setattr(main_module, 'execute_run', execute_with_temporary_store, raising=True)

    await main_module.start(
        argparse.Namespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='192.0.2.53,192.0.2.54,192.0.2.55',
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

    assert set(created) == {'192.0.2.53', '192.0.2.54', '192.0.2.55'}
    assert set(closed) == set(created)
    assert captured[0].entities[0].addressability is Addressability.CURRENT

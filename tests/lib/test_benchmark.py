from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from theHarvester.lib.benchmark import (
    BenchmarkFixture,
    BenchmarkRunMetadata,
    compare_benchmarks,
    evaluate_benchmark,
    main,
    serialize_benchmark,
)
from theHarvester.lib.output import run_result_jsonl
from theHarvester.lib.run import (
    Addressability,
    Derivation,
    DiscoveryObservation,
    DNSResponse,
    DNSValidationObservation,
    MergedEntity,
    RunResult,
    ScopeClass,
    SourceFinding,
    SourceExecution,
    SourceStatus,
    execute_run,
)


def _observation(value: str, source: str, family: str, scope: ScopeClass = ScopeClass.IN_SCOPE) -> DiscoveryObservation:
    return DiscoveryObservation(
        run_id='fixture-run',
        target='benchmark.test',
        value=value,
        source=source,
        source_family=family,
        derivation=Derivation.PROVIDER,
        collected_at=datetime(2026, 1, 1, tzinfo=UTC),
        scope_class=scope,
    )


def _execution(source: str, family: str) -> SourceExecution:
    return SourceExecution(
        run_id='fixture-run',
        source=source,
        source_family=family,
        status=SourceStatus.SUCCEEDED,
        duration_ms=10,
        result_count=1,
        observation_count=1,
        entity_count=1,
    )


def _numeric_settings() -> dict[str, int]:
    return {
        'resolver_vantages': 3,
        'resolver_quorum': 2,
        'wildcard_probes_per_depth': 3,
        'recursive_depth': 2,
        'recursive_query_limit': 100,
        'qps_limit': 20,
        'runtime_limit_seconds': 5,
        'futility_zero_yield_batches': 3,
    }


def _validation(candidate: str) -> DNSValidationObservation:
    return DNSValidationObservation(
        run_id='fixture-run',
        candidate=candidate,
        query_name=candidate,
        resolver='fixture-resolver',
        queried_at=datetime(2026, 1, 1, tzinfo=UTC),
        ipv4=('192.0.2.10',),
        ipv6=(),
        cnames=(),
        rcode='NOERROR',
        ttl=60,
        cname_chain=(),
        latency_ms=1,
        error=None,
    )


def test_completed_run_is_scored_by_truth_and_distinct_source_families() -> None:
    api = _observation('api.benchmark.test', 'fixture-a', 'shared-corpus')
    shared_a = _observation('shared.benchmark.test', 'fixture-a', 'shared-corpus')
    shared_mirror = _observation('shared.benchmark.test', 'fixture-a-mirror', 'shared-corpus')
    shared_independent = _observation('shared.benchmark.test', 'fixture-b', 'independent-corpus')
    disputed = _observation('disputed.benchmark.test', 'fixture-b', 'independent-corpus')
    api_validation = _validation(api.value)
    shared_validation = _validation(shared_a.value)
    started = datetime(2026, 1, 1, tzinfo=UTC)
    result = RunResult(
        run_id='fixture-run',
        target='benchmark.test',
        started_at=started,
        completed_at=started + timedelta(milliseconds=250),
        source_executions=(
            _execution('fixture-a', 'shared-corpus'),
            _execution('fixture-a-mirror', 'shared-corpus'),
            _execution('fixture-b', 'independent-corpus'),
        ),
        observations=(api, shared_a, shared_mirror, shared_independent, disputed),
        dns_validations=(api_validation, shared_validation),
        entities=(
            MergedEntity('api.benchmark.test', (api,), Addressability.CURRENT, (api_validation,)),
            MergedEntity(
                'shared.benchmark.test',
                (shared_a, shared_mirror, shared_independent),
                Addressability.CURRENT,
                (shared_validation,),
            ),
            MergedEntity('disputed.benchmark.test', (disputed,), Addressability.RESOLVER_DISPUTED),
        ),
    )
    fixture = BenchmarkFixture.from_dict(
        {
            'fixture_id': 'public-v1',
            'expected_in_scope': ['api.benchmark.test', 'shared.benchmark.test', 'disputed.benchmark.test'],
            'dns_outcomes': {
                'api.benchmark.test': 'currently-addressable',
                'shared.benchmark.test': 'currently-addressable',
                'disputed.benchmark.test': 'resolver-disputed',
            },
            'wildcard_ancestry': {},
            'scope_extensions': ['related.example.test'],
            'external_relationships': ['cdn.example.test'],
            'source_payloads': {
                'fixture-a': ['api.benchmark.test', 'shared.benchmark.test'],
                'fixture-a-mirror': ['shared.benchmark.test'],
                'fixture-b': ['shared.benchmark.test', 'disputed.benchmark.test'],
            },
            'primary_truth': ['api.benchmark.test', 'shared.benchmark.test'],
            'known_inventory': ['api.benchmark.test', 'shared.benchmark.test'],
            'known_false': ['wild.benchmark.test'],
        }
    )
    settings = _numeric_settings()
    metadata = BenchmarkRunMetadata.from_dict(
        {
            'arm_id': 'baseline',
            'selected_sources': ['fixture-a', 'fixture-a-mirror', 'fixture-b'],
            'selected_actions': ['dns-validation'],
            'provider_availability': {
                'fixture-a': True,
                'fixture-a-mirror': True,
                'fixture-b': True,
            },
            'request_count': 3,
            'dns_query_count': 2,
            'declared_cost_microunits': 0,
            'declared_settings': settings,
            'effective_settings': settings,
            'budget': {
                'request_limit': 10,
                'dns_query_limit': 100,
                'runtime_limit_ms': 1000,
                'cost_limit_microunits': 0,
            },
        }
    )

    report = evaluate_benchmark(result, fixture, metadata)

    assert report['passed'] is True, report
    assert report['failures'] == []
    assert report['metrics']['unique_currently_addressable_yield'] == 2
    assert report['metrics']['known_inventory_recovery'] == {
        'numerator': 2,
        'denominator': 2,
        'ratio': '1.000000',
    }
    assert report['metrics']['precision'] == {'numerator': 2, 'denominator': 2, 'ratio': '1.000000'}
    assert report['metrics']['resolver_disagreement_count'] == 1
    assert report['metrics']['runtime_ms'] == 250
    assert report['attribution']['combined_unique_yield'] == 2
    assert report['attribution']['independent_family_counts'] == {'1': 1, '2': 1}
    assert report['attribution']['family_overlaps'][0]['yield'] == 1
    assert all(
        family.startswith('family-') for family in report['attribution']['family_overlaps'][0]['source_families']
    )
    assert sorted(
        (source['source_alone_yield'], source['exclusive_yield']) for source in report['attribution']['sources']
    ) == [(1, 0), (1, 0), (2, 1)]


def test_safety_completion_configuration_and_budget_gates_fail_closed() -> None:
    wildcard = _observation('wild.benchmark.test', 'unexpected-source', 'shared-corpus')
    external = _observation(
        'outside.example.test',
        'unexpected-source',
        'shared-corpus',
        ScopeClass.SCOPE_EXTENSION,
    )
    started = datetime(2026, 1, 1, tzinfo=UTC)
    result = RunResult(
        run_id='fixture-run',
        target='benchmark.test',
        started_at=started,
        completed_at=started + timedelta(seconds=2),
        source_executions=(
            SourceExecution(
                run_id='fixture-run',
                source='unexpected-source',
                source_family='shared-corpus',
                status=SourceStatus.FAILED,
                duration_ms=2000,
                result_count=2,
                observation_count=2,
                entity_count=2,
                error_type='SyntheticFailure',
            ),
        ),
        observations=(wildcard, external),
        dns_validations=(),
        entities=(
            MergedEntity('wild.benchmark.test', (wildcard,), Addressability.CURRENT),
            MergedEntity('outside.example.test', (external,), Addressability.CURRENT),
        ),
    )
    fixture = BenchmarkFixture.from_dict(
        {
            'fixture_id': 'public-v1',
            'expected_in_scope': ['good.benchmark.test', 'wild.benchmark.test'],
            'dns_outcomes': {
                'good.benchmark.test': 'currently-addressable',
                'wild.benchmark.test': 'wildcard-uncertain',
            },
            'wildcard_ancestry': {'wild.benchmark.test': 'benchmark.test'},
            'scope_extensions': ['outside.example.test'],
            'external_relationships': ['cdn.example.test'],
            'source_payloads': {'expected-source': ['good.benchmark.test']},
            'primary_truth': ['good.benchmark.test'],
            'known_inventory': ['good.benchmark.test'],
            'known_false': ['wild.benchmark.test'],
        }
    )
    metadata = BenchmarkRunMetadata.from_dict(
        {
            'arm_id': 'candidate',
            'selected_sources': ['expected-source'],
            'selected_actions': [],
            'provider_availability': {'expected-source': False},
            'request_count': 11,
            'dns_query_count': 2,
            'declared_cost_microunits': 2,
            'declared_settings': {'resolver_quorum': 2},
            'effective_settings': {'resolver_quorum': 1},
            'budget': {
                'request_limit': 10,
                'dns_query_limit': 1,
                'runtime_limit_ms': 1000,
                'cost_limit_microunits': 1,
            },
        }
    )

    report = evaluate_benchmark(result, fixture, metadata)

    assert report['passed'] is False
    assert report['failures'] == [
        'availability-mismatch',
        'configuration-mismatch',
        'cost-budget-exceeded',
        'dns-outcome-mismatch',
        'dns-query-accounting-mismatch',
        'dns-query-budget-exceeded',
        'fixture-source-mismatch',
        'known-false-primary',
        'missing-dns-evidence',
        'missing-selected-activity',
        'out-of-scope-promotion',
        'partial-run',
        'request-budget-exceeded',
        'runtime-budget-exceeded',
        'unselected-activity',
        'wildcard-false-positive',
    ]
    assert report['metrics']['wildcard_false_positive_count'] == 1
    assert report['metrics']['out_of_scope_promotion_count'] == 1
    assert report['metrics']['source_failures']['failed'] == 1


def _sanitized_case(arm_id: str, qps: int = 10) -> tuple[RunResult, BenchmarkFixture, BenchmarkRunMetadata]:
    observation = _observation('private-name.benchmark.test', 'provider-secret-token', 'sensitive-family')
    raw_payload_marker = _observation(
        'raw-provider-payload-marker',
        'provider-secret-token',
        'sensitive-family',
        ScopeClass.SCOPE_EXTENSION,
    )
    validation = _validation(observation.value)
    started = datetime(2026, 1, 1, tzinfo=UTC)
    result = RunResult(
        run_id='private-run-id',
        target='benchmark.test',
        started_at=started,
        completed_at=started + timedelta(milliseconds=100),
        source_executions=(_execution('provider-secret-token', 'sensitive-family'),),
        observations=(observation, raw_payload_marker),
        dns_validations=(validation,),
        entities=(MergedEntity(observation.value, (observation,), Addressability.CURRENT, (validation,)),),
    )
    fixture = BenchmarkFixture.from_dict(
        {
            'fixture_id': 'sanitized-v1',
            'expected_in_scope': [observation.value],
            'dns_outcomes': {observation.value: 'currently-addressable'},
            'wildcard_ancestry': {},
            'scope_extensions': ['scope-extension.private.test'],
            'external_relationships': ['external.private.test'],
            'source_payloads': {
                'provider-secret-token': [observation.value, raw_payload_marker.value],
            },
            'primary_truth': [observation.value],
            'known_inventory': [observation.value],
            'known_false': ['known-false.private.test'],
        }
    )
    settings = {'qps_limit': qps}
    metadata = BenchmarkRunMetadata.from_dict(
        {
            'arm_id': arm_id,
            'selected_sources': ['provider-secret-token'],
            'selected_actions': ['dns-validation'],
            'provider_availability': {'provider-secret-token': True},
            'request_count': 1,
            'dns_query_count': 1,
            'declared_cost_microunits': 0,
            'declared_settings': settings,
            'effective_settings': settings,
            'budget': {
                'request_limit': 5,
                'dns_query_limit': 1,
                'runtime_limit_ms': 500,
                'cost_limit_microunits': 0,
            },
        }
    )
    return result, fixture, metadata


def test_selected_source_must_match_the_complete_deterministic_fixture_payload() -> None:
    result, fixture, metadata = _sanitized_case('missing-payload')
    fixture = replace(
        fixture,
        source_payloads={
            'provider-secret-token': (*fixture.source_payloads['provider-secret-token'], 'missing.benchmark.test'),
        },
    )

    report = evaluate_benchmark(result, fixture, metadata)

    assert report['failures'] == ['fixture-source-mismatch']


def test_benchmark_artifact_is_deterministic_and_contains_only_aggregate_labels() -> None:
    result, fixture, metadata = _sanitized_case('baseline')
    report = evaluate_benchmark(result, fixture, metadata)

    artifact = serialize_benchmark(report)

    assert artifact == serialize_benchmark(report)
    assert json.loads(artifact)['attribution']['sources'][0]['source'].startswith('source-')
    for forbidden in (
        'benchmark.test',
        'private-name',
        'provider-secret-token',
        'sensitive-family',
        'raw-provider-payload-marker',
        'private-run-id',
        'scope-extension.private.test',
        'external.private.test',
        'known-false.private.test',
        '2026-01-01',
    ):
        assert forbidden not in artifact


def test_comparison_requires_equal_budgets_and_provider_availability_but_allows_tunable_settings() -> None:
    result, fixture, baseline_metadata = _sanitized_case('baseline', qps=10)
    _, _, candidate_metadata = _sanitized_case('candidate', qps=20)
    baseline = evaluate_benchmark(result, fixture, baseline_metadata)
    candidate = evaluate_benchmark(result, fixture, candidate_metadata)

    comparison = compare_benchmarks((baseline, candidate))

    assert comparison == {
        'schema_version': 'theharvester-benchmark-comparison-v1',
        'comparable': True,
        'reason': None,
        'arms': [
            {
                'arm_id': 'baseline',
                'effective_settings': {'qps_limit': 10},
                'unique_currently_addressable_yield': 1,
                'yield_delta_from_baseline': 0,
            },
            {
                'arm_id': 'candidate',
                'effective_settings': {'qps_limit': 20},
                'unique_currently_addressable_yield': 1,
                'yield_delta_from_baseline': 0,
            },
        ],
    }

    candidate['budget']['request_limit'] = 6
    assert compare_benchmarks((baseline, candidate))['reason'] == 'unequal-budget'
    candidate['budget']['request_limit'] = 5
    candidate['fixture_id'] = 'different-fixture'
    assert compare_benchmarks((baseline, candidate))['reason'] == 'unequal-fixture'
    candidate['fixture_id'] = baseline['fixture_id']
    candidate['comparison_context']['provider_availability'] = {'source-different': True}
    assert compare_benchmarks((baseline, candidate))['reason'] == 'unequal-provider-availability'


def test_public_cli_scores_local_jsonl_and_writes_only_the_sanitized_artifact(tmp_path: Path) -> None:
    fixture_path = tmp_path / 'truth.fixture'
    observation = _observation('api.benchmark.test', 'fixture-a', 'shared-corpus')
    validation = _validation(observation.value)
    started = datetime(2026, 1, 1, tzinfo=UTC)
    result = RunResult(
        run_id='local-private-run',
        target='benchmark.test',
        started_at=started,
        completed_at=started + timedelta(milliseconds=50),
        source_executions=(_execution('fixture-a', 'shared-corpus'),),
        observations=(observation,),
        dns_validations=(validation,),
        entities=(MergedEntity(observation.value, (observation,), Addressability.CURRENT, (validation,)),),
    )
    metadata = {
        'arm_id': 'cli-baseline',
        'selected_sources': ['fixture-a'],
        'selected_actions': ['dns-validation'],
        'provider_availability': {'fixture-a': True},
        'request_count': 1,
        'dns_query_count': 1,
        'declared_cost_microunits': 0,
        'declared_settings': {'qps_limit': 10},
        'effective_settings': {'qps_limit': 10},
        'budget': {
            'request_limit': 5,
            'dns_query_limit': 1,
            'runtime_limit_ms': 100,
            'cost_limit_microunits': 0,
        },
    }
    run_path = tmp_path / 'run.jsonl'
    metadata_path = tmp_path / 'metadata.json'
    output_path = tmp_path / 'report.json'
    fixture_path.write_text(
        json.dumps(
            {
                'fixture_id': 'cli-v1',
                'expected_in_scope': [observation.value],
                'dns_outcomes': {observation.value: 'currently-addressable'},
                'wildcard_ancestry': {},
                'scope_extensions': ['related.example.test'],
                'external_relationships': ['cdn.vendor.test'],
                'source_payloads': {'fixture-a': [observation.value]},
                'primary_truth': [observation.value],
                'known_inventory': [observation.value],
                'known_false': ['wild.benchmark.test'],
            }
        ),
        encoding='utf-8',
    )
    run_path.write_text(run_result_jsonl(result), encoding='utf-8')
    metadata_path.write_text(json.dumps(metadata), encoding='utf-8')

    exit_code = main(
        [
            '--run-jsonl',
            str(run_path),
            '--fixture',
            str(fixture_path),
            '--metadata',
            str(metadata_path),
            '--output',
            str(output_path),
        ]
    )

    artifact = output_path.read_text(encoding='utf-8')
    assert exit_code == 0
    assert json.loads(artifact)['metrics']['unique_currently_addressable_yield'] == 1
    assert 'benchmark.test' not in artifact
    assert 'local-private-run' not in artifact


def test_public_cli_fails_closed_without_echoing_sensitive_input_details(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_path = tmp_path / 'private-client-name-and-token.jsonl'
    secret_path.write_text('raw-secret-payload', encoding='utf-8')

    exit_code = main(
        [
            '--run-jsonl',
            str(secret_path),
            '--fixture',
            str(secret_path),
            '--metadata',
            str(secret_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ''
    assert captured.err == 'benchmark input error\n'


class FixtureSource:
    def __init__(self, name: str, family: str, values: tuple[str, ...], fixture: BenchmarkFixture) -> None:
        self.name = name
        self.family = family
        self.values = values
        self.fixture = fixture

    async def collect(self, _target: str) -> tuple[SourceFinding, ...]:
        return tuple(
            SourceFinding(
                value,
                Derivation.EXTERNAL_RELATIONSHIP
                if value in self.fixture.external_relationships
                else Derivation.RELATED
                if value in self.fixture.scope_extensions
                else Derivation.PROVIDER,
            )
            for value in self.values
        )


class FixtureResolver:
    def __init__(self, name: str) -> None:
        self.name = name

    async def query(self, hostname: str) -> DNSResponse:
        if hostname.startswith('th-'):
            if hostname.endswith('.dev.benchmark.test'):
                return DNSResponse(ipv4=('192.0.2.200',))
            return DNSResponse(rcode='NXDOMAIN')
        if hostname == 'api.benchmark.test':
            return DNSResponse(ipv4=('192.0.2.10',))
        if hostname == 'ipv6.benchmark.test':
            return DNSResponse(ipv6=('2001:db8::10',))
        if hostname == 'alias.benchmark.test':
            return DNSResponse(ipv4=('192.0.2.11',), cnames=('origin.benchmark.test',))
        if hostname == 'ghost.dev.benchmark.test':
            return DNSResponse(ipv4=('192.0.2.200',))
        if hostname == 'disputed.benchmark.test':
            if self.name == 'resolver-a':
                return DNSResponse(ipv4=('192.0.2.12',))
            if self.name == 'resolver-b':
                return DNSResponse(rcode='NXDOMAIN')
            return DNSResponse(rcode='ERROR', error='synthetic resolver error')
        if hostname == 'nodata.benchmark.test':
            return DNSResponse(rcode='NODATA')
        return DNSResponse(rcode='NXDOMAIN')


@pytest.mark.asyncio
async def test_repo_fixture_runs_only_through_fake_source_and_resolver_boundaries() -> None:
    fixture_path = Path(__file__).parents[1] / 'fixtures' / 'benchmark' / 'truth.fixture'
    fixture = BenchmarkFixture.from_dict(json.loads(fixture_path.read_text(encoding='utf-8')))
    families = {
        'fixture-a': 'shared-corpus',
        'fixture-a-mirror': 'shared-corpus',
        'fixture-b': 'independent-corpus',
    }
    resolvers = tuple(FixtureResolver(name) for name in ('resolver-a', 'resolver-b', 'resolver-c'))
    result = None
    for source_name, payload in fixture.source_payloads.items():
        result = await execute_run(
            'benchmark.test',
            FixtureSource(source_name, families[source_name], payload, fixture),
            resolver_vantages=resolvers,
            persist=False,
            base_result=result,
        )
    assert result is not None
    settings = _numeric_settings()
    metadata = BenchmarkRunMetadata.from_dict(
        {
            'arm_id': 'synthetic-fixture',
            'selected_sources': list(fixture.source_payloads),
            'selected_actions': ['dns-validation'],
            'provider_availability': dict.fromkeys(fixture.source_payloads, True),
            'request_count': len(fixture.source_payloads),
            'dns_query_count': len(result.dns_validations),
            'declared_cost_microunits': 0,
            'declared_settings': settings,
            'effective_settings': settings,
            'budget': {
                'request_limit': 10,
                'dns_query_limit': 1000,
                'runtime_limit_ms': 5000,
                'cost_limit_microunits': 0,
            },
        }
    )

    report = evaluate_benchmark(result, fixture, metadata)

    assert {
        entity.value: entity.addressability.value
        for entity in result.entities
        if entity.value in fixture.dns_outcomes
    } == fixture.dns_outcomes
    assert report['failures'] == []
    assert report['passed'] is True
    assert report['metrics']['unique_currently_addressable_yield'] == 3
    assert report['metrics']['resolver_disagreement_count'] == 1
    assert report['metrics']['wildcard_false_positive_count'] == 0
    assert report['attribution']['independent_family_counts'] == {'1': 2, '2': 1}

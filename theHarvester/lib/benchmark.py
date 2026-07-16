from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from itertools import combinations
from pathlib import Path
from typing import TYPE_CHECKING, Any

from theHarvester.lib.run import (
    Addressability,
    Derivation,
    DiscoveryObservation,
    DNSValidationObservation,
    MergedEntity,
    RunResult,
    RunStatus,
    ScopeClass,
    SourceExecution,
    SourceStatus,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

Number = int | float
_PUBLIC_ID_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')


def _public_id(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or value[0] not in _PUBLIC_ID_CHARS
        or any(character not in _PUBLIC_ID_CHARS for character in value)
    ):
        raise ValueError(f'{field} must be a 1-64 character public identifier')
    return value


def _strings(value: object, field: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f'{field} must be a list of strings')
    return frozenset(value)


def _string_map(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        raise ValueError(f'{field} must map strings to strings')
    return dict(value)


def _source_payloads(value: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        raise ValueError('source_payloads must be an object')
    payloads: dict[str, tuple[str, ...]] = {}
    for source, items in value.items():
        if not isinstance(source, str) or not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise ValueError('source_payloads must map source names to lists of strings')
        payloads[source] = tuple(items)
    return payloads


def _settings(value: object, field: str) -> dict[str, Number]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, (int, float)) and not isinstance(item, bool) for key, item in value.items()
    ):
        raise ValueError(f'{field} must map names to numeric values')
    return {_public_id(key, f'{field} key'): item for key, item in value.items()}


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f'{field} must be a non-negative integer')
    return value


def _nonnegative_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f'{field} must be a non-negative number')
    return float(value)


@dataclass(frozen=True, slots=True)
class BenchmarkFixture:
    fixture_id: str
    expected_in_scope: frozenset[str]
    dns_outcomes: Mapping[str, str]
    wildcard_ancestry: Mapping[str, str]
    scope_extensions: frozenset[str]
    external_relationships: frozenset[str]
    source_payloads: Mapping[str, tuple[str, ...]]
    primary_truth: frozenset[str]
    known_inventory: frozenset[str]
    known_false: frozenset[str]

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> BenchmarkFixture:
        required = {
            'fixture_id',
            'expected_in_scope',
            'dns_outcomes',
            'wildcard_ancestry',
            'scope_extensions',
            'external_relationships',
            'source_payloads',
            'primary_truth',
            'known_inventory',
            'known_false',
        }
        missing = required - data.keys()
        if missing:
            raise ValueError(f'missing fixture fields: {", ".join(sorted(missing))}')
        fixture = cls(
            fixture_id=_public_id(data['fixture_id'], 'fixture_id'),
            expected_in_scope=_strings(data['expected_in_scope'], 'expected_in_scope'),
            dns_outcomes=_string_map(data['dns_outcomes'], 'dns_outcomes'),
            wildcard_ancestry=_string_map(data['wildcard_ancestry'], 'wildcard_ancestry'),
            scope_extensions=_strings(data['scope_extensions'], 'scope_extensions'),
            external_relationships=_strings(data['external_relationships'], 'external_relationships'),
            source_payloads=_source_payloads(data['source_payloads']),
            primary_truth=_strings(data['primary_truth'], 'primary_truth'),
            known_inventory=_strings(data['known_inventory'], 'known_inventory'),
            known_false=_strings(data['known_false'], 'known_false'),
        )
        if not fixture.primary_truth <= fixture.expected_in_scope:
            raise ValueError('primary_truth must be a subset of expected_in_scope')
        if not fixture.known_inventory <= fixture.primary_truth:
            raise ValueError('known_inventory must be a subset of primary_truth')
        if fixture.dns_outcomes.keys() != fixture.expected_in_scope:
            raise ValueError('dns_outcomes must cover expected_in_scope exactly')
        if any(outcome not in Addressability for outcome in fixture.dns_outcomes.values()):
            raise ValueError('dns_outcomes contains an unsupported addressability')
        if not fixture.wildcard_ancestry.keys() <= fixture.expected_in_scope:
            raise ValueError('wildcard_ancestry names must be expected in-scope names')
        return fixture


@dataclass(frozen=True, slots=True)
class BenchmarkBudget:
    request_limit: int
    dns_query_limit: int
    runtime_limit_ms: float
    cost_limit_microunits: int

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> BenchmarkBudget:
        return cls(
            request_limit=_nonnegative_int(data.get('request_limit'), 'request_limit'),
            dns_query_limit=_nonnegative_int(data.get('dns_query_limit'), 'dns_query_limit'),
            runtime_limit_ms=_nonnegative_number(data.get('runtime_limit_ms'), 'runtime_limit_ms'),
            cost_limit_microunits=_nonnegative_int(data.get('cost_limit_microunits'), 'cost_limit_microunits'),
        )

    def to_dict(self) -> dict[str, int | float]:
        return {
            'request_limit': self.request_limit,
            'dns_query_limit': self.dns_query_limit,
            'runtime_limit_ms': self.runtime_limit_ms,
            'cost_limit_microunits': self.cost_limit_microunits,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkRunMetadata:
    arm_id: str
    selected_sources: frozenset[str]
    selected_actions: frozenset[str]
    provider_availability: Mapping[str, bool]
    request_count: int
    dns_query_count: int
    declared_cost_microunits: int
    declared_settings: Mapping[str, Number]
    effective_settings: Mapping[str, Number]
    budget: BenchmarkBudget

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> BenchmarkRunMetadata:
        availability = data.get('provider_availability')
        budget = data.get('budget')
        if not isinstance(availability, dict) or not all(
            isinstance(source, str) and isinstance(available, bool) for source, available in availability.items()
        ):
            raise ValueError('provider_availability must map source names to booleans')
        if not isinstance(budget, dict):
            raise ValueError('budget must be an object')
        return cls(
            arm_id=_public_id(data.get('arm_id'), 'arm_id'),
            selected_sources=_strings(data.get('selected_sources'), 'selected_sources'),
            selected_actions=_strings(data.get('selected_actions'), 'selected_actions'),
            provider_availability=dict(availability),
            request_count=_nonnegative_int(data.get('request_count'), 'request_count'),
            dns_query_count=_nonnegative_int(data.get('dns_query_count'), 'dns_query_count'),
            declared_cost_microunits=_nonnegative_int(data.get('declared_cost_microunits'), 'declared_cost_microunits'),
            declared_settings=_settings(data.get('declared_settings'), 'declared_settings'),
            effective_settings=_settings(data.get('effective_settings'), 'effective_settings'),
            budget=BenchmarkBudget.from_dict(budget),
        )


def _ratio(numerator: int, denominator: int) -> dict[str, int | str | None]:
    return {
        'numerator': numerator,
        'denominator': denominator,
        'ratio': f'{numerator / denominator:.6f}' if denominator else None,
    }


def _labels(values: set[str], prefix: str) -> dict[str, str]:
    return {value: f'{prefix}-{hashlib.sha256(value.encode()).hexdigest()[:12]}' for value in sorted(values)}


def _source_attribution(result: RunResult, primary: set[str]) -> dict[str, object]:
    primary_entities = tuple(entity for entity in result.entities if entity.value in primary)
    sources = {observation.source for entity in primary_entities for observation in entity.observations} | {
        execution.source for execution in result.source_executions
    }
    families = {observation.source_family for entity in primary_entities for observation in entity.observations} | {
        execution.source_family for execution in result.source_executions
    }
    source_labels = _labels(sources, 'source')
    family_labels = _labels(families, 'family')
    source_family = {execution.source: execution.source_family for execution in result.source_executions}
    for entity in primary_entities:
        for observation in entity.observations:
            source_family[observation.source] = observation.source_family

    source_results = []
    for source in sorted(sources):
        supported = {
            entity.value for entity in primary_entities if source in {observation.source for observation in entity.observations}
        }
        exclusive = {
            entity.value for entity in primary_entities if {observation.source for observation in entity.observations} == {source}
        }
        source_results.append(
            {
                'source': source_labels[source],
                'source_family': family_labels[source_family[source]],
                'currently_addressable_yield': len(supported),
                'source_alone_yield': len(supported),
                'exclusive_yield': len(exclusive),
            }
        )

    family_results = []
    corroboration: dict[str, int] = {}
    family_overlap_counts: dict[tuple[str, str], int] = {}
    for family in sorted(families):
        supported = {
            entity.value
            for entity in primary_entities
            if family in {observation.source_family for observation in entity.observations}
        }
        family_results.append({'source_family': family_labels[family], 'currently_addressable_yield': len(supported)})
    for entity in primary_entities:
        entity_families = sorted({observation.source_family for observation in entity.observations})
        count = len(entity_families)
        corroboration[str(count)] = corroboration.get(str(count), 0) + 1
        for left, right in combinations(entity_families, 2):
            pair = (family_labels[left], family_labels[right])
            family_overlap_counts[pair] = family_overlap_counts.get(pair, 0) + 1

    return {
        'combined_unique_yield': len(primary),
        'sources': source_results,
        'source_families': family_results,
        'independent_family_counts': dict(sorted(corroboration.items())),
        'family_overlaps': [
            {'source_families': list(pair), 'yield': count} for pair, count in sorted(family_overlap_counts.items())
        ],
    }


def evaluate_benchmark(
    result: RunResult,
    fixture: BenchmarkFixture,
    metadata: BenchmarkRunMetadata,
) -> dict[str, Any]:
    """Evaluate one completed run without exposing entity-level evidence."""

    def is_subdomain(value: str) -> bool:
        return value.endswith(f'.{result.target}')

    primary = {
        entity.value
        for entity in result.entities
        if entity.addressability is Addressability.CURRENT
        and ScopeClass.IN_SCOPE in entity.scope_classes
        and is_subdomain(entity.value)
    }
    true_primary = primary & fixture.primary_truth
    wildcard_false = primary & (fixture.known_false | fixture.wildcard_ancestry.keys())
    out_of_scope_current = {
        entity.value
        for entity in result.entities
        if entity.addressability is Addressability.CURRENT
        and (
            not is_subdomain(entity.value)
            or ScopeClass.IN_SCOPE not in entity.scope_classes
            or entity.value in fixture.scope_extensions
            or entity.value in fixture.external_relationships
        )
    }
    missing_dns_evidence = {
        entity.value
        for entity in result.entities
        if entity.addressability is Addressability.CURRENT
        and not any(
            not validation.is_wildcard_control and bool(validation.ipv4 or validation.ipv6)
            for validation in entity.dns_validations
        )
    }
    dns_outcome_mismatches = {
        entity.value
        for entity in result.entities
        if (expected := fixture.dns_outcomes.get(entity.value)) is not None and entity.addressability.value != expected
    }
    observed_source_payloads = {
        source: {
            observation.value
            for observation in result.observations
            if observation.source == source and not observation.source.startswith('action:')
        }
        for source in metadata.selected_sources
    }
    fixture_source_mismatch = any(
        observed_source_payloads[source] != set(fixture.source_payloads.get(source, ())) for source in metadata.selected_sources
    )
    actual_executions = {execution.source for execution in result.source_executions}
    expected_executions = metadata.selected_sources | {
        f'action:{action}' for action in metadata.selected_actions if action != 'dns-validation'
    }
    incomplete_statuses = {SourceStatus.FAILED, SourceStatus.RATE_LIMITED, SourceStatus.SKIPPED}
    failure_counts = {
        status.value: sum(execution.status is status for execution in result.source_executions)
        for status in sorted(incomplete_statuses, key=str)
    }
    runtime_ms = max(0.0, (result.completed_at - result.started_at).total_seconds() * 1000)
    availability_labels = _labels(set(metadata.provider_availability), 'source')

    failures: list[str] = []
    if primary - fixture.primary_truth:
        failures.append('known-false-primary')
    if wildcard_false:
        failures.append('wildcard-false-positive')
    if missing_dns_evidence:
        failures.append('missing-dns-evidence')
    if dns_outcome_mismatches:
        failures.append('dns-outcome-mismatch')
    if fixture_source_mismatch:
        failures.append('fixture-source-mismatch')
    if out_of_scope_current or any(
        observation.derivation is Derivation.RECURSIVE_DNS
        and (
            observation.value not in fixture.expected_in_scope
            or (observation.parent is not None and observation.parent not in fixture.expected_in_scope | {result.target})
        )
        for observation in result.observations
    ):
        failures.append('out-of-scope-promotion')
    if (
        actual_executions - expected_executions
        or any(observation.source not in expected_executions for observation in result.observations)
        or (bool(result.dns_validations) and 'dns-validation' not in metadata.selected_actions)
    ):
        failures.append('unselected-activity')
    if expected_executions - actual_executions or ('dns-validation' in metadata.selected_actions and not result.dns_validations):
        failures.append('missing-selected-activity')
    if result.status is not RunStatus.COMPLETE or any(failure_counts.values()) or not result.source_executions:
        failures.append('partial-run')
    if metadata.declared_settings != metadata.effective_settings:
        failures.append('configuration-mismatch')
    if any(not metadata.provider_availability.get(source, False) for source in metadata.selected_sources):
        failures.append('availability-mismatch')
    if metadata.request_count > metadata.budget.request_limit:
        failures.append('request-budget-exceeded')
    if metadata.dns_query_count > metadata.budget.dns_query_limit:
        failures.append('dns-query-budget-exceeded')
    if metadata.dns_query_count != len(result.dns_validations):
        failures.append('dns-query-accounting-mismatch')
    if runtime_ms > metadata.budget.runtime_limit_ms:
        failures.append('runtime-budget-exceeded')
    if metadata.declared_cost_microunits > metadata.budget.cost_limit_microunits:
        failures.append('cost-budget-exceeded')

    return {
        'schema_version': 'theharvester-benchmark-v1',
        'fixture_id': fixture.fixture_id,
        'arm_id': metadata.arm_id,
        'passed': not failures,
        'failures': sorted(set(failures)),
        'metrics': {
            'unique_currently_addressable_yield': len(primary),
            'known_inventory_recovery': _ratio(len(primary & fixture.known_inventory), len(fixture.known_inventory)),
            'precision': _ratio(len(true_primary), len(primary)),
            'wildcard_false_positive_count': len(wildcard_false),
            'resolver_disagreement_count': sum(
                entity.addressability is Addressability.RESOLVER_DISPUTED for entity in result.entities
            ),
            'out_of_scope_promotion_count': len(out_of_scope_current),
            'source_failures': failure_counts,
            'runtime_ms': round(runtime_ms, 6),
            'request_count': metadata.request_count,
            'dns_query_count': metadata.dns_query_count,
            'declared_cost_microunits': metadata.declared_cost_microunits,
        },
        'attribution': _source_attribution(result, primary),
        'effective_settings': dict(sorted(metadata.effective_settings.items())),
        'budget': metadata.budget.to_dict(),
        'comparison_context': {
            'provider_availability': {
                availability_labels[source]: metadata.provider_availability[source]
                for source in sorted(metadata.provider_availability)
            },
        },
    }


def serialize_benchmark(report: Mapping[str, object]) -> str:
    """Return a canonical aggregate-only benchmark artifact."""
    return json.dumps(report, sort_keys=True, separators=(',', ':'))


def compare_benchmarks(reports: tuple[Mapping[str, Any], ...]) -> dict[str, object]:
    """Compare qualified arms only under the same declared budget and provider availability."""
    if len(reports) < 2:
        raise ValueError('at least two benchmark reports are required')
    baseline_context = reports[0].get('comparison_context')
    if not isinstance(baseline_context, dict):
        raise ValueError('benchmark report is missing comparison context')
    contexts = [report.get('comparison_context') for report in reports]
    reason: str | None = None
    if any(not report.get('passed') for report in reports):
        reason = 'qualification-failed'
    elif any(not isinstance(context, dict) for context in contexts):
        reason = 'missing-comparison-context'
    elif any(report.get('fixture_id') != reports[0].get('fixture_id') for report in reports[1:]):
        reason = 'unequal-fixture'
    elif any(report.get('budget') != reports[0].get('budget') for report in reports[1:]):
        reason = 'unequal-budget'
    elif any(
        isinstance(context, dict) and context.get('provider_availability') != baseline_context.get('provider_availability')
        for context in contexts[1:]
    ):
        reason = 'unequal-provider-availability'

    arms: list[dict[str, object]] = []
    if reason is None:
        baseline_metrics = reports[0].get('metrics')
        if not isinstance(baseline_metrics, dict):
            raise ValueError('benchmark report is missing metrics')
        baseline_yield = baseline_metrics.get('unique_currently_addressable_yield')
        if not isinstance(baseline_yield, int):
            raise ValueError('benchmark yield must be an integer')
        for report in reports:
            metrics = report.get('metrics')
            settings = report.get('effective_settings')
            arm_id = report.get('arm_id')
            if not isinstance(metrics, dict) or not isinstance(settings, dict) or not isinstance(arm_id, str):
                raise ValueError('benchmark report is missing arm data')
            current_yield = metrics.get('unique_currently_addressable_yield')
            if not isinstance(current_yield, int):
                raise ValueError('benchmark yield must be an integer')
            arms.append(
                {
                    'arm_id': arm_id,
                    'effective_settings': settings,
                    'unique_currently_addressable_yield': current_yield,
                    'yield_delta_from_baseline': current_yield - baseline_yield,
                }
            )

    return {
        'schema_version': 'theharvester-benchmark-comparison-v1',
        'comparable': reason is None,
        'reason': reason,
        'arms': arms,
    }


def _discovery_observation(data: Mapping[str, Any]) -> DiscoveryObservation:
    provider_observed_at = data.get('provider_observed_at')
    return DiscoveryObservation(
        run_id=data['run_id'],
        target=data['target'],
        value=data['value'],
        source=data['source'],
        source_family=data['source_family'],
        derivation=Derivation(data['derivation']),
        collected_at=datetime.fromisoformat(data['collected_at']),
        scope_class=ScopeClass(data['scope_class']),
        provider_observed_at=datetime.fromisoformat(provider_observed_at) if provider_observed_at is not None else None,
        parent=data.get('parent'),
    )


def _dns_validation(data: Mapping[str, Any]) -> DNSValidationObservation:
    return DNSValidationObservation(
        run_id=data['run_id'],
        candidate=data['candidate'],
        query_name=data['query_name'],
        resolver=data['resolver'],
        queried_at=datetime.fromisoformat(data['validated_at']),
        ipv4=tuple(data['ipv4']),
        ipv6=tuple(data['ipv6']),
        cnames=tuple(data['cnames']),
        rcode=data['rcode'],
        ttl=data['ttl'],
        cname_chain=tuple(data['cname_chain']),
        latency_ms=data['latency_ms'],
        error=data['error'],
        is_wildcard_control=data['is_wildcard_control'],
        wildcard_depth=data['wildcard_depth'],
    )


def _source_execution(data: Mapping[str, Any]) -> SourceExecution:
    return SourceExecution(
        run_id=data['run_id'],
        source=data['source'],
        source_family=data['source_family'],
        status=SourceStatus(data['status']),
        duration_ms=data['duration_ms'],
        result_count=data['result_count'],
        observation_count=data['observation_count'],
        entity_count=data['entity_count'],
        error_type=data.get('error_type'),
        query_count=data.get('query_count'),
        depth_reached=data.get('depth_reached'),
        zero_yield_batches=data.get('zero_yield_batches'),
        stop_reason=data.get('stop_reason'),
    )


def load_run_jsonl(path: str | Path) -> RunResult:
    """Load the existing normalized evidence JSONL for offline scoring."""
    records: dict[str, list[dict[str, Any]]] = {}
    for line_number, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict) or record.get('schema_version') != 'theharvester-evidence-v1':
            raise ValueError(f'invalid evidence record on line {line_number}')
        record_type = record.get('record_type')
        data = record.get('data')
        if not isinstance(record_type, str) or not isinstance(data, dict):
            raise ValueError(f'invalid evidence record on line {line_number}')
        records.setdefault(record_type, []).append(data)
    run_records = records.get('run', [])
    if len(run_records) != 1:
        raise ValueError('evidence JSONL must contain exactly one run record')
    run = run_records[0]
    observations = tuple(_discovery_observation(data) for data in records.get('discovery_observation', []))
    validations = tuple(_dns_validation(data) for data in records.get('dns_validation_observation', []))
    entities = tuple(
        MergedEntity(
            value=data['value'],
            observations=tuple(_discovery_observation(item) for item in data['provenance']),
            addressability=Addressability(data['addressability']),
            dns_validations=tuple(validation for validation in validations if validation.candidate == data['value']),
        )
        for data in records.get('merged_result', [])
    )
    return RunResult(
        run_id=run['run_id'],
        target=run['target'],
        started_at=datetime.fromisoformat(run['started_at']),
        completed_at=datetime.fromisoformat(run['completed_at']),
        source_executions=tuple(_source_execution(data) for data in records.get('source_execution', [])),
        observations=observations,
        dns_validations=validations,
        entities=entities,
    )


def _load_json_object(path: str | Path) -> dict[str, object]:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError(f'{path} must contain one JSON object')
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Score a completed evidence run against a deterministic fixture.')
    parser.add_argument('--run-jsonl', required=True, help='Completed theHarvester evidence JSONL')
    parser.add_argument('--fixture', required=True, help='Synthetic benchmark truth JSON')
    parser.add_argument('--metadata', required=True, help='Applied settings, accounting, availability, and budget JSON')
    parser.add_argument('--output', help='Write the sanitized report here instead of standard output')
    args = parser.parse_args(argv)
    try:
        result = load_run_jsonl(args.run_jsonl)
        fixture = BenchmarkFixture.from_dict(_load_json_object(args.fixture))
        metadata = BenchmarkRunMetadata.from_dict(_load_json_object(args.metadata))
        report = evaluate_benchmark(result, fixture, metadata)
        artifact = serialize_benchmark(report)
        if args.output:
            Path(args.output).write_text(f'{artifact}\n', encoding='utf-8')
        else:
            print(artifact)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print('benchmark input error', file=sys.stderr)
        return 2
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

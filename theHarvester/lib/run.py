from __future__ import annotations

import logging
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

from theHarvester.lib.dns_validation import (
    Addressability,
    DnsValidationObservation,
    DnsValidator,
)
from theHarvester.lib.hostnames import normalize_hostname

if TYPE_CHECKING:
    from collections.abc import Collection, Sequence

logger = logging.getLogger(__name__)


class Derivation(StrEnum):
    PROVIDER = 'provider'
    DNS = 'dns'


class ScopeClass(StrEnum):
    IN_SCOPE = 'in-scope'
    SCOPE_EXTENSION = 'scope-extension'
    EXTERNAL_RELATIONSHIP = 'external-relationship'


class ExecutionStatus(StrEnum):
    SUCCEEDED = 'succeeded'
    PARTIAL = 'partial'
    EMPTY = 'empty'
    FAILED = 'failed'
    RATE_LIMITED = 'rate-limited'


SourceStatus = ExecutionStatus


class RunStatus(StrEnum):
    COMPLETE = 'complete'
    PARTIAL = 'partial'
    FAILED = 'failed'


class ActivityClass(StrEnum):
    PASSIVE = 'P0 passive collection'
    DNS = 'P1 DNS interaction'
    DIRECT = 'P2 direct interaction'


class SourceIncompleteError(Exception):
    status = ExecutionStatus.FAILED

    def __init__(self, message: str = '', *, findings: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.findings = tuple(findings)


class SourceRateLimitedError(SourceIncompleteError):
    status = ExecutionStatus.RATE_LIMITED


class PassiveSource(Protocol):
    @property
    def name(self) -> str: ...

    async def collect(self, target: str) -> Sequence[str]: ...


class LegacyHostnameSearch(Protocol):
    async def process(self, proxy: bool = False) -> None: ...

    async def get_hostnames(self) -> Collection[str]: ...


@dataclass(frozen=True)
class LegacyHostnameSource:
    name: str
    legacy_name: str
    search: LegacyHostnameSearch
    proxy: bool = False

    async def collect(self, _target: str) -> tuple[str, ...]:
        await self.search.process(self.proxy)
        return tuple(await self.search.get_hostnames())


@dataclass(frozen=True)
class DiscoveryObservation:
    value: str
    source: str
    derivation: Derivation
    collected_at: datetime
    scope_class: ScopeClass

    def to_dict(self) -> dict[str, object]:
        return {
            'value': self.value,
            'source': self.source,
            'derivation': self.derivation,
            'collected_at': self.collected_at.isoformat(),
            'scope_class': self.scope_class,
        }


@dataclass(frozen=True)
class RunExecution:
    name: str
    activity: ActivityClass
    status: ExecutionStatus
    duration_ms: float
    result_count: int
    observation_count: int = 0
    entity_count: int = 0
    error_type: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @property
    def source(self) -> str:
        return self.name

    def to_dict(self) -> dict[str, object]:
        return {
            'name': self.name,
            'activity': self.activity,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'observation_count': self.observation_count,
            'entity_count': self.entity_count,
            'error_type': self.error_type,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }


SourceExecution = RunExecution


@dataclass(frozen=True)
class ResultRecord:
    type: str
    value: str
    sources: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {'type': self.type, 'value': self.value}
        if self.sources:
            result['sources'] = list(self.sources)
        return result


@dataclass(frozen=True)
class MergedEntity:
    value: str
    observations: tuple[DiscoveryObservation, ...]
    addressability: Addressability | None = None

    @property
    def scope_classes(self) -> tuple[ScopeClass, ...]:
        return tuple(dict.fromkeys(observation.scope_class for observation in self.observations))

    def to_dict(self) -> dict[str, object]:
        return {
            'value': self.value,
            'scope_classes': list(self.scope_classes),
            'addressability': self.addressability,
            'sources': sorted({observation.source for observation in self.observations}),
        }


@dataclass(frozen=True)
class RunResult:
    run_id: str
    target: str
    started_at: datetime
    completed_at: datetime | None
    executions: tuple[RunExecution, ...]
    observations: tuple[DiscoveryObservation, ...]
    entities: tuple[MergedEntity, ...]
    dns_validations: tuple[DnsValidationObservation, ...] = ()
    results: tuple[ResultRecord, ...] = ()

    @property
    def source_executions(self) -> tuple[RunExecution, ...]:
        return tuple(execution for execution in self.executions if execution.activity is ActivityClass.PASSIVE)

    @property
    def status(self) -> RunStatus:
        if self.completed_at is None:
            raise RuntimeError('run is not complete')
        incomplete = {ExecutionStatus.PARTIAL, ExecutionStatus.FAILED, ExecutionStatus.RATE_LIMITED}
        if self.executions and all(
            execution.status in incomplete and execution.result_count == 0 for execution in self.executions
        ):
            return RunStatus.FAILED
        if any(execution.status in incomplete for execution in self.executions):
            return RunStatus.PARTIAL
        return RunStatus.COMPLETE

    def to_dict(self) -> dict[str, object]:
        if self.completed_at is None:
            raise RuntimeError('run is not complete')
        return {
            'run_id': self.run_id,
            'target': self.target,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat(),
            'status': self.status,
            'executions': [execution.to_dict() for execution in self.executions],
            'results': [result.to_dict() for result in self.results],
            'observations': [observation.to_dict() for observation in self.observations],
            'entities': [entity.to_dict() for entity in self.entities],
            'dns_validations': [
                {
                    'candidate': observation.candidate,
                    'query_name': observation.query_name,
                    'resolver': observation.resolver,
                    'queried_at': observation.queried_at.isoformat(),
                    'ipv4': list(observation.ipv4),
                    'ipv6': list(observation.ipv6),
                    'cnames': list(observation.cnames),
                    'rcode': observation.rcode,
                    'ttl': observation.ttl,
                    'cname_chain': list(observation.cname_chain),
                    'latency_ms': observation.latency_ms,
                    'error': observation.error,
                    'is_wildcard_control': observation.is_wildcard_control,
                    'wildcard_depth': observation.wildcard_depth,
                }
                for observation in self.dns_validations
            ],
        }


def _classify_scope(target: str, value: str) -> ScopeClass:
    if value == target or value.endswith(f'.{target}'):
        return ScopeClass.IN_SCOPE
    return ScopeClass.SCOPE_EXTENSION


def _merge_observations(observations: Sequence[DiscoveryObservation]) -> tuple[MergedEntity, ...]:
    grouped: dict[str, list[DiscoveryObservation]] = {}
    for observation in observations:
        grouped.setdefault(observation.value, []).append(observation)
    return tuple(MergedEntity(value, tuple(supporting)) for value, supporting in grouped.items())


def start_run(target: str) -> RunResult:
    """Start one incomplete enumeration run for the supplied target."""
    normalized_target = normalize_hostname(target)
    if normalized_target is None:
        raise ValueError('target must be a hostname')
    return RunResult(
        run_id=str(uuid4()),
        target=normalized_target,
        started_at=datetime.now(UTC),
        completed_at=None,
        executions=(),
        observations=(),
        entities=(),
    )


def add_run_evidence(
    run: RunResult,
    *,
    executions: Sequence[RunExecution] = (),
    observations: Sequence[DiscoveryObservation] = (),
) -> RunResult:
    """Add finished work to an incomplete run without reporting it as complete."""
    if run.completed_at is not None:
        raise RuntimeError('run is already complete')
    merged_observations = (*run.observations, *observations)
    previous_entities = {entity.value: entity for entity in run.entities}
    entities = tuple(
        replace(entity, addressability=previous.addressability)
        if (previous := previous_entities.get(entity.value)) is not None
        else entity
        for entity in _merge_observations(merged_observations)
    )
    return replace(
        run,
        executions=(*run.executions, *executions),
        observations=merged_observations,
        entities=entities,
    )


async def validate_run(
    run: RunResult,
    dns_validator: DnsValidator,
    *,
    deterministic_exact_dns_names: tuple[str, ...] = (),
) -> RunResult:
    """Attach current DNS consensus evidence without completing the run."""
    if run.completed_at is not None:
        raise RuntimeError('run is already complete')
    candidates = tuple(
        entity.value for entity in run.entities if ScopeClass.IN_SCOPE in entity.scope_classes and entity.addressability is None
    )
    if not candidates:
        return run
    validation = await dns_validator.validate(
        run.run_id,
        run.target,
        candidates,
        deterministic_exact_names=deterministic_exact_dns_names,
    )
    classifications = {classification.candidate: classification.addressability for classification in validation.classifications}
    return replace(
        run,
        entities=tuple(replace(entity, addressability=classifications.get(entity.value)) for entity in run.entities),
        dns_validations=(*run.dns_validations, *validation.observations),
    )


async def execute_run(
    target: str,
    sources: Sequence[PassiveSource],
    *,
    dns_validator: DnsValidator | None = None,
    deterministic_exact_dns_names: tuple[str, ...] = (),
    run: RunResult | None = None,
) -> RunResult:
    normalized_target = normalize_hostname(target)
    if normalized_target is None:
        raise ValueError('target must be a hostname')
    result = run or start_run(normalized_target)
    if result.completed_at is not None:
        raise RuntimeError('run is already complete')
    if result.target != normalized_target:
        raise ValueError('run target does not match target')
    executions: list[RunExecution] = []
    observations: list[DiscoveryObservation] = []

    for source in sources:
        logger.info(f'Source {source.name} started')
        source_started_at = datetime.now(UTC)
        source_started = time.perf_counter()
        source_observations: tuple[DiscoveryObservation, ...] = ()
        status = SourceStatus.FAILED
        result_count = 0
        error_type: str | None = None
        findings: tuple[str, ...] = ()

        try:
            findings = tuple(await source.collect(normalized_target))
            status = SourceStatus.SUCCEEDED
        except SourceIncompleteError as error:
            findings = error.findings
            status = error.status
            error_type = type(error).__name__
        except Exception as error:
            error_type = type(error).__name__
            logger.exception(f'Source {source.name} failed')

        result_count = len(findings)
        try:
            collected_at = datetime.now(UTC)
            normalized_observations = []
            for finding in findings:
                value = normalize_hostname(finding)
                if value is None:
                    continue
                normalized_observations.append(
                    DiscoveryObservation(
                        value=value,
                        source=source.name,
                        derivation=Derivation.PROVIDER,
                        collected_at=collected_at,
                        scope_class=_classify_scope(normalized_target, value),
                    )
                )
            source_observations = tuple(normalized_observations)
            if status is SourceStatus.SUCCEEDED and not source_observations:
                status = SourceStatus.EMPTY
        except Exception as error:
            source_observations = ()
            status = SourceStatus.FAILED
            error_type = type(error).__name__
            logger.exception(f'Source {source.name} failed')

        source_entities = _merge_observations(source_observations)
        executions.append(
            RunExecution(
                name=source.name,
                activity=ActivityClass.PASSIVE,
                status=status,
                duration_ms=(time.perf_counter() - source_started) * 1000,
                result_count=result_count,
                observation_count=len(source_observations),
                entity_count=len(source_entities),
                error_type=error_type,
                started_at=source_started_at,
                completed_at=datetime.now(UTC),
            )
        )
        observations.extend(source_observations)
        logger.info(f'Source {source.name} completed with status {status}')

    result = add_run_evidence(result, executions=executions, observations=observations)
    return (
        await validate_run(
            result,
            dns_validator,
            deterministic_exact_dns_names=deterministic_exact_dns_names,
        )
        if dns_validator is not None
        else result
    )


def complete_run(
    run: RunResult,
    *,
    results: Sequence[ResultRecord] = (),
    executions: Sequence[RunExecution] = (),
    completed_at: datetime | None = None,
) -> RunResult:
    """Return one immutable result after every selected execution finishes."""
    if run.completed_at is not None:
        raise RuntimeError('run is already complete')
    result_sources: dict[tuple[str, str], set[str]] = {}
    for result in results:
        result_sources.setdefault((result.type, result.value), set()).update(result.sources)
    return replace(
        run,
        completed_at=completed_at or datetime.now(UTC),
        executions=(*run.executions, *executions),
        results=tuple(
            ResultRecord(result_type, value, tuple(sorted(sources))) for (result_type, value), sources in result_sources.items()
        ),
    )


def legacy_hostnames(result: RunResult, source: str | None = None) -> list[str]:
    """Return the host list consumed by the existing CLI, REST, file, and stash paths."""
    validated_hosts = {entity.value for entity in result.entities if entity.addressability is Addressability.CURRENT}
    return sorted(
        {
            observation.value
            for observation in result.observations
            if observation.value != result.target
            and observation.scope_class is ScopeClass.IN_SCOPE
            and (source is None or observation.source == source)
            and (not result.dns_validations or observation.value in validated_hosts)
        }
    )


def legacy_dns_results(result: RunResult, source: str | None = None) -> tuple[list[str], list[str], list[str]]:
    hosts = legacy_hostnames(result, source)
    host_set = set(hosts)
    addresses_by_host: dict[str, set[str]] = {host: set() for host in hosts}
    for observation in result.dns_validations:
        if not observation.is_wildcard_control and observation.candidate in host_set:
            addresses_by_host[observation.candidate].update((*observation.ipv4, *observation.ipv6))
    addresses = sorted({address for values in addresses_by_host.values() for address in values})
    resolved = [f'{host}:{",".join(sorted(addresses_by_host[host]))}' if addresses_by_host[host] else host for host in hosts]
    return resolved, hosts, addresses

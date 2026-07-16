from __future__ import annotations

import asyncio
import ipaddress
import json
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

import aiodns
import aiosqlite

if TYPE_CHECKING:
    from collections.abc import Sequence


class Derivation(StrEnum):
    PROVIDER = 'provider'
    RELATED = 'related'
    EXTERNAL_RELATIONSHIP = 'external-relationship'


class ScopeClass(StrEnum):
    IN_SCOPE = 'in-scope'
    SCOPE_EXTENSION = 'scope-extension'
    EXTERNAL_RELATIONSHIP = 'external-relationship'


class Addressability(StrEnum):
    UNVERIFIED = 'unverified'
    CURRENT = 'currently-addressable'
    NOT_CURRENT = 'not-currently-addressable'
    RESOLVER_DISPUTED = 'resolver-disputed'
    WILDCARD_UNCERTAIN = 'wildcard-uncertain'


class SourceStatus(StrEnum):
    SUCCEEDED = 'succeeded'
    EMPTY = 'empty'
    FAILED = 'failed'
    RATE_LIMITED = 'rate-limited'
    SKIPPED = 'skipped'


class SourceRateLimitedError(Exception):
    pass


class SourceSkippedError(Exception):
    pass


@dataclass(frozen=True)
class SourceFinding:
    value: str
    derivation: Derivation = Derivation.PROVIDER


class PassiveSource(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def family(self) -> str: ...

    async def collect(self, target: str) -> Sequence[SourceFinding]: ...


@dataclass(frozen=True)
class DNSResponse:
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()
    rcode: str = 'NOERROR'
    ttl: int | None = None
    cname_chain: tuple[str, ...] = ()
    error: str | None = None


class ResolverVantage(Protocol):
    @property
    def name(self) -> str: ...

    async def query(self, hostname: str) -> DNSResponse: ...


class AioDNSResolverVantage:
    """A single operator-selected resolver exposed through the validation boundary."""

    def __init__(self, nameserver: str) -> None:
        self.name = nameserver
        self._resolver = aiodns.DNSResolver(nameservers=[nameserver])

    async def query(self, hostname: str) -> DNSResponse:
        record_types = ('A', 'AAAA', 'CNAME')
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        cnames: list[str] = []
        ttls: list[int] = []
        dns_error_codes: list[int] = []
        errors: list[str] = []
        successful_query = False
        current = _normalize_hostname(hostname)
        seen = {current}
        for _ in range(_MAX_CNAME_DEPTH):
            results = await asyncio.gather(
                *(self._resolver.query_dns(current, record_type) for record_type in record_types),
                return_exceptions=True,
            )
            next_cnames: list[str] = []
            for result in results:
                if isinstance(result, asyncio.CancelledError):
                    raise result
                if isinstance(result, BaseException):
                    if isinstance(result, aiodns.error.DNSError):
                        dns_error_codes.append(result.args[0])
                        if result.args[0] in {aiodns.error.ARES_ENOTFOUND, aiodns.error.ARES_ENODATA}:
                            continue
                    errors.append(f'{type(result).__name__}: {result}')
                    continue
                successful_query = True
                for record in result.answer:
                    ttl = getattr(record, 'ttl', None)
                    if ttl is not None:
                        ttls.append(ttl)
                    address = getattr(record.data, 'addr', None)
                    if address is not None:
                        parsed_address = ipaddress.ip_address(address)
                        (ipv4 if parsed_address.version == 4 else ipv6).add(str(parsed_address))
                    cname = getattr(record.data, 'cname', None)
                    if cname is not None:
                        normalized_cname = _normalize_hostname(cname)
                        if normalized_cname not in next_cnames:
                            next_cnames.append(normalized_cname)
            if not next_cnames:
                break
            for cname in next_cnames:
                if cname not in cnames:
                    cnames.append(cname)
            next_target = next_cnames[-1]
            if next_target in seen:
                errors.append(f'CNAME loop detected at {next_target}')
                break
            seen.add(next_target)
            current = next_target
        else:
            errors.append(f'CNAME chain exceeded {_MAX_CNAME_DEPTH} links')
        if successful_query:
            rcode = 'NOERROR'
        elif dns_error_codes and all(code == aiodns.error.ARES_ENOTFOUND for code in dns_error_codes):
            rcode = 'NXDOMAIN'
        elif dns_error_codes and all(
            code in {aiodns.error.ARES_ENOTFOUND, aiodns.error.ARES_ENODATA} for code in dns_error_codes
        ):
            rcode = 'NODATA'
        else:
            rcode = 'ERROR'
        return DNSResponse(
            ipv4=tuple(ipv4),
            ipv6=tuple(ipv6),
            cnames=tuple(cnames),
            rcode=rcode,
            ttl=min(ttls, default=None),
            cname_chain=tuple(cnames),
            error='; '.join(errors) or None,
        )

    async def close(self) -> None:
        await self._resolver.close()


class LegacyHostnameSearch(Protocol):
    async def process(self, proxy: bool = False) -> None: ...

    async def get_hostnames(self) -> Sequence[str]: ...


@dataclass(frozen=True)
class LegacyHostnameSource:
    name: str
    family: str
    search: LegacyHostnameSearch
    proxy: bool = False

    async def collect(self, _target: str) -> tuple[SourceFinding, ...]:
        await self.search.process(self.proxy)
        return tuple(SourceFinding(hostname) for hostname in await self.search.get_hostnames())


@dataclass(frozen=True)
class DiscoveryObservation:
    run_id: str
    target: str
    value: str
    source: str
    source_family: str
    derivation: Derivation
    collected_at: datetime
    scope_class: ScopeClass

    def to_dict(self) -> dict[str, str]:
        return {
            'run_id': self.run_id,
            'target': self.target,
            'value': self.value,
            'source': self.source,
            'source_family': self.source_family,
            'derivation': self.derivation,
            'collected_at': self.collected_at.isoformat(),
            'scope_class': self.scope_class,
        }


@dataclass(frozen=True)
class DNSValidationObservation:
    run_id: str
    candidate: str
    query_name: str
    resolver: str
    queried_at: datetime
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    cnames: tuple[str, ...]
    rcode: str
    ttl: int | None
    cname_chain: tuple[str, ...]
    latency_ms: float
    error: str | None
    is_wildcard_control: bool = False
    wildcard_depth: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            'run_id': self.run_id,
            'candidate': self.candidate,
            'query_name': self.query_name,
            'resolver': self.resolver,
            'queried_at': self.queried_at.isoformat(),
            'ipv4': list(self.ipv4),
            'ipv6': list(self.ipv6),
            'cnames': list(self.cnames),
            'rcode': self.rcode,
            'ttl': self.ttl,
            'cname_chain': list(self.cname_chain),
            'latency_ms': self.latency_ms,
            'error': self.error,
            'is_wildcard_control': self.is_wildcard_control,
            'wildcard_depth': self.wildcard_depth,
        }


@dataclass(frozen=True)
class SourceExecution:
    run_id: str
    source: str
    source_family: str
    status: SourceStatus
    duration_ms: float
    result_count: int
    observation_count: int
    entity_count: int
    error_type: str | None = None

    def to_dict(self) -> dict[str, str | float | int | None]:
        return {
            'run_id': self.run_id,
            'source': self.source,
            'source_family': self.source_family,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'observation_count': self.observation_count,
            'entity_count': self.entity_count,
            'error_type': self.error_type,
        }


@dataclass(frozen=True)
class MergedEntity:
    value: str
    observations: tuple[DiscoveryObservation, ...]
    addressability: Addressability = Addressability.UNVERIFIED
    dns_validations: tuple[DNSValidationObservation, ...] = ()

    @property
    def scope_classes(self) -> tuple[ScopeClass, ...]:
        return tuple(dict.fromkeys(observation.scope_class for observation in self.observations))

    @property
    def independent_corroboration_count(self) -> int:
        return len({observation.source_family for observation in self.observations})

    def to_dict(self) -> dict[str, object]:
        return {
            'value': self.value,
            'addressability': self.addressability,
            'scope_classes': list(self.scope_classes),
            'independent_corroboration_count': self.independent_corroboration_count,
            'observations': [observation.to_dict() for observation in self.observations],
            'dns_validations': [observation.to_dict() for observation in self.dns_validations],
        }


@dataclass(frozen=True)
class RunResult:
    run_id: str
    target: str
    started_at: datetime
    completed_at: datetime
    source_executions: tuple[SourceExecution, ...]
    observations: tuple[DiscoveryObservation, ...]
    dns_validations: tuple[DNSValidationObservation, ...]
    entities: tuple[MergedEntity, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            'run_id': self.run_id,
            'target': self.target,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat(),
            'source_executions': [execution.to_dict() for execution in self.source_executions],
            'observations': [observation.to_dict() for observation in self.observations],
            'dns_validations': [observation.to_dict() for observation in self.dns_validations],
            'entities': [entity.to_dict() for entity in self.entities],
        }


class SQLiteRunStore:
    def __init__(self, database: str | Path | None = None) -> None:
        self.database = Path(database) if database is not None else Path('~/.local/share/theHarvester/stash.sqlite').expanduser()

    async def save(self, result: RunResult) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_runs (
                    run_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                )
                """
            )
            await database.execute(
                'INSERT INTO evidence_runs (run_id, target, completed_at, evidence_json) VALUES (?, ?, ?, ?)',
                (result.run_id, result.target, result.completed_at.isoformat(), json.dumps(result.to_dict())),
            )
            await database.commit()

    async def load(self, run_id: str) -> dict[str, object] | None:
        async with aiosqlite.connect(self.database) as database:
            cursor = await database.execute('SELECT evidence_json FROM evidence_runs WHERE run_id = ?', (run_id,))
            row = await cursor.fetchone()
        return json.loads(row[0]) if row is not None else None


def _normalize_hostname(value: str) -> str:
    hostname = value.strip().rstrip('.').lower()
    if not hostname:
        raise ValueError('hostname cannot be empty')
    return hostname.encode('idna').decode('ascii')


def _classify_scope(target: str, value: str, derivation: Derivation) -> ScopeClass:
    if value == target or value.endswith(f'.{target}'):
        return ScopeClass.IN_SCOPE
    if derivation is Derivation.EXTERNAL_RELATIONSHIP:
        return ScopeClass.EXTERNAL_RELATIONSHIP
    return ScopeClass.SCOPE_EXTENSION


def _merge_observations(observations: Sequence[DiscoveryObservation]) -> tuple[MergedEntity, ...]:
    grouped: dict[str, list[DiscoveryObservation]] = {}
    for observation in observations:
        grouped.setdefault(observation.value, []).append(observation)
    return tuple(MergedEntity(value, tuple(supporting)) for value, supporting in grouped.items())


# Initial DNS policy. Keep these together so consented benchmarks can tune them later.
_RESOLVER_VANTAGE_COUNT = 3
_RESOLVER_QUORUM = 2
_WILDCARD_PROBES_PER_DEPTH = 3
_MAX_CNAME_DEPTH = 16


def _normalize_dns_response(response: DNSResponse) -> DNSResponse:
    return DNSResponse(
        ipv4=tuple(sorted({str(ipaddress.IPv4Address(value)) for value in response.ipv4})),
        ipv6=tuple(sorted({str(ipaddress.IPv6Address(value)) for value in response.ipv6})),
        cnames=tuple(sorted({_normalize_hostname(value) for value in response.cnames})),
        rcode=response.rcode.upper(),
        ttl=response.ttl,
        cname_chain=tuple(_normalize_hostname(value) for value in response.cname_chain),
        error=response.error,
    )


async def _query_dns(
    run_id: str,
    candidate: str,
    query_name: str,
    resolver: ResolverVantage,
    *,
    wildcard_depth: str | None = None,
) -> DNSValidationObservation:
    queried_at = datetime.now(UTC)
    started = time.perf_counter()
    try:
        response = _normalize_dns_response(await resolver.query(query_name))
    except asyncio.CancelledError:
        raise
    except Exception as error:
        response = DNSResponse(rcode='ERROR', error=f'{type(error).__name__}: {error}')
    return DNSValidationObservation(
        run_id=run_id,
        candidate=candidate,
        query_name=query_name,
        resolver=resolver.name,
        queried_at=queried_at,
        ipv4=response.ipv4,
        ipv6=response.ipv6,
        cnames=response.cnames,
        rcode=response.rcode,
        ttl=response.ttl,
        cname_chain=response.cname_chain,
        latency_ms=(time.perf_counter() - started) * 1000,
        error=response.error,
        is_wildcard_control=wildcard_depth is not None,
        wildcard_depth=wildcard_depth,
    )


def _wildcard_depths(target: str, candidate: str) -> tuple[str, ...]:
    target_labels = target.split('.')
    candidate_labels = candidate.split('.')
    extra_label_count = len(candidate_labels) - len(target_labels)
    return (target, *('.'.join(candidate_labels[index:]) for index in range(extra_label_count - 1, 0, -1)))


def _has_dns_evidence(observation: DNSValidationObservation) -> bool:
    return bool(observation.ipv4 or observation.ipv6 or observation.cnames or observation.cname_chain)


def _classify_addressability(
    candidate_observations: Sequence[DNSValidationObservation],
    controls: Sequence[DNSValidationObservation],
) -> Addressability:
    closest_depth = max(
        (control.wildcard_depth for control in controls if control.wildcard_depth is not None),
        key=lambda depth: depth.count('.'),
    )
    closest_controls = tuple(control for control in controls if control.wildcard_depth == closest_depth)
    if any(map(_has_dns_evidence, candidate_observations)) and any(map(_has_dns_evidence, closest_controls)):
        return Addressability.WILDCARD_UNCERTAIN
    determinate_negative = [
        observation
        for observation in candidate_observations
        if not observation.ipv4
        and not observation.ipv6
        and observation.error is None
        and observation.rcode in {'NOERROR', 'NXDOMAIN', 'NODATA'}
    ]
    addressable_count = sum(bool(observation.ipv4 or observation.ipv6) for observation in candidate_observations)
    not_addressable_count = len(determinate_negative)
    if addressable_count >= _RESOLVER_QUORUM:
        return Addressability.CURRENT
    if not_addressable_count >= _RESOLVER_QUORUM:
        return Addressability.NOT_CURRENT
    return Addressability.RESOLVER_DISPUTED


async def _validate_entities(
    run_id: str,
    target: str,
    entities: Sequence[MergedEntity],
    resolvers: Sequence[ResolverVantage],
) -> tuple[tuple[DNSValidationObservation, ...], tuple[MergedEntity, ...]]:
    validations: list[DNSValidationObservation] = []
    validated_entities: list[MergedEntity] = []
    for entity in entities:
        if ScopeClass.IN_SCOPE not in entity.scope_classes:
            validated_entities.append(entity)
            continue
        candidate_observations = tuple(
            await asyncio.gather(*(_query_dns(run_id, entity.value, entity.value, resolver) for resolver in resolvers))
        )
        control_queries = tuple(
            (f'th-{uuid4().hex}.{depth}', depth)
            for depth in _wildcard_depths(target, entity.value)
            for _ in range(_WILDCARD_PROBES_PER_DEPTH)
        )
        controls = tuple(
            await asyncio.gather(
                *(
                    _query_dns(
                        run_id,
                        entity.value,
                        query_name,
                        resolver,
                        wildcard_depth=depth,
                    )
                    for query_name, depth in control_queries
                    for resolver in resolvers
                )
            )
        )
        entity_validations = candidate_observations + controls
        validations.extend(entity_validations)
        validated_entities.append(
            replace(
                entity,
                addressability=_classify_addressability(candidate_observations, controls),
                dns_validations=entity_validations,
            )
        )
    return tuple(validations), tuple(validated_entities)


async def execute_run(
    target: str,
    source: PassiveSource,
    *,
    resolver_vantages: Sequence[ResolverVantage] | None = None,
    store: SQLiteRunStore | None = None,
) -> RunResult:
    if resolver_vantages is not None and (
        len(resolver_vantages) != _RESOLVER_VANTAGE_COUNT
        or len({resolver.name for resolver in resolver_vantages}) != _RESOLVER_VANTAGE_COUNT
    ):
        raise ValueError('DNS validation requires exactly three distinct resolver vantages')
    normalized_target = _normalize_hostname(target)
    run_id = str(uuid4())
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    observations: tuple[DiscoveryObservation, ...] = ()
    status = SourceStatus.FAILED
    result_count = 0
    error_type: str | None = None

    try:
        findings = tuple(await source.collect(normalized_target))
        result_count = len(findings)
        collected_at = datetime.now(UTC)
        observations = tuple(
            DiscoveryObservation(
                run_id=run_id,
                target=normalized_target,
                value=(value := _normalize_hostname(finding.value)),
                source=source.name,
                source_family=source.family,
                derivation=finding.derivation,
                collected_at=collected_at,
                scope_class=_classify_scope(normalized_target, value, finding.derivation),
            )
            for finding in findings
        )
        status = SourceStatus.SUCCEEDED if observations else SourceStatus.EMPTY
    except SourceRateLimitedError:
        status = SourceStatus.RATE_LIMITED
    except SourceSkippedError:
        status = SourceStatus.SKIPPED
    except Exception as error:
        error_type = type(error).__name__

    entities = _merge_observations(observations)
    dns_validations: tuple[DNSValidationObservation, ...] = ()
    if resolver_vantages is not None:
        dns_validations, entities = await _validate_entities(run_id, normalized_target, entities, resolver_vantages)
    execution = SourceExecution(
        run_id=run_id,
        source=source.name,
        source_family=source.family,
        status=status,
        duration_ms=(time.perf_counter() - started) * 1000,
        result_count=result_count,
        observation_count=len(observations),
        entity_count=len(entities),
        error_type=error_type,
    )
    result = RunResult(
        run_id=run_id,
        target=normalized_target,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        source_executions=(execution,),
        observations=observations,
        dns_validations=dns_validations,
        entities=entities,
    )
    await (store or SQLiteRunStore()).save(result)
    return result


def legacy_hostnames(result: RunResult) -> list[str]:
    """Return the host list consumed by the existing CLI, REST, file, and stash paths."""
    return sorted(
        entity.value
        for entity in result.entities
        if ScopeClass.IN_SCOPE in entity.scope_classes
        and (entity.addressability is Addressability.CURRENT or not result.dns_validations)
    )

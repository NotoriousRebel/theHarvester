from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

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
        }


@dataclass(frozen=True)
class RunResult:
    run_id: str
    target: str
    started_at: datetime
    completed_at: datetime
    source_executions: tuple[SourceExecution, ...]
    observations: tuple[DiscoveryObservation, ...]
    entities: tuple[MergedEntity, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            'run_id': self.run_id,
            'target': self.target,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat(),
            'source_executions': [execution.to_dict() for execution in self.source_executions],
            'observations': [observation.to_dict() for observation in self.observations],
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


async def execute_run(
    target: str,
    source: PassiveSource,
    *,
    store: SQLiteRunStore | None = None,
) -> RunResult:
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
        entities=entities,
    )
    await (store or SQLiteRunStore()).save(result)
    return result


def legacy_hostnames(result: RunResult) -> list[str]:
    """Return the host list consumed by the existing CLI, REST, file, and stash paths."""
    return sorted(entity.value for entity in result.entities if ScopeClass.IN_SCOPE in entity.scope_classes)

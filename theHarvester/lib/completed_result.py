import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Self, get_args
from uuid import UUID, uuid4

ResultKind = Literal[
    'analytics',
    'api-endpoint',
    'asn',
    'breach',
    'cms',
    'dns-recursive-classification',
    'dns-recursive-finding',
    'dns-recursive-summary',
    'email',
    'framework',
    'hostname',
    'infostealer',
    'interesting-url',
    'ip-address',
    'language',
    'linkedin-link',
    'linkedin-person',
    'person',
    'server',
    'screenshot',
    'shodan',
    'takeover',
    'twitter-person',
    'url',
    'vhost',
]
ExecutionStatus = Literal['succeeded', 'empty', 'partial', 'failed', 'rate-limited', 'skipped']

SCHEMA_VERSION = 'theharvester-results-v1'
RESULT_KINDS: frozenset[str] = frozenset(get_args(ResultKind))
EXECUTION_STATUSES: frozenset[str] = frozenset(get_args(ExecutionStatus))


def _isoformat_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')


@dataclass(frozen=True, order=True, slots=True)
class ResultObservation:
    source: str
    kind: ResultKind
    value: str

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError('observation source must not be empty')
        if self.kind not in RESULT_KINDS:
            raise ValueError(f'unknown observation kind: {self.kind}')
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError('observation value must be a non-empty string')


@dataclass(frozen=True, order=True, slots=True)
class ActionObservation:
    action: str
    kind: ResultKind
    value: str

    def __post_init__(self) -> None:
        if not self.action.strip():
            raise ValueError('action observation must name an action')
        if self.kind not in RESULT_KINDS:
            raise ValueError(f'unknown action observation kind: {self.kind}')
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError('action observation value must be a non-empty string')


def _validate_execution(name: str, status: ExecutionStatus, duration_ms: float, result_count: int) -> None:
    if not name.strip():
        raise ValueError('execution name must not be empty')
    if status not in EXECUTION_STATUSES:
        raise ValueError(f'unknown execution status: {status}')
    if duration_ms < 0 or result_count < 0:
        raise ValueError('execution duration and result count must not be negative')


@dataclass(frozen=True, slots=True)
class SourceExecution:
    source: str
    status: ExecutionStatus
    duration_ms: float
    result_count: int
    error_type: str | None = None
    stop_reason: str | None = None

    def __post_init__(self) -> None:
        _validate_execution(self.source, self.status, self.duration_ms, self.result_count)

    def to_dict(self) -> dict[str, str | float | int | None]:
        return {
            'source': self.source,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'error_type': self.error_type,
            'stop_reason': self.stop_reason,
        }


@dataclass(frozen=True, slots=True)
class ActionExecution:
    action: str
    status: ExecutionStatus
    duration_ms: float
    result_count: int
    error_type: str | None = None
    stop_reason: str | None = None

    def __post_init__(self) -> None:
        _validate_execution(self.action, self.status, self.duration_ms, self.result_count)

    def to_dict(self) -> dict[str, str | float | int | None]:
        return {
            'action': self.action,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'error_type': self.error_type,
            'stop_reason': self.stop_reason,
        }


@dataclass(frozen=True, order=True, slots=True)
class ArtifactReference:
    action: str
    result_kind: ResultKind
    result_value: str
    path: str
    media_type: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if not self.action.strip() or not self.path.strip() or not self.media_type.strip():
            raise ValueError('artifact action, path, and media type must not be empty')
        if self.result_kind not in RESULT_KINDS or not self.result_value.strip():
            raise ValueError('artifact must reference a known non-empty result')
        if self.size_bytes < 0:
            raise ValueError('artifact size must not be negative')
        if len(self.sha256) != 64 or any(character not in '0123456789abcdef' for character in self.sha256):
            raise ValueError('artifact sha256 must be 64 lowercase hexadecimal characters')

    def to_dict(self) -> dict[str, str | int]:
        return {
            'action': self.action,
            'result_kind': self.result_kind,
            'result_value': self.result_value,
            'path': self.path,
            'media_type': self.media_type,
            'size_bytes': self.size_bytes,
            'sha256': self.sha256,
        }


@dataclass(frozen=True, slots=True)
class SourceYield:
    source: str
    observed_result_count: int
    unique_result_count: int
    shared_result_count: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            'source': self.source,
            'observed_result_count': self.observed_result_count,
            'unique_result_count': self.unique_result_count,
            'shared_result_count': self.shared_result_count,
        }


@dataclass(frozen=True, slots=True)
class ActionYield:
    action: str
    observed_result_count: int
    unique_result_count: int
    shared_result_count: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            'action': self.action,
            'observed_result_count': self.observed_result_count,
            'unique_result_count': self.unique_result_count,
            'shared_result_count': self.shared_result_count,
        }


@dataclass(frozen=True, slots=True)
class CompletedResult:
    run_id: UUID
    target: str
    started_at: datetime
    completed_at: datetime
    results: tuple[tuple[ResultKind, str], ...]
    source_executions: tuple[SourceExecution, ...] = ()
    observations: tuple[ResultObservation, ...] = ()
    action_executions: tuple[ActionExecution, ...] = ()
    action_observations: tuple[ActionObservation, ...] = ()
    artifacts: tuple[ArtifactReference, ...] = ()

    def __post_init__(self) -> None:
        if not self.target.strip():
            raise ValueError('target must not be empty')
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise ValueError('started_at must be timezone-aware')
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError('completed_at must be timezone-aware')
        if self.completed_at < self.started_at:
            raise ValueError('completed_at must not be earlier than started_at')
        if not isinstance(self.run_id, UUID):
            raise ValueError('run_id must be a UUID')
        if any(kind not in RESULT_KINDS or not isinstance(value, str) or not value.strip() for kind, value in self.results):
            raise ValueError('results must contain known kinds and non-empty string values')
        if self.results != tuple(sorted(set(self.results))):
            raise ValueError('results must be deduplicated and sorted')
        if self.observations != tuple(sorted(set(self.observations))):
            raise ValueError('observations must be deduplicated and sorted')
        if any((observation.kind, observation.value) not in self.results for observation in self.observations):
            raise ValueError('every observation must reference a completed result')
        if self.action_observations != tuple(sorted(set(self.action_observations))):
            raise ValueError('action observations must be deduplicated and sorted')
        if any((observation.kind, observation.value) not in self.results for observation in self.action_observations):
            raise ValueError('every action observation must reference a completed result')
        if self.artifacts != tuple(sorted(set(self.artifacts))):
            raise ValueError('artifacts must be deduplicated and sorted')
        action_results = {(observation.action, observation.kind, observation.value) for observation in self.action_observations}
        if any(
            (artifact.action, artifact.result_kind, artifact.result_value) not in action_results for artifact in self.artifacts
        ):
            raise ValueError('every artifact must reference an action observation')

    @classmethod
    def finish(
        cls,
        *,
        run_id: UUID | None = None,
        target: str,
        started_at: datetime,
        completed_at: datetime,
        groups: Mapping[ResultKind, Iterable[str]],
        source_executions: Iterable[SourceExecution] = (),
        observations: Iterable[ResultObservation] = (),
        action_executions: Iterable[ActionExecution] = (),
        action_observations: Iterable[ActionObservation] = (),
        artifacts: Iterable[ArtifactReference] = (),
    ) -> Self:
        results: set[tuple[ResultKind, str]] = set()
        for kind, values in groups.items():
            if kind not in RESULT_KINDS:
                raise ValueError(f'unknown result kind: {kind}')
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError('results must contain non-empty string values')
                results.add((kind, value.strip()))
        return cls(
            run_id=run_id or uuid4(),
            target=target.strip(),
            started_at=started_at,
            completed_at=completed_at,
            results=tuple(sorted(results)),
            source_executions=tuple(source_executions),
            observations=tuple(sorted(set(observations))),
            action_executions=tuple(action_executions),
            action_observations=tuple(sorted(set(action_observations))),
            artifacts=tuple(sorted(set(artifacts))),
        )

    def evidence_dict(self) -> dict[str, object]:
        incomplete = {'partial', 'failed', 'rate-limited', 'skipped'}
        execution_statuses = [execution.status for execution in self.source_executions]
        execution_statuses.extend(execution.status for execution in self.action_executions)
        status = 'complete'
        if execution_statuses and all(execution_status == 'failed' for execution_status in execution_statuses):
            status = 'failed'
        elif any(execution_status in incomplete for execution_status in execution_statuses):
            status = 'partial'
        return {
            'run_id': str(self.run_id),
            'target': self.target,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat(),
            'status': status,
            'results': self._result_records(),
            'source_executions': [execution.to_dict() for execution in self.source_executions],
            'action_executions': [execution.to_dict() for execution in self.action_executions],
            'artifacts': [artifact.to_dict() for artifact in self.artifacts],
        }

    def jsonl(self) -> str:
        counts = Counter(kind for kind, _value in self.results)
        records = [
            {
                'completed_at': _isoformat_utc(self.completed_at),
                'counts': dict(sorted(counts.items())),
                'result_count': len(self.results),
                'run_id': str(self.run_id),
                'schema_version': SCHEMA_VERSION,
                'started_at': _isoformat_utc(self.started_at),
                'target': self.target,
                'type': 'summary',
                'source_executions': [execution.to_dict() for execution in self.source_executions],
                'action_executions': [execution.to_dict() for execution in self.action_executions],
                'artifacts': [artifact.to_dict() for artifact in self.artifacts],
            },
            *self._result_records(),
        ]
        return ''.join(json.dumps(record, ensure_ascii=False, separators=(',', ':'), sort_keys=True) + '\n' for record in records)

    def _result_records(self) -> list[dict[str, object]]:
        sources_by_result: dict[tuple[ResultKind, str], list[str]] = {}
        for observation in self.observations:
            sources_by_result.setdefault((observation.kind, observation.value), []).append(observation.source)
        actions_by_result: dict[tuple[ResultKind, str], list[str]] = {}
        for action_observation in self.action_observations:
            actions_by_result.setdefault((action_observation.kind, action_observation.value), []).append(
                action_observation.action
            )
        return [
            {
                'type': kind,
                'value': value,
                'sources': sources_by_result.get((kind, value), []),
                'actions': actions_by_result.get((kind, value), []),
            }
            for kind, value in self.results
        ]

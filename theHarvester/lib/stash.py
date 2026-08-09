import datetime
import logging
import os
from collections import Counter
from collections.abc import Iterable
from typing import cast
from uuid import UUID

from sqlalchemy import func, select

from theHarvester.lib.completed_result import (
    ActionExecution,
    ActionObservation,
    ActionYield,
    ArtifactReference,
    CompletedResult,
    ExecutionStatus,
    ResultKind,
    ResultObservation,
    SourceExecution,
    SourceYield,
)
from theHarvester.lib.database import (
    ActionExecutionRecord,
    ActionObservationRecord,
    CompletedResultItemRecord,
    CompletedRunRecord,
    DiscoveryObservationRecord,
    RunArtifactRecord,
    SourceExecutionRecord,
    initialize_stash_schema,
    sqlite_session,
)

logger = logging.getLogger(__name__)


db_path = os.path.expanduser('~/.local/share/theHarvester')

if not os.path.isdir(db_path):
    os.makedirs(db_path)


class StashManager:
    def __init__(self) -> None:
        self.db = os.path.join(db_path, 'stash.sqlite')

    async def do_init(self) -> None:
        await initialize_stash_schema(self.db)

    async def store_completed_result(self, result: CompletedResult) -> None:
        run_id = str(result.run_id)
        async with sqlite_session(self.db) as session:
            session.add(
                CompletedRunRecord(
                    run_id=run_id,
                    target=result.target,
                    started_at=result.started_at.isoformat(),
                    completed_at=result.completed_at.isoformat(),
                )
            )
            await session.flush()
            session.add_all(
                CompletedResultItemRecord(run_id=run_id, position=position, kind=kind, value=value)
                for position, (kind, value) in enumerate(result.results)
            )
            session.add_all(
                SourceExecutionRecord(
                    run_id=run_id,
                    position=position,
                    source=execution.source,
                    status=execution.status,
                    duration_ms=execution.duration_ms,
                    result_count=execution.result_count,
                    error_type=execution.error_type,
                    stop_reason=execution.stop_reason,
                )
                for position, execution in enumerate(result.source_executions)
            )
            session.add_all(
                DiscoveryObservationRecord(
                    run_id=run_id,
                    domain=result.target,
                    resource=observation.value,
                    kind=observation.kind,
                    discovered_on=result.completed_at.date(),
                    source=observation.source,
                )
                for observation in result.observations
            )
            session.add_all(
                ActionExecutionRecord(
                    run_id=run_id,
                    position=position,
                    action=execution.action,
                    status=execution.status,
                    duration_ms=execution.duration_ms,
                    result_count=execution.result_count,
                    error_type=execution.error_type,
                    stop_reason=execution.stop_reason,
                )
                for position, execution in enumerate(result.action_executions)
            )
            session.add_all(
                ActionObservationRecord(
                    run_id=run_id,
                    action=observation.action,
                    kind=observation.kind,
                    resource=observation.value,
                )
                for observation in result.action_observations
            )
            session.add_all(
                RunArtifactRecord(
                    run_id=run_id,
                    position=position,
                    action=artifact.action,
                    result_kind=artifact.result_kind,
                    result_value=artifact.result_value,
                    path=artifact.path,
                    media_type=artifact.media_type,
                    size_bytes=artifact.size_bytes,
                    sha256=artifact.sha256,
                )
                for position, artifact in enumerate(result.artifacts)
            )
            await session.commit()

    async def load_completed_result(self, run_id: UUID) -> CompletedResult:
        async with sqlite_session(self.db) as session:
            parent = await session.get(CompletedRunRecord, str(run_id))
            if parent is None:
                raise LookupError(f'completed result not found: {run_id}')
            rows = (
                await session.scalars(
                    select(CompletedResultItemRecord)
                    .where(CompletedResultItemRecord.run_id == str(run_id))
                    .order_by(CompletedResultItemRecord.position)
                )
            ).all()
            execution_rows = (
                await session.scalars(
                    select(SourceExecutionRecord)
                    .where(SourceExecutionRecord.run_id == str(run_id))
                    .order_by(SourceExecutionRecord.position)
                )
            ).all()
            observation_rows = (
                await session.scalars(
                    select(DiscoveryObservationRecord)
                    .where(DiscoveryObservationRecord.run_id == str(run_id))
                    .order_by(
                        DiscoveryObservationRecord.source,
                        DiscoveryObservationRecord.kind,
                        DiscoveryObservationRecord.resource,
                    )
                )
            ).all()
            action_execution_rows = (
                await session.scalars(
                    select(ActionExecutionRecord)
                    .where(ActionExecutionRecord.run_id == str(run_id))
                    .order_by(ActionExecutionRecord.position)
                )
            ).all()
            action_observation_rows = (
                await session.scalars(
                    select(ActionObservationRecord)
                    .where(ActionObservationRecord.run_id == str(run_id))
                    .order_by(ActionObservationRecord.action, ActionObservationRecord.kind, ActionObservationRecord.resource)
                )
            ).all()
            artifact_rows = (
                await session.scalars(
                    select(RunArtifactRecord).where(RunArtifactRecord.run_id == str(run_id)).order_by(RunArtifactRecord.position)
                )
            ).all()
        return CompletedResult(
            run_id=UUID(parent.run_id),
            target=parent.target,
            started_at=datetime.datetime.fromisoformat(parent.started_at),
            completed_at=datetime.datetime.fromisoformat(parent.completed_at),
            results=tuple((cast('ResultKind', row.kind), row.value) for row in rows),
            source_executions=tuple(
                SourceExecution(
                    source=row.source,
                    status=cast('ExecutionStatus', row.status),
                    duration_ms=row.duration_ms,
                    result_count=row.result_count,
                    error_type=row.error_type,
                    stop_reason=row.stop_reason,
                )
                for row in execution_rows
            ),
            observations=tuple(
                ResultObservation(row.source, cast('ResultKind', row.kind), row.resource) for row in observation_rows
            ),
            action_executions=tuple(
                ActionExecution(
                    action=row.action,
                    status=cast('ExecutionStatus', row.status),
                    duration_ms=row.duration_ms,
                    result_count=row.result_count,
                    error_type=row.error_type,
                    stop_reason=row.stop_reason,
                )
                for row in action_execution_rows
            ),
            action_observations=tuple(
                ActionObservation(row.action, cast('ResultKind', row.kind), row.resource) for row in action_observation_rows
            ),
            artifacts=tuple(
                ArtifactReference(
                    action=row.action,
                    result_kind=cast('ResultKind', row.result_kind),
                    result_value=row.result_value,
                    path=row.path,
                    media_type=row.media_type,
                    size_bytes=row.size_bytes,
                    sha256=row.sha256,
                )
                for row in artifact_rows
            ),
        )

    async def list_completed_results(self, *, limit: int = 50) -> list[dict[str, object]]:
        async with sqlite_session(self.db) as session:
            rows = (
                await session.execute(
                    select(CompletedRunRecord, func.count(CompletedResultItemRecord.position))
                    .outerjoin(
                        CompletedResultItemRecord,
                        CompletedResultItemRecord.run_id == CompletedRunRecord.run_id,
                    )
                    .group_by(CompletedRunRecord.run_id)
                    .order_by(
                        func.julianday(CompletedRunRecord.completed_at).desc(),
                        CompletedRunRecord.run_id.desc(),
                    )
                    .limit(limit)
                )
            ).all()
        return [
            {
                'run_id': run.run_id,
                'target': run.target,
                'started_at': run.started_at,
                'completed_at': run.completed_at,
                'result_count': result_count,
            }
            for run, result_count in rows
        ]

    async def source_yields(self, run_id: UUID) -> list[SourceYield]:
        async with sqlite_session(self.db) as session:
            rows = (
                await session.execute(
                    select(
                        DiscoveryObservationRecord.source,
                        DiscoveryObservationRecord.kind,
                        DiscoveryObservationRecord.resource,
                    ).where(DiscoveryObservationRecord.run_id == str(run_id))
                )
            ).all()
            executed_sources = set(
                await session.scalars(select(SourceExecutionRecord.source).where(SourceExecutionRecord.run_id == str(run_id)))
            )
        observed_counts, unique_counts, shared_counts = self._yield_counts((row[0], row[1], row[2]) for row in rows)
        return [
            SourceYield(
                source=source,
                observed_result_count=observed_counts[source],
                unique_result_count=unique_counts[source],
                shared_result_count=shared_counts[source],
            )
            for source in sorted(executed_sources | observed_counts.keys())
        ]

    async def action_yields(self, run_id: UUID) -> list[ActionYield]:
        async with sqlite_session(self.db) as session:
            rows = (
                await session.execute(
                    select(
                        ActionObservationRecord.action,
                        ActionObservationRecord.kind,
                        ActionObservationRecord.resource,
                    ).where(ActionObservationRecord.run_id == str(run_id))
                )
            ).all()
            executed_actions = set(
                await session.scalars(select(ActionExecutionRecord.action).where(ActionExecutionRecord.run_id == str(run_id)))
            )
        observed_counts, unique_counts, shared_counts = self._yield_counts((row[0], row[1], row[2]) for row in rows)
        return [
            ActionYield(
                action=action,
                observed_result_count=observed_counts[action],
                unique_result_count=unique_counts[action],
                shared_result_count=shared_counts[action],
            )
            for action in sorted(executed_actions | observed_counts.keys())
        ]

    @staticmethod
    def _yield_counts(rows: Iterable[tuple[str, str, str]]) -> tuple[Counter[str], Counter[str], Counter[str]]:
        producers_by_result: dict[tuple[str, str], set[str]] = {}
        for producer, kind, value in rows:
            producers_by_result.setdefault((kind, value), set()).add(producer)
        observed_counts: Counter[str] = Counter()
        unique_counts: Counter[str] = Counter()
        shared_counts: Counter[str] = Counter()
        for producers in producers_by_result.values():
            for producer in producers:
                observed_counts[producer] += 1
                (unique_counts if len(producers) == 1 else shared_counts)[producer] += 1
        return observed_counts, unique_counts, shared_counts

    async def store(self, domain: str, resource: str, res_type: ResultKind, source: str) -> None:
        try:
            async with sqlite_session(self.db) as session:
                session.add(
                    DiscoveryObservationRecord(
                        run_id=None,
                        domain=domain,
                        resource=resource,
                        kind=res_type,
                        discovered_on=datetime.date.today(),
                        source=source,
                    )
                )
                await session.commit()
        except Exception as error:
            logger.info(f'Unexpected error while storing result: {error}')

    async def store_all(self, domain: str, results: Iterable[object], res_type: ResultKind, source: str) -> None:
        try:
            async with sqlite_session(self.db) as session:
                session.add_all(
                    DiscoveryObservationRecord(
                        run_id=None,
                        domain=domain,
                        resource=str(resource),
                        kind=res_type,
                        discovered_on=datetime.date.today(),
                        source=source,
                    )
                    for resource in results
                )
                await session.commit()
        except Exception as error:
            logger.info(f'Unexpected error while storing result: {error}')

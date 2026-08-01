from datetime import UTC, datetime
from sqlite3 import Error, IntegrityError

import pytest

from theHarvester.lib.dns_validation import Addressability, DnsValidationObservation
from theHarvester.lib.run import (
    ActivityClass,
    Derivation,
    DiscoveryObservation,
    ExecutionStatus,
    MergedEntity,
    ResultRecord,
    RunExecution,
    RunResult,
    ScopeClass,
    complete_run,
    start_run,
)
from theHarvester.lib.stash import StashManager


@pytest.mark.asyncio
async def test_stash_round_trips_a_completed_run_without_changing_legacy_results(tmp_path) -> None:
    started_at = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
    collected_at = datetime(2026, 7, 31, 12, 0, 30, tzinfo=UTC)
    completed_at = datetime(2026, 7, 31, 12, 1, tzinfo=UTC)
    observation = DiscoveryObservation('api.example.com', 'crtsh', Derivation.PROVIDER, collected_at, ScopeClass.IN_SCOPE)
    run = complete_run(
        RunResult(
            run_id='run-1',
            target='example.com',
            started_at=started_at,
            completed_at=None,
            executions=(
                RunExecution(
                    'crtsh',
                    ActivityClass.PASSIVE,
                    ExecutionStatus.SUCCEEDED,
                    10,
                    1,
                    observation_count=1,
                    entity_count=1,
                    started_at=started_at,
                    completed_at=collected_at,
                ),
                RunExecution(
                    'action:shodan',
                    ActivityClass.DIRECT,
                    ExecutionStatus.FAILED,
                    20,
                    0,
                    error_type='TimeoutError',
                ),
            ),
            observations=(observation,),
            entities=(MergedEntity('api.example.com', (observation,), Addressability.CURRENT),),
            dns_validations=(
                DnsValidationObservation(
                    run_id='run-1',
                    candidate='api.example.com',
                    query_name='api.example.com',
                    resolver='192.0.2.53',
                    queried_at=collected_at,
                    ipv4=('192.0.2.10',),
                    ipv6=(),
                    cnames=(),
                    rcode='NOERROR',
                    ttl=300,
                    cname_chain=(),
                    latency_ms=2.5,
                    error=None,
                ),
                DnsValidationObservation(
                    run_id='run-1',
                    candidate=None,
                    query_name='th-random.example.com',
                    resolver='192.0.2.53',
                    queried_at=collected_at,
                    ipv4=(),
                    ipv6=(),
                    cnames=(),
                    rcode='NXDOMAIN',
                    ttl=None,
                    cname_chain=(),
                    latency_ms=2.0,
                    error=None,
                    is_wildcard_control=True,
                    wildcard_depth='example.com',
                ),
            ),
        ),
        results=(
            ResultRecord('subdomain', 'api.example.com', ('crtsh',)),
            ResultRecord('ip', '192.0.2.10', ('dns-resolution',)),
        ),
        completed_at=completed_at,
    )
    manager = StashManager()
    manager.db = str(tmp_path / 'stash.sqlite')
    await manager.do_init()
    await manager.store('example.com', 'legacy.example.com', 'host', 'fixture')

    await manager.store_run(run)

    with pytest.raises(IntegrityError):
        await manager.store_run(run)

    loaded = await manager.load_run('run-1')
    assert loaded is not None
    assert loaded.to_dict() == run.to_dict()
    assert loaded.status == 'partial'
    assert [tuple(row) for row in (await manager.getlatestscanresults('example.com') or [])] == [
        (str(datetime.now().date()), 'example.com', 'fixture', 'host', 'legacy.example.com')
    ]


@pytest.mark.asyncio
async def test_stash_rolls_back_the_completed_run_when_a_legacy_row_fails(tmp_path) -> None:
    manager = StashManager()
    manager.db = str(tmp_path / 'stash.sqlite')
    await manager.do_init()
    run = complete_run(
        start_run('example.com'),
        completed_at=datetime(2026, 7, 31, 12, 1, tzinfo=UTC),
    )

    with pytest.raises(Error):
        await manager.store_run(
            run,
            legacy_results=(('example.com', (object(),), 'host', 'fixture'),),
        )

    assert await manager.load_run(run.run_id) is None


@pytest.mark.asyncio
async def test_stash_lists_the_most_recent_completed_runs(tmp_path) -> None:
    manager = StashManager()
    manager.db = str(tmp_path / 'stash.sqlite')
    await manager.do_init()
    older = complete_run(
        start_run('older.example'),
        completed_at=datetime(2026, 7, 31, 12, 0, tzinfo=UTC),
    )
    newer = complete_run(
        start_run('newer.example'),
        completed_at=datetime(2026, 7, 31, 13, 0, tzinfo=UTC),
    )
    await manager.store_run(older)
    await manager.store_run(newer)

    assert await manager.list_runs(limit=1) == [
        {
            'run_id': newer.run_id,
            'target': 'newer.example',
            'started_at': newer.started_at.isoformat(),
            'completed_at': '2026-07-31T13:00:00+00:00',
            'status': 'complete',
        }
    ]

from datetime import UTC, datetime

import pytest

from theHarvester.lib.dns_validation import DnsValidationObservation
from theHarvester.lib.run import (
    ActivityClass,
    Derivation,
    DiscoveryObservation,
    ExecutionStatus,
    MergedEntity,
    ResultRecord,
    RunExecution,
    RunResult,
    RunStatus,
    ScopeClass,
    add_run_evidence,
    complete_run,
    start_run,
)


def test_completed_run_serializes_partial_result_after_every_execution() -> None:
    started_at = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
    completed_at = datetime(2026, 7, 31, 12, 1, tzinfo=UTC)
    run = RunResult(
        run_id='run-1',
        target='example.com',
        started_at=started_at,
        completed_at=None,
        executions=(
            RunExecution(
                name='crtsh',
                activity=ActivityClass.PASSIVE,
                status=ExecutionStatus.SUCCEEDED,
                duration_ms=10,
                result_count=1,
            ),
            RunExecution(
                name='action:shodan',
                activity=ActivityClass.DIRECT,
                status=ExecutionStatus.FAILED,
                duration_ms=20,
                result_count=0,
                error_type='TimeoutError',
            ),
        ),
        observations=(),
        entities=(),
    )

    completed = complete_run(
        run,
        results=(
            ResultRecord('subdomain', 'api.example.com'),
            ResultRecord('asn', 'AS64500', ('crtsh',)),
        ),
        completed_at=completed_at,
    )

    assert completed.status is RunStatus.PARTIAL
    assert completed.to_dict()['completed_at'] == '2026-07-31T12:01:00+00:00'
    assert completed.to_dict()['results'] == [
        {'type': 'subdomain', 'value': 'api.example.com'},
        {'type': 'asn', 'value': 'AS64500', 'sources': ['crtsh']},
    ]
    assert completed.to_dict()['executions'][1] == {
        'name': 'action:shodan',
        'activity': 'P2 direct interaction',
        'status': 'failed',
        'duration_ms': 20,
        'result_count': 0,
        'observation_count': 0,
        'entity_count': 0,
        'error_type': 'TimeoutError',
        'started_at': None,
        'completed_at': None,
    }


def test_run_cannot_report_before_completion_or_complete_twice() -> None:
    run = start_run('Example.COM.')

    with pytest.raises(RuntimeError, match='run is not complete'):
        _ = run.status

    completed = complete_run(run, completed_at=datetime(2026, 7, 31, 12, 1, tzinfo=UTC))

    with pytest.raises(RuntimeError, match='run is already complete'):
        complete_run(completed)


def test_run_is_failed_when_every_execution_failed_without_results() -> None:
    run = start_run('example.com')
    failed = complete_run(
        run,
        executions=(
            RunExecution('crtsh', ActivityClass.PASSIVE, ExecutionStatus.FAILED, 10, 0),
            RunExecution('action:shodan', ActivityClass.DIRECT, ExecutionStatus.FAILED, 20, 0),
        ),
        completed_at=datetime(2026, 7, 31, 12, 1, tzinfo=UTC),
    )

    assert failed.status is RunStatus.FAILED


def test_add_run_evidence_merges_observations_without_completing() -> None:
    run = start_run('example.com')
    observation = DiscoveryObservation(
        value='api.example.com',
        source='crtsh',
        derivation=Derivation.PROVIDER,
        collected_at=datetime(2026, 7, 31, 12, 0, 30, tzinfo=UTC),
        scope_class=ScopeClass.IN_SCOPE,
    )

    updated = add_run_evidence(
        run,
        executions=(RunExecution('crtsh', ActivityClass.PASSIVE, ExecutionStatus.SUCCEEDED, 10, 1),),
        observations=(observation,),
    )

    assert updated.run_id == run.run_id
    assert updated.completed_at is None
    assert updated.observations == (observation,)
    assert updated.entities == (MergedEntity('api.example.com', (observation,)),)


def test_completed_run_serializes_provenance_without_repeated_run_metadata() -> None:
    collected_at = datetime(2026, 7, 31, 12, 0, 30, tzinfo=UTC)
    observation = DiscoveryObservation(
        value='api.example.com',
        source='crtsh',
        derivation=Derivation.PROVIDER,
        collected_at=collected_at,
        scope_class=ScopeClass.IN_SCOPE,
    )
    run = RunResult(
        run_id='run-1',
        target='example.com',
        started_at=datetime(2026, 7, 31, 12, 0, tzinfo=UTC),
        completed_at=None,
        executions=(),
        observations=(observation,),
        entities=(MergedEntity('api.example.com', (observation,)),),
    )

    payload = complete_run(run, completed_at=datetime(2026, 7, 31, 12, 1, tzinfo=UTC)).to_dict()

    assert payload['observations'] == [
        {
            'value': 'api.example.com',
            'source': 'crtsh',
            'derivation': 'provider',
            'collected_at': '2026-07-31T12:00:30+00:00',
            'scope_class': 'in-scope',
        }
    ]
    assert payload['entities'] == [
        {
            'value': 'api.example.com',
            'scope_classes': ['in-scope'],
            'addressability': None,
            'sources': ['crtsh'],
        }
    ]


def test_completed_run_serializes_dns_validation_once_at_run_level() -> None:
    queried_at = datetime(2026, 7, 31, 12, 0, 45, tzinfo=UTC)
    run = RunResult(
        run_id='run-1',
        target='example.com',
        started_at=datetime(2026, 7, 31, 12, 0, tzinfo=UTC),
        completed_at=None,
        executions=(),
        observations=(),
        entities=(),
        dns_validations=(
            DnsValidationObservation(
                run_id='run-1',
                candidate='api.example.com',
                query_name='api.example.com',
                resolver='192.0.2.53',
                queried_at=queried_at,
                ipv4=('192.0.2.10',),
                ipv6=(),
                cnames=(),
                rcode='NOERROR',
                ttl=300,
                cname_chain=(),
                latency_ms=2.5,
                error=None,
            ),
        ),
    )

    payload = complete_run(run, completed_at=datetime(2026, 7, 31, 12, 1, tzinfo=UTC)).to_dict()

    assert payload['dns_validations'] == [
        {
            'candidate': 'api.example.com',
            'query_name': 'api.example.com',
            'resolver': '192.0.2.53',
            'queried_at': '2026-07-31T12:00:45+00:00',
            'ipv4': ['192.0.2.10'],
            'ipv6': [],
            'cnames': [],
            'rcode': 'NOERROR',
            'ttl': 300,
            'cname_chain': [],
            'latency_ms': 2.5,
            'error': None,
            'is_wildcard_control': False,
            'wildcard_depth': None,
        }
    ]


def test_complete_run_merges_result_provenance_by_type_and_value() -> None:
    completed = complete_run(
        start_run('example.com'),
        results=(
            ResultRecord('asn', 'AS64500', ('crtsh',)),
            ResultRecord('asn', 'AS64500', ('censys',)),
        ),
        completed_at=datetime(2026, 7, 31, 12, 1, tzinfo=UTC),
    )

    assert completed.results == (ResultRecord('asn', 'AS64500', ('censys', 'crtsh')),)

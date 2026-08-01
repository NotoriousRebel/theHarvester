import json
from datetime import UTC, datetime
from xml.etree.ElementTree import fromstring

from theHarvester.lib.dns_validation import Addressability
from theHarvester.lib.output import (
    format_run_terminal,
    legacy_json_result,
    legacy_report_hosts,
    run_result_jsonl,
    run_result_xml,
)
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
)

STARTED = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
COMPLETED = datetime(2026, 7, 31, 12, 1, tzinfo=UTC)
SUCCESS = RunExecution('crtsh', ActivityClass.PASSIVE, ExecutionStatus.SUCCEEDED, 10, 1)
FAILED = RunExecution('action:shodan', ActivityClass.DIRECT, ExecutionStatus.FAILED, 20, 0, error_type='TimeoutError')


def _completed(
    *results: ResultRecord,
    executions: tuple[RunExecution, ...] = (SUCCESS,),
    observations: tuple[DiscoveryObservation, ...] = (),
    entities: tuple[MergedEntity, ...] = (),
) -> RunResult:
    return RunResult(
        run_id='run-1',
        target='example.com',
        started_at=STARTED,
        completed_at=COMPLETED,
        executions=executions,
        observations=observations,
        entities=entities,
        results=results,
    )


def test_terminal_output_leads_with_flags_results_and_failed_work() -> None:
    completed = _completed(
        ResultRecord('subdomain', 'api.example.com'),
        ResultRecord('asn', 'AS64500', ('crtsh',)),
        executions=(SUCCESS, FAILED),
    )

    output = format_run_terminal(
        completed,
        configuration=(
            'Command: theHarvester -d example.com -b crtsh -s',
            'Sources: crtsh',
            'DNS resolution: off',
            'Actions: shodan',
            'Activity: P0 passive collection; P2 direct interaction',
        ),
    )

    assert (
        output
        == """[*] Run status: partial
Command: theHarvester -d example.com -b crtsh -s
Target: example.com
Sources: crtsh
DNS resolution: off
Actions: shodan
Activity: P0 passive collection; P2 direct interaction
[*] Subdomains (1)
api.example.com
[*] ASNs (1)
AS64500
[*] Executions
crtsh [P0 passive collection: succeeded; results=1]
action:shodan [P2 direct interaction: failed; results=0; error=TimeoutError]"""
    )


def test_terminal_groups_hostname_evidence_with_status_and_sources() -> None:
    collected_at = datetime(2026, 7, 31, 12, 0, 30, tzinfo=UTC)
    current = DiscoveryObservation('api.example.com', 'crtsh', Derivation.PROVIDER, collected_at, ScopeClass.IN_SCOPE)
    extension = DiscoveryObservation('example.net', 'crtsh', Derivation.PROVIDER, collected_at, ScopeClass.SCOPE_EXTENSION)
    brute = DiscoveryObservation('brute.example.com', 'dns-brute', Derivation.DNS, collected_at, ScopeClass.IN_SCOPE)
    completed = _completed(
        ResultRecord('subdomain', 'api.example.com'),
        ResultRecord('subdomain', 'brute.example.com'),
        executions=(),
        observations=(current, extension, brute),
        entities=(
            MergedEntity('api.example.com', (current,), Addressability.CURRENT),
            MergedEntity('example.net', (extension,)),
            MergedEntity('brute.example.com', (brute,)),
        ),
    )

    output = format_run_terminal(completed)

    assert '[*] Currently addressable subdomains (1)' in output
    assert 'api.example.com [currently-addressable; sources: crtsh]' in output
    assert '[*] Scope-extension candidates (1)' in output
    assert 'example.net [scope-extension; sources: crtsh]' in output
    assert '[*] Secondary subdomain evidence (1)' in output
    assert 'brute.example.com [not-consensus-validated; sources: dns-brute]' in output
    assert 'Additional subdomains' not in output


def test_terminal_says_when_dns_validation_was_not_requested() -> None:
    collected_at = datetime(2026, 7, 31, 12, 0, 30, tzinfo=UTC)
    observation = DiscoveryObservation(
        'api.example.com',
        'crtsh',
        Derivation.PROVIDER,
        collected_at,
        ScopeClass.IN_SCOPE,
    )
    completed = _completed(
        ResultRecord('subdomain', 'api.example.com'),
        observations=(observation,),
        entities=(MergedEntity('api.example.com', (observation,)),),
    )

    terminal = format_run_terminal(completed)

    assert '[*] Subdomains (DNS validation not requested) (1)' in terminal
    assert 'api.example.com [dns-not-requested; sources: crtsh]' in terminal


def test_jsonl_is_a_summary_followed_by_flat_results() -> None:
    completed = _completed(
        ResultRecord('subdomain', 'api.example.com'),
        ResultRecord('asn', 'AS64500', ('crtsh',)),
        executions=(SUCCESS, FAILED),
    )

    records = [json.loads(line) for line in run_result_jsonl(completed).splitlines()]

    assert records == [
        {
            'type': 'summary',
            'schema': 'theharvester-results-v1',
            'target': 'example.com',
            'status': 'partial',
            'counts': {'asn': 1, 'subdomain': 1},
        },
        {'type': 'subdomain', 'value': 'api.example.com'},
        {'type': 'asn', 'value': 'AS64500'},
    ]
    assert all('run_id' not in record and 'source' not in record for record in records)


def test_legacy_json_fields_are_preserved_and_receive_completed_run() -> None:
    completed = _completed(
        ResultRecord('subdomain', 'api.example.com'),
        executions=(SUCCESS, FAILED),
    )
    legacy = {'hosts': ['www.example.com'], 'emails': ['security@example.com']}

    adapted = legacy_json_result(completed, legacy)

    assert legacy == {'hosts': ['www.example.com'], 'emails': ['security@example.com']}
    assert adapted['hosts'] == ['www.example.com']
    assert adapted['emails'] == ['security@example.com']
    assert adapted['run']['status'] == 'partial'


def test_legacy_json_does_not_duplicate_resolved_hosts() -> None:
    completed = _completed(ResultRecord('subdomain', 'api.example.com'))

    adapted = legacy_json_result(completed, {'hosts': ['api.example.com:192.0.2.10']})

    assert adapted['hosts'] == ['api.example.com:192.0.2.10']


def test_legacy_report_keeps_unresolved_hosts_without_duplicating_resolved_hosts() -> None:
    assert legacy_report_hosts(
        ['api.example.com', 'old.example.com'],
        ['api.example.com:192.0.2.10'],
    ) == ['api.example.com:192.0.2.10', 'old.example.com']


def test_completed_run_xml_fragment_keeps_results_and_execution_status() -> None:
    completed = _completed(ResultRecord('subdomain', 'api.example.com'), executions=(SUCCESS, FAILED))

    fragment = fromstring(run_result_xml(completed))

    assert fragment.attrib == {'status': 'partial', 'target': 'example.com'}
    assert [(node.attrib, node.text) for node in fragment.findall('./results/result')] == [
        ({'type': 'subdomain'}, 'api.example.com')
    ]
    assert [node.attrib['status'] for node in fragment.findall('./executions/execution')] == ['succeeded', 'failed']

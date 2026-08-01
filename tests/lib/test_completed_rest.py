import argparse
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from theHarvester.lib.run import ActivityClass, ExecutionStatus, ResultRecord, RunExecution, complete_run, start_run

FAILED_ACTION = RunExecution('action:shodan', ActivityClass.DIRECT, ExecutionStatus.FAILED, 20, 0, error_type='TimeoutError')
SUCCESS_SOURCE = RunExecution('crtsh', ActivityClass.PASSIVE, ExecutionStatus.SUCCEEDED, 10, 1)


@pytest.mark.asyncio
async def test_rest_query_can_include_dns_brute_in_the_completed_response(monkeypatch) -> None:
    import theHarvester.__main__ as main_module

    searched_ips: list[str] = []

    class FakeDnsForce:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        async def run(self):
            return ['brute.example.com:192.0.2.10'], ['brute.example.com'], ['192.0.2.10']

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store_run(self, _run, **_kwargs) -> None:
            return None

    class FakeShodanSearch:
        async def search_ip(self, ip: str):
            searched_ips.append(ip)
            return {ip: {'ports': [443]}}

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(main_module.dnssearch, 'DnsForce', FakeDnsForce)
    monkeypatch.setattr(main_module.shodansearch, 'SearchShodan', FakeShodanSearch)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module.asyncio, 'sleep', no_sleep)

    response = await main_module.start(
        argparse.Namespace(
            api_scan=False,
            dns_brute=True,
            dns_brute_only=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            include_run=True,
            limit=500,
            proxies=False,
            quiet=False,
            screenshot='',
            shodan=True,
            source=None,
            start=0,
            take_over=False,
            wordlist='',
        )
    )

    assert len(response) == 10
    assert response[8] == ['brute.example.com']
    assert response[9].entities[0].value == 'brute.example.com'
    assert response[9].entities[0].observations[0].source == 'dns-brute'
    brute_execution = next(execution for execution in response[9].executions if execution.name == 'action:dns-brute')
    assert (brute_execution.observation_count, brute_execution.entity_count) == (1, 1)
    assert response[9].to_dict()['results'] == [
        {'type': 'subdomain', 'value': 'brute.example.com', 'sources': ['dns-brute']},
        {'type': 'ip', 'value': '192.0.2.10', 'sources': ['dns-brute']},
        {'type': 'shodan', 'value': '["443"]', 'sources': ['shodan']},
    ]
    assert searched_ips == ['192.0.2.10']


def test_rest_query_adds_completed_run_without_changing_legacy_fields(monkeypatch) -> None:
    from theHarvester.lib.api import api

    completed = complete_run(
        start_run('example.com'),
        results=(ResultRecord('subdomain', 'api.example.com'),),
        executions=(SUCCESS_SOURCE, FAILED_ACTION),
        completed_at=datetime(2026, 7, 31, 12, 1, tzinfo=UTC),
    )

    async def start(_args):
        return ([], [], [], [], [], [], [], [], ['api.example.com'], completed)

    monkeypatch.setattr(api.__main__, 'start', start)
    monkeypatch.setattr(api.__main__.Core, 'get_supportedengines', lambda: ['crtsh'])

    response = TestClient(api.app).get('/query?domain=example.com&source=crtsh')

    assert response.status_code == 200
    assert response.json()['hosts'] == ['api.example.com']
    assert response.json()['run']['status'] == 'partial'
    assert response.json()['run']['results'] == [{'type': 'subdomain', 'value': 'api.example.com'}]


def test_dnsbrute_adds_completed_run_without_changing_legacy_results(monkeypatch) -> None:
    from theHarvester.lib.api import api

    completed = complete_run(
        start_run('example.com'),
        results=(ResultRecord('subdomain', 'brute.example.com'),),
        executions=(SUCCESS_SOURCE, FAILED_ACTION),
        completed_at=datetime(2026, 7, 31, 12, 1, tzinfo=UTC),
    )

    async def start(args):
        assert args.dns_brute_only is True
        assert args.include_run is True
        return ['brute.example.com:192.0.2.10'], completed

    monkeypatch.setattr(api.__main__, 'start', start)

    response = TestClient(api.app).get('/dnsbrute?domain=example.com')

    assert response.status_code == 200
    assert response.json()['dns_bruteforce'] == ['brute.example.com:192.0.2.10']
    assert response.json()['run']['status'] == 'partial'
    assert 'run' in api.app.openapi()['components']['schemas']['DnsBruteResponse']['properties']


def test_rest_lists_completed_runs(monkeypatch) -> None:
    from theHarvester.lib import stash
    from theHarvester.lib.api import api

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def list_runs(self, *, limit: int):
            assert limit == 1
            return [
                {
                    'run_id': 'run-1',
                    'target': 'example.com',
                    'started_at': '2026-07-31T12:00:00+00:00',
                    'completed_at': '2026-07-31T12:01:00+00:00',
                    'status': 'complete',
                }
            ]

    monkeypatch.setattr(stash, 'StashManager', FakeStashManager)
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-secret')

    response = TestClient(api.app).get('/runs?limit=1', headers={'X-API-Key': 'test-secret'})

    assert response.status_code == 200
    assert response.json() == [
        {
            'run_id': 'run-1',
            'target': 'example.com',
            'started_at': '2026-07-31T12:00:00+00:00',
            'completed_at': '2026-07-31T12:01:00+00:00',
            'status': 'complete',
        }
    ]


def test_rest_retrieves_one_completed_run_and_reports_missing_ids(monkeypatch) -> None:
    from theHarvester.lib import stash
    from theHarvester.lib.api import api

    completed = complete_run(
        start_run('example.com'),
        results=(ResultRecord('subdomain', 'api.example.com'),),
        completed_at=datetime(2026, 7, 31, 12, 1, tzinfo=UTC),
    )

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def load_run(self, run_id: str):
            return completed if run_id == completed.run_id else None

    monkeypatch.setattr(stash, 'StashManager', FakeStashManager)
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-secret')
    client = TestClient(api.app)

    response = client.get(f'/runs/{completed.run_id}', headers={'X-API-Key': 'test-secret'})
    missing = client.get('/runs/missing', headers={'X-API-Key': 'test-secret'})

    assert response.status_code == 200
    assert response.json()['target'] == 'example.com'
    assert response.json()['results'] == [{'type': 'subdomain', 'value': 'api.example.com'}]
    assert missing.status_code == 404
    assert missing.json() == {'detail': 'Completed run not found'}


def test_run_history_fails_closed_without_the_operator_api_key(monkeypatch) -> None:
    from theHarvester.lib import stash
    from theHarvester.lib.api import api

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def list_runs(self, *, limit: int):
            return []

    monkeypatch.setattr(stash, 'StashManager', FakeStashManager)
    monkeypatch.delenv('THEHARVESTER_API_KEY', raising=False)
    client = TestClient(api.app)

    unconfigured = client.get('/runs')
    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-secret')
    unauthenticated = client.get('/runs')
    authenticated = client.get('/runs', headers={'X-API-Key': 'test-secret'})

    assert unconfigured.status_code == 503
    assert unauthenticated.status_code == 401
    assert authenticated.status_code == 200

from __future__ import annotations

import asyncio
import json
import os
import signal
import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_api_rate_limits():
    from theHarvester.lib.api.rate_limit import limiter

    limiter.reset()
    yield
    limiter.reset()


def test_operator_api_header_authenticates_an_empty_durable_run_history(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')

    with TestClient(api.app) as client:
        locked = client.get('/api/wayfinder/runs')
        unlocked = client.get('/api/wayfinder/runs', headers={'X-API-Key': 'test-key'})

    assert locked.status_code == 401
    assert unlocked.status_code == 200
    assert unlocked.json() == []


def test_operator_app_replaces_legacy_root_cookie(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        client.cookies.set('theharvester-api-key', 'test-key', domain='127.0.0.1', path='/')
        client.get('/')
        runs = client.get('/api/wayfinder/runs')

    assert runs.status_code == 200
    assert runs.json() == []


def test_operator_app_rejects_non_loopback_clients_and_cross_origin_cookie_writes(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')

    with TestClient(api.app) as remote_client:
        remote_page = remote_client.get('/')
    with TestClient(api.app, base_url='http://attacker.example', client=('127.0.0.1', 50000)) as rebound_client:
        rebound_page = rebound_client.get('/')
    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as local_client:
        local_client.get('/')
        cross_origin = local_client.post(
            '/api/wayfinder/runs/not-found/cancel',
            headers={'Origin': 'http://127.0.0.1:9999'},
        )
        same_origin = local_client.post(
            '/api/wayfinder/runs/not-found/cancel',
            headers={'Origin': 'http://127.0.0.1'},
        )
        header_authenticated = local_client.post(
            '/api/wayfinder/runs/not-found/cancel',
            headers={'X-API-Key': 'test-key'},
        )

    assert remote_page.status_code == 403
    assert 'set-cookie' not in remote_page.headers
    assert rebound_page.status_code == 403
    assert 'set-cookie' not in rebound_page.headers
    assert cross_origin.status_code == 403
    assert same_origin.status_code == 404
    assert header_authenticated.status_code == 404


@pytest.mark.skipif(os.name == 'nt', reason='POSIX file modes')
def test_wayfinder_database_is_owner_only(tmp_path) -> None:
    from theHarvester.lib.api import wayfinder

    database = tmp_path / 'private-data' / 'wayfinder.sqlite'
    asyncio.run(wayfinder.WayfinderStore(database).initialize())

    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == 'nt', reason='POSIX file modes')
def test_wayfinder_does_not_change_an_existing_database_parent_mode(tmp_path) -> None:
    from theHarvester.lib.api import wayfinder

    parent = tmp_path / 'shared-data'
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)

    asyncio.run(wayfinder.WayfinderStore(parent / 'wayfinder.sqlite').initialize())

    assert stat.S_IMODE(parent.stat().st_mode) == 0o755
    assert stat.S_IMODE((parent / 'wayfinder.sqlite').stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == 'nt', reason='POSIX file modes')
def test_wayfinder_does_not_chmod_a_parent_created_by_another_process(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import wayfinder

    parent = tmp_path / 'shared-data'
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    real_exists = wayfinder.Path.exists
    monkeypatch.setattr(
        wayfinder.Path,
        'exists',
        lambda path: False if path == parent else real_exists(path),
    )

    asyncio.run(wayfinder.WayfinderStore(parent / 'wayfinder.sqlite').initialize())

    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_run_submission_authenticates_before_parsing_json(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/wayfinder/runs',
            headers={'Content-Type': 'application/json'},
            content='{',
        )

    assert response.status_code == 401
    assert response.json()['detail'] == 'Invalid API key'


def test_run_submission_rejects_when_execution_worker_is_disabled(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/wayfinder/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': 'example.com', 'sources': ['crtsh']},
        )
        history = client.get('/api/wayfinder/runs', headers={'X-API-Key': 'test-key'})

    assert response.status_code == 503
    assert response.json()['detail'] == 'Wayfinder execution worker is disabled'
    assert history.json() == []


def test_run_submission_rejects_an_oversized_json_body(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    body = json.dumps(
        {
            'target': 'example.com',
            'sources': ['crtsh'],
            'padding': 'x' * (64 * 1024),
        }
    )

    with TestClient(api.app) as client:
        response = client.post(
            '/api/wayfinder/runs',
            headers={'X-API-Key': 'test-key', 'Content-Type': 'application/json'},
            content=body,
        )

    assert response.status_code == 413
    assert response.json()['detail'] == 'Run request exceeds the 64 KiB limit'


def test_run_submission_rejects_more_sources_than_the_catalog(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')

    with TestClient(api.app) as client:
        response = client.post(
            '/api/wayfinder/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': 'example.com', 'sources': ['crtsh'] * 56},
        )

    assert response.status_code == 422


def test_operator_can_submit_and_atomically_cancel_a_queued_run(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, wayfinder

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    submitted = asyncio.run(
        wayfinder.WayfinderStore().create(
            wayfinder.RunRequest(
                target='Example.COM.',
                sources=['crtsh'],
                limit=200,
                deadline_seconds=600,
            )
        )
    )
    run_id = submitted['run_id']

    with TestClient(api.app) as client:
        detail = client.get(f'/api/wayfinder/runs/{run_id}', headers=headers)
        cancelled = client.post(f'/api/wayfinder/runs/{run_id}/cancel', headers=headers)
        history = client.get('/api/wayfinder/runs', headers=headers)

    assert submitted['target'] == 'example.com'
    assert submitted['status'] == 'queued'
    assert detail.json()['request']['sources'] == ['crtsh']
    assert cancelled.status_code == 200
    assert cancelled.json()['status'] == 'cancelled'
    assert history.json()[0]['run_id'] == run_id
    assert history.json()[0]['status'] == 'cancelled'


def test_run_submission_expands_the_same_capability_union_as_the_cli(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, wayfinder
    from theHarvester.lib.core import Core

    async def no_op() -> None:
        return None

    async def public_target(_target: str) -> bool:
        return True

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(wayfinder, '_worker_enabled', lambda: True)
    monkeypatch.setattr(wayfinder, '_worker_task', type('RunningTask', (), {'done': lambda self: False})())
    monkeypatch.setattr(wayfinder, '_wake_worker', lambda: None)
    monkeypatch.setattr(wayfinder, 'is_public_target', public_target)

    with TestClient(api.app) as client:
        response = client.post(
            '/api/wayfinder/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': 'example.com', 'sources': ['subdomains', 'ips', 'certspotter']},
        )

    assert response.status_code == 201
    assert response.json()['request']['sources'] == Core.expand_source_selection('subdomains,ips,certspotter')


def test_submission_rejects_unknown_sources_and_private_direct_targets(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app) as client:
        unknown = client.post(
            '/api/wayfinder/runs',
            headers=headers,
            json={'target': 'example.com', 'sources': ['made-up-provider']},
        )
        private = client.post(
            '/api/wayfinder/runs',
            headers=headers,
            json={'target': '127.0.0.1', 'sources': ['crtsh'], 'screenshot': True},
        )
        carrier_nat = client.post(
            '/api/wayfinder/runs',
            headers=headers,
            json={'target': '100.64.0.1', 'sources': ['crtsh'], 'screenshot': True},
        )

    assert unknown.status_code == 422
    assert 'Unsupported sources' in unknown.json()['detail']
    assert private.status_code == 400
    assert private.json()['detail'] == 'P2 direct interaction requires a publicly routable target'
    assert carrier_nat.status_code == 400
    assert carrier_nat.json()['detail'] == 'P2 direct interaction requires a publicly routable target'


def test_public_target_check_fails_closed_when_resolution_is_unavailable(monkeypatch) -> None:
    from theHarvester.lib.api import wayfinder

    class UnavailableResolver:
        async def resolve(self, _target, _port=0):
            raise OSError('resolver unavailable')

        async def close(self):
            return None

    class UnexpectedLoop:
        async def getaddrinfo(self, _target, _port):
            raise AssertionError('Wayfinder should reuse PublicResolver')

    monkeypatch.setattr(wayfinder, 'PublicResolver', UnavailableResolver, raising=False)
    monkeypatch.setattr(wayfinder.asyncio, 'get_running_loop', lambda: UnexpectedLoop())

    assert asyncio.run(wayfinder.is_public_target('unresolved.example')) is False


def test_operator_can_import_json_evidence_and_export_normalized_routes(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    evidence = {
        'run_id': 'evidence-run-1',
        'target': 'example.com',
        'started_at': '2026-08-01T12:00:00+00:00',
        'completed_at': '2026-08-01T12:01:00+00:00',
        'status': 'partial',
        'source_executions': [
            {'source': 'crtsh', 'status': 'succeeded', 'duration_ms': 30, 'result_count': 1},
            {'source': 'urlscan', 'status': 'rate-limited', 'duration_ms': 90, 'result_count': 0},
            {'source': 'criminalip', 'activity': 'P0', 'status': 'empty', 'duration_ms': 12, 'result_count': 0},
        ],
        'entities': [
            {
                'value': 'api.example.com',
                'addressability': 'currently-addressable',
                'scope_classes': ['in-scope'],
                'observations': [{'source': 'crtsh'}],
                'dns_validations': [],
            }
        ],
        'selected_observations': [{'source': 'crtsh', 'kind': 'email', 'value': 'ops@example.com', 'detail': None}],
    }

    with TestClient(api.app) as client:
        imported = client.post(
            '/api/wayfinder/import?filename=example.json',
            headers={**headers, 'Content-Type': 'application/json'},
            content=json.dumps(evidence),
        )
        run_id = imported.json()['run_id']
        detail = client.get(f'/api/wayfinder/runs/{run_id}', headers=headers)
        json_export = client.get(f'/api/wayfinder/runs/{run_id}/export.json', headers=headers)
        csv_export = client.get(f'/api/wayfinder/runs/{run_id}/export.csv', headers=headers)

    assert imported.status_code == 201
    assert imported.json()['origin'] == 'imported'
    assert imported.json()['status'] == 'completed'
    assert imported.json()['evidence_status'] == 'partial'
    assert detail.json()['results'] == [
        {'type': 'subdomain', 'value': 'api.example.com', 'sources': ['crtsh'], 'dns_status': 'resolved'},
        {'type': 'email', 'value': 'ops@example.com', 'sources': ['crtsh']},
    ]
    assert detail.json()['source_executions'][1]['status'] == 'rate-limited'
    assert detail.json()['activities'] == ['P0', 'P2']
    assert json_export.status_code == 200
    assert json_export.json()['evidence_run_id'] == 'evidence-run-1'
    assert csv_export.status_code == 200
    assert '"subdomain","api.example.com","resolved","crtsh"' in csv_export.text


def test_import_rejects_nested_entity_shapes_before_persistence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    evidence = {
        'target': 'example.com',
        'status': 'complete',
        'entities': [{'value': 'api.example.com', 'scope_classes': 1}],
    }

    with TestClient(api.app, raise_server_exceptions=False) as client:
        response = client.post(
            '/api/wayfinder/import?filename=evidence.json',
            headers={**headers, 'Content-Type': 'application/json'},
            content=json.dumps(evidence),
        )
        history = client.get('/api/wayfinder/runs', headers=headers)

    assert response.status_code == 400
    assert history.status_code == 200
    assert history.json() == []


def test_wayfinder_client_discards_stale_run_detail_responses() -> None:
    app_script = (Path(__file__).parents[2] / 'theHarvester/lib/api/static/wayfinder/app.js').read_text(encoding='utf-8')

    assert 'const selectedId = state.selectedId;' in app_script
    assert app_script.count('if (state.selectedId !== runId) return;') >= 2
    assert app_script.count('if (state.selectedId !== selectedId) return;') >= 4


def test_csv_export_neutralizes_spreadsheet_formulas_without_changing_json(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    dangerous = ['=cmd', '+cmd', '-cmd', '@cmd', '\tcmd', '\rcmd']
    evidence = {
        'target': 'example.com',
        'status': 'complete',
        'results': [{'type': 'other', 'value': value, 'sources': [value]} for value in dangerous],
    }

    with TestClient(api.app) as client:
        imported = client.post(
            '/api/wayfinder/import?filename=formulas.json',
            headers={**headers, 'Content-Type': 'application/json'},
            content=json.dumps(evidence),
        ).json()
        json_export = client.get(f'/api/wayfinder/runs/{imported["run_id"]}/export.json', headers=headers)
        csv_export = client.get(f'/api/wayfinder/runs/{imported["run_id"]}/export.csv', headers=headers)

    assert [result['value'] for result in json_export.json()['results']] == dangerous
    for value in dangerous:
        assert f'"\'{value.replace(chr(34), chr(34) * 2)}"' in csv_export.text


def test_operator_can_import_versioned_jsonl_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key', 'Content-Type': 'application/x-ndjson'}
    records = [
        {
            'schema_version': 'theharvester-evidence-v1',
            'record_type': 'run',
            'data': {
                'run_id': 'evidence-run-2',
                'target': 'example.net',
                'status': 'complete',
                'started_at': '2026-08-01T13:00:00+00:00',
                'completed_at': '2026-08-01T13:01:00+00:00',
            },
        },
        {
            'schema_version': 'theharvester-evidence-v1',
            'record_type': 'merged_result',
            'data': {
                'value': 'www.example.net',
                'addressability': 'resolver-disputed',
                'scope_classes': ['in-scope'],
                'provenance': [{'source': 'crtsh'}],
            },
        },
    ]
    body = '\n'.join(json.dumps(record) for record in records)

    with TestClient(api.app) as client:
        imported = client.post('/api/wayfinder/import?filename=evidence.jsonl', headers=headers, content=body)
        detail = client.get(f'/api/wayfinder/runs/{imported.json()["run_id"]}', headers={'X-API-Key': 'test-key'})

    assert imported.status_code == 201
    assert detail.json()['results'] == [
        {'type': 'subdomain', 'value': 'www.example.net', 'sources': ['crtsh'], 'dns_status': 'disputed'}
    ]


def test_import_rejects_invalid_and_oversized_result_files(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key', 'Content-Type': 'application/json'}

    with TestClient(api.app) as client:
        invalid = client.post('/api/wayfinder/import?filename=broken.json', headers=headers, content='{')
        oversized = client.post(
            '/api/wayfinder/import?filename=large.json',
            headers=headers,
            content=b' ' * (10 * 1024 * 1024 + 1),
        )

    assert invalid.status_code == 400
    assert invalid.json()['detail'] == 'Result file is not valid JSON'
    assert oversized.status_code == 413
    assert oversized.json()['detail'] == 'Result file exceeds the 10 MiB limit'


def test_import_rejects_malformed_legacy_collections_without_poisoning_history(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key', 'Content-Type': 'application/json'}

    with TestClient(api.app) as client:
        invalid_legacy = client.post(
            '/api/wayfinder/import?filename=legacy.json',
            headers=headers,
            content=json.dumps({'target': 'example.com', 'status': 'complete', '_legacy': []}),
        )
        invalid_route = client.post(
            '/api/wayfinder/import?filename=legacy.json',
            headers=headers,
            content=json.dumps({'target': 'example.com', 'status': 'complete', '_legacy': {'hosts': 'not-an-array'}}),
        )
        history = client.get('/api/wayfinder/runs', headers={'X-API-Key': 'test-key'})

    assert invalid_legacy.status_code == 400
    assert invalid_legacy.json()['detail'] == 'Evidence field _legacy must be an object'
    assert invalid_route.status_code == 400
    assert invalid_route.json()['detail'] == 'Legacy evidence field hosts must be an array'
    assert history.json() == []


def test_sqlite_worker_lease_can_replace_a_stale_owner(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import wayfinder

    moments = iter(('2026-08-02T12:00:00+00:00', '2026-08-02T12:00:31+00:00'))
    monkeypatch.setattr(wayfinder, '_now', lambda: next(moments))

    async def scenario():
        store = wayfinder.WayfinderStore(tmp_path / 'wayfinder.sqlite')
        first = await store.acquire_worker_lease('worker-a')
        replacement = await store.acquire_worker_lease('worker-b')
        return first, replacement

    assert asyncio.run(scenario()) == (True, True)


def test_worker_retries_a_fresh_lease_after_the_previous_process_disappears(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import wayfinder

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'enabled')
    monkeypatch.setattr(wayfinder, '_worker_task', None)
    monkeypatch.setattr(wayfinder, '_worker_stop', None)
    monkeypatch.setattr(wayfinder, '_worker_wakeup', None)

    async def scenario():
        store = wayfinder.WayfinderStore()
        await store.acquire_worker_lease('other-process')
        await wayfinder.start_worker()
        task = wayfinder._worker_task
        await store.release_worker_lease('other-process')
        wayfinder._wake_worker()
        for _ in range(20):
            await asyncio.sleep(0.01)
            if wayfinder._worker_owner is not None and await store.heartbeat_worker_lease(wayfinder._worker_owner):
                break
        acquired = wayfinder._worker_owner is not None and await store.heartbeat_worker_lease(wayfinder._worker_owner)
        await wayfinder.stop_worker()
        return task, acquired

    task, acquired = asyncio.run(scenario())
    assert task is not None
    assert acquired is True


def test_stop_worker_releases_its_lease_and_resets_globals_when_the_task_fails(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import wayfinder

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))

    async def scenario():
        store = wayfinder.WayfinderStore()
        await store.acquire_worker_lease('worker-a')

        async def fail() -> None:
            raise RuntimeError('worker failed')

        wayfinder._worker_owner = 'worker-a'
        wayfinder._worker_stop = asyncio.Event()
        wayfinder._worker_wakeup = asyncio.Event()
        wayfinder._worker_task = asyncio.create_task(fail())
        with pytest.raises(RuntimeError, match='worker failed'):
            await wayfinder.stop_worker()
        acquired = await store.acquire_worker_lease('worker-b')
        return acquired

    assert asyncio.run(scenario()) is True
    assert wayfinder._worker_task is None
    assert wayfinder._worker_owner is None
    assert wayfinder._worker_stop is None
    assert wayfinder._worker_wakeup is None


def test_single_worker_completes_a_queued_run_with_child_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, wayfinder

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'enabled')

    async def fixture_process(run_id, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {
                    'run_id': 'child-evidence',
                    'target': 'example.com',
                    'started_at': '2026-08-01T12:00:00+00:00',
                    'completed_at': '2026-08-01T12:00:01+00:00',
                    'status': 'complete',
                    'source_executions': [],
                    'entities': [],
                }
            ),
            encoding='utf-8',
        )
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'print("fixture worker complete")',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    monkeypatch.setattr(wayfinder, '_process_factory', fixture_process)
    headers = {'X-API-Key': 'test-key'}
    with TestClient(api.app) as client:
        submitted = client.post(
            '/api/wayfinder/runs',
            headers=headers,
            json={'target': 'example.com', 'sources': ['crtsh'], 'deadline_seconds': 60},
        ).json()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            detail = client.get(f'/api/wayfinder/runs/{submitted["run_id"]}', headers=headers).json()
            if detail['status'] == 'completed':
                break
            time.sleep(0.02)

    assert detail['status'] == 'completed'
    assert detail['evidence_status'] == 'complete'
    assert 'fixture worker complete' in detail['log']


def test_worker_revalidates_a_direct_target_before_starting_the_child(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, wayfinder

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'enabled')
    answers = [True, False]
    started = []

    async def changing_resolution(_target):
        return answers.pop(0) if answers else False

    async def unexpected_process(run_id, _artifact_dir):
        started.append(run_id)
        return await asyncio.create_subprocess_exec(sys.executable, '-c', 'pass')

    monkeypatch.setattr(wayfinder, 'is_public_target', changing_resolution)
    monkeypatch.setattr(wayfinder, '_process_factory', unexpected_process)
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app) as client:
        submitted = client.post(
            '/api/wayfinder/runs',
            headers=headers,
            json={'target': 'example.com', 'sources': ['crtsh'], 'screenshot': True},
        ).json()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            detail = client.get(f'/api/wayfinder/runs/{submitted["run_id"]}', headers=headers).json()
            if detail['status'] == 'failed':
                break
            time.sleep(0.02)

    assert started == []
    assert detail['status'] == 'failed'
    assert detail['error'] == 'P2 target is no longer publicly routable'


def test_running_cancellation_terminates_the_child_and_becomes_cancelled(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, wayfinder

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'enabled')

    async def slow_process(_run_id, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {'target': 'example.com', 'status': 'partial', 'results': [{'type': 'email', 'value': 'saved@example.com'}]}
            ),
            encoding='utf-8',
        )
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import time; time.sleep(60)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    monkeypatch.setattr(wayfinder, '_process_factory', slow_process)
    headers = {'X-API-Key': 'test-key'}
    with TestClient(api.app) as client:
        submitted = client.post(
            '/api/wayfinder/runs',
            headers=headers,
            json={'target': 'example.com', 'sources': ['crtsh'], 'deadline_seconds': 60},
        ).json()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            detail = client.get(f'/api/wayfinder/runs/{submitted["run_id"]}', headers=headers).json()
            if detail['status'] == 'running':
                break
            time.sleep(0.02)
        requested = client.post(f'/api/wayfinder/runs/{submitted["run_id"]}/cancel', headers=headers)
        while time.monotonic() < deadline:
            detail = client.get(f'/api/wayfinder/runs/{submitted["run_id"]}', headers=headers).json()
            if detail['status'] == 'cancelled':
                break
            time.sleep(0.02)

    assert requested.json()['status'] == 'cancelling'
    assert detail['status'] == 'cancelled'
    assert detail['completed_at'] is not None
    assert detail['evidence_status'] == 'partial'
    assert detail['results'][0]['value'] == 'saved@example.com'


@pytest.mark.skipif(os.name == 'nt', reason='POSIX process-group behavior')
def test_running_cancellation_terminates_the_child_process_group(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, wayfinder

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'enabled')
    pid_file = tmp_path / 'grandchild.pid'

    async def process_tree(_run_id, _artifact_dir):
        script = (
            'import subprocess,sys,time; '
            'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); '
            'open(sys.argv[1],"w").write(str(child.pid)); time.sleep(60)'
        )
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            script,
            str(pid_file),
            start_new_session=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        wayfinder._process_groups[process] = process.pid
        return process

    monkeypatch.setattr(wayfinder, '_process_factory', process_tree)
    headers = {'X-API-Key': 'test-key'}
    grandchild_pid = None
    try:
        with TestClient(api.app) as client:
            submitted = client.post(
                '/api/wayfinder/runs',
                headers=headers,
                json={'target': 'example.com', 'sources': ['crtsh'], 'deadline_seconds': 60},
            ).json()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    grandchild_pid = int(pid_file.read_text())
                    break
                except (FileNotFoundError, ValueError):
                    time.sleep(0.02)
            else:
                pytest.fail('grandchild PID was not written')
            client.post(f'/api/wayfinder/runs/{submitted["run_id"]}/cancel', headers=headers)
            while time.monotonic() < deadline:
                detail = client.get(f'/api/wayfinder/runs/{submitted["run_id"]}', headers=headers).json()
                if detail['status'] == 'cancelled':
                    break
                time.sleep(0.02)
        while time.monotonic() < deadline:
            try:
                os.kill(grandchild_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail('grandchild remained alive after cancellation')
    finally:
        if grandchild_pid is not None:
            try:
                os.kill(grandchild_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_whole_run_deadline_terminates_child_and_retains_saved_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import wayfinder

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(wayfinder, '_worker_stop', None)

    async def slow_process(_run_id, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {'target': 'example.com', 'status': 'partial', 'results': [{'type': 'email', 'value': 'saved@example.com'}]}
            ),
            encoding='utf-8',
        )
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import time; time.sleep(60)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    monkeypatch.setattr(wayfinder, '_process_factory', slow_process)

    async def scenario():
        store = wayfinder.WayfinderStore()
        await store.create(wayfinder.RunRequest(target='example.com', sources=['crtsh']))
        run = await store.claim_next()
        assert run is not None
        run['request']['deadline_seconds'] = 0
        await wayfinder._execute_claimed(store, run)
        return await store.get(run['run_id'])

    detail = asyncio.run(scenario())

    assert detail is not None
    assert detail['status'] == 'failed'
    assert 'deadline' in detail['error']
    assert detail['evidence_status'] == 'partial'
    assert detail['results'][0]['value'] == 'saved@example.com'


def test_nonzero_child_exit_retains_saved_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import wayfinder

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(wayfinder, '_worker_stop', None)

    async def failing_process(_run_id, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {'target': 'example.com', 'status': 'partial', 'results': [{'type': 'email', 'value': 'saved@example.com'}]}
            ),
            encoding='utf-8',
        )
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'raise SystemExit(7)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    monkeypatch.setattr(wayfinder, '_process_factory', failing_process)

    async def scenario():
        store = wayfinder.WayfinderStore()
        await store.create(wayfinder.RunRequest(target='example.com', sources=['crtsh']))
        run = await store.claim_next()
        assert run is not None
        await wayfinder._execute_claimed(store, run)
        return await store.get(run['run_id'])

    detail = asyncio.run(scenario())

    assert detail is not None
    assert detail['status'] == 'failed'
    assert detail['error'] == 'Child process exited with status 7 without terminal completion'
    assert detail['evidence_status'] == 'partial'
    assert detail['results'][0]['value'] == 'saved@example.com'


def test_child_exit_with_invalid_evidence_preserves_cancelling_lifecycle(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import wayfinder

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))
    failures = []

    class Process:
        pid = None
        returncode = 0
        stdout = None
        stderr = None

        async def wait(self):
            return 0

    class DoneTask:
        def __init__(self, result):
            self.result = result

        def done(self):
            return True

        def __await__(self):
            async def complete():
                return self.result

            return complete().__await__()

    class Store:
        async def get(self, _run_id):
            return {'status': 'cancelling'}

        async def fail(self, *args, **kwargs):
            failures.append((args, kwargs))

        async def finish(self, *_args, **_kwargs):
            raise AssertionError('Invalid evidence should use the terminal failure path')

    async def process_factory(_run_id, _artifact_dir):
        return Process()

    task_results = iter((0, 'child log'))

    def create_done_task(coroutine):
        coroutine.close()
        return DoneTask(next(task_results))

    monkeypatch.setattr(wayfinder, '_process_factory', process_factory)
    monkeypatch.setattr(wayfinder, '_read_child_evidence', lambda _path: (None, 'Child evidence is invalid'))
    monkeypatch.setattr(wayfinder.asyncio, 'create_task', create_done_task)

    asyncio.run(
        wayfinder._execute_claimed(
            Store(),
            {'run_id': 'run-1', 'request': {'deadline_seconds': 60}},
        )
    )

    assert failures[0][1]['cancelled'] is True


def test_child_forwards_shared_dns_limits_and_resolver_vantages(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import wayfinder
    from theHarvester.lib.enumeration import EnumerationOptions

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))
    observed = {}

    async def stop_after_args(args, *, completed_result_checkpoint, return_completed_result):
        observed['args'] = args
        observed['checkpoint'] = completed_result_checkpoint
        observed['return_completed_result'] = return_completed_result
        raise RuntimeError('arguments captured')

    monkeypatch.setattr(main_module, 'start', stop_after_args)

    async def scenario():
        store = wayfinder.WayfinderStore()
        await store.create(
            wayfinder.RunRequest(
                target='example.com',
                sources=['crtsh'],
                start=25,
                proxies=True,
                dns_lookup=True,
                dns_resolve=True,
                dns_resolvers=['192.0.2.53', '198.51.100.53', '203.0.113.53'],
                dns_recursive_depth=3,
                dns_recursive_query_limit=1_234,
                dns_recursive_runtime_seconds=12.5,
            )
        )
        run = await store.claim_next()
        assert run is not None
        with pytest.raises(RuntimeError, match='arguments captured'):
            await wayfinder._child_execute(run['run_id'], store.database)

    asyncio.run(scenario())

    args = observed['args']
    assert isinstance(args, EnumerationOptions)
    assert args.start == 25
    assert args.proxies is True
    assert args.dns_lookup is True
    assert args.dns_resolve == '192.0.2.53,198.51.100.53,203.0.113.53'
    assert args.dns_recursive_depth == 3
    assert args.dns_recursive_query_limit == 1_234
    assert args.dns_recursive_runtime_seconds == 12.5
    assert callable(observed['checkpoint'])
    assert observed['return_completed_result'] is True


def test_child_retains_partial_checkpoint_when_cancelled(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import wayfinder
    from theHarvester.lib.completed_result import CompletedResult

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))

    checkpointed = asyncio.Event()

    async def checkpoint_then_wait(_args, *, completed_result_checkpoint, return_completed_result):
        assert return_completed_result is True
        now = datetime.now(UTC)
        evidence = CompletedResult.finish(
            target='example.com',
            started_at=now,
            completed_at=now,
            groups={'email': ['saved@example.com']},
        )
        await completed_result_checkpoint(evidence)
        checkpointed.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(main_module, 'start', checkpoint_then_wait)

    async def scenario():
        store = wayfinder.WayfinderStore()
        created = await store.create(wayfinder.RunRequest(target='example.com', sources=['crtsh']))
        run = await store.claim_next()
        assert run is not None
        child = asyncio.create_task(wayfinder._child_execute(created['run_id'], store.database))
        await checkpointed.wait()
        child.cancel()
        await child
        return wayfinder._read_child_evidence(wayfinder._artifact_dir(created['run_id']))

    evidence, error = asyncio.run(scenario())

    assert error is None
    assert evidence is not None
    assert evidence['status'] == 'partial'
    assert evidence['results'] == [{'type': 'email', 'value': 'saved@example.com', 'sources': []}]


@pytest.mark.parametrize(
    ('field', 'value'),
    [
        ('dns_resolvers', ['192.0.2.53', '192.0.2.53', '203.0.113.53']),
        ('dns_resolvers', ['not-an-ip', '198.51.100.53', '203.0.113.53']),
        ('dns_recursive_runtime_seconds', float('nan')),
        ('dns_recursive_runtime_seconds', float('inf')),
    ],
)
def test_run_request_rejects_invalid_recursive_dns_controls(field, value) -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api import wayfinder

    with pytest.raises(ValidationError):
        wayfinder.RunRequest(target='example.com', sources=['crtsh'], **{field: value})


@pytest.mark.skipif(os.name == 'nt', reason='POSIX file modes')
def test_child_artifacts_are_owner_only(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import wayfinder
    from theHarvester.lib.completed_result import CompletedResult

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def complete_without_network(*_args, **_kwargs):
        now = datetime.now(UTC)
        return [CompletedResult.finish(target='example.com', started_at=now, completed_at=now, groups={})]

    monkeypatch.setattr(main_module, 'start', complete_without_network)

    async def scenario():
        store = wayfinder.WayfinderStore()
        created = await store.create(wayfinder.RunRequest(target='example.com', sources=['crtsh'], screenshot=True))
        claimed = await store.claim_next()
        assert claimed is not None
        await wayfinder._child_execute(created['run_id'], store.database)
        return wayfinder._artifact_dir(created['run_id'])

    artifact_dir = asyncio.run(scenario())

    assert stat.S_IMODE(artifact_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((artifact_dir / 'screenshots').stat().st_mode) == 0o700
    assert stat.S_IMODE((artifact_dir / 'evidence.json').stat().st_mode) == 0o600


def test_wayfinder_uses_same_origin_cors_and_limits_only_mutations(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    api.limiter.reset()
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app) as client:
        preflight = client.options(
            '/api/wayfinder/runs',
            headers={'Origin': 'https://attacker.example', 'Access-Control-Request-Method': 'POST'},
        )
        mutations = [
            client.post('/api/wayfinder/runs', headers=headers, json={'target': 'example.com', 'sources': ['crtsh']})
            for _ in range(6)
        ]
        polls = [client.get('/api/wayfinder/runs', headers=headers) for _ in range(10)]

    assert 'access-control-allow-origin' not in preflight.headers
    assert [response.status_code for response in mutations[:5]] == [503] * 5
    assert mutations[5].status_code == 429
    assert [response.status_code for response in polls] == [200] * 10


def test_fastapi_and_operator_header_use_the_authoritative_version(tmp_path, monkeypatch) -> None:
    from theHarvester import __version__
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        page = client.get('/')

    assert api.app.version == __version__
    assert page.status_code == 200
    assert f'v{__version__}' in page.text
    assert '{{ASSET_VERSION}}' not in page.text


def test_source_catalog_and_screenshots_stay_inside_managed_artifacts(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    evidence = {
        'run_id': 'evidence-with-untrusted-path',
        'target': 'example.com',
        'started_at': '2026-08-01T12:00:00+00:00',
        'completed_at': '2026-08-01T12:01:00+00:00',
        'status': 'complete',
        'source_executions': [],
        'results': [
            {'type': 'api-endpoint', 'value': '/api/v1', 'sources': []},
            {'type': 'screenshot', 'value': 'https://api.example.com', 'sources': []},
        ],
        'entities': [],
        'selected_observations': [{'source': 'action:screenshot', 'kind': 'screenshot', 'value': '/etc/passwd', 'detail': None}],
    }

    with TestClient(api.app) as client:
        sources = client.get('/api/wayfinder/sources', headers=headers)
        imported = client.post(
            '/api/wayfinder/import?filename=evidence.json',
            headers={**headers, 'Content-Type': 'application/json'},
            content=json.dumps(evidence),
        ).json()
        screenshot_dir = tmp_path / 'artifacts' / imported['run_id'] / 'screenshots'
        screenshot_dir.mkdir(parents=True)
        (screenshot_dir / 'api.example.com.png').write_bytes(b'\x89PNG\r\n\x1a\nfixture')
        detail = client.get(f'/api/wayfinder/runs/{imported["run_id"]}', headers=headers)
        screenshot = client.get(
            f'/api/wayfinder/runs/{imported["run_id"]}/screenshots/api.example.com.png',
            headers=headers,
        )
        outside = client.get(
            f'/api/wayfinder/runs/{imported["run_id"]}/screenshots/evidence.json',
            headers=headers,
        )

    by_name = {source['name']: source for source in sources.json()}
    from theHarvester.lib.source_catalog import SOURCE_SPECS

    assert {name: source['activity'] for name, source in by_name.items()} == {
        name: spec.activity for name, spec in SOURCE_SPECS.items()
    }
    assert by_name['crtsh']['activity'] == 'P0'
    assert by_name['criminalip']['activity'] == 'P2'
    assert all('family' not in source for source in by_name.values())
    assert by_name['urlscan']['capabilities'] == ['asns', 'ips', 'subdomains', 'urls']
    assert detail.json()['results'] == [{'type': 'api-endpoint', 'value': '/api/v1', 'sources': []}]
    assert detail.json()['screenshots'] == [
        {
            'name': 'api.example.com.png',
            'target': 'api.example.com',
            'url': f'/api/wayfinder/runs/{imported["run_id"]}/screenshots/api.example.com.png',
        }
    ]
    assert screenshot.status_code == 200
    assert screenshot.content.startswith(b'\x89PNG')
    assert outside.status_code == 404


@pytest.mark.skipif(os.name == 'nt', reason='POSIX symlink behavior')
def test_screenshot_route_rejects_symlinked_files(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}
    evidence = {'target': 'example.com', 'status': 'complete'}

    with TestClient(api.app) as client:
        imported = client.post(
            '/api/wayfinder/import?filename=evidence.json',
            headers={**headers, 'Content-Type': 'application/json'},
            content=json.dumps(evidence),
        ).json()
        screenshot_dir = tmp_path / 'artifacts' / imported['run_id'] / 'screenshots'
        screenshot_dir.mkdir(parents=True)
        outside = tmp_path / 'outside.png'
        outside.write_bytes(b'private')
        (screenshot_dir / 'linked.png').symlink_to(outside)
        response = client.get(
            f'/api/wayfinder/runs/{imported["run_id"]}/screenshots/linked.png',
            headers=headers,
        )

    assert response.status_code == 404

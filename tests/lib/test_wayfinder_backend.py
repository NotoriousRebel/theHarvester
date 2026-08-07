from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi.testclient import TestClient


def test_worker_layer_preserves_the_existing_api_root(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        response = client.get('/')

    assert response.status_code == 200
    assert 'API Documentation' in response.text


def test_orphan_recovery_reattaches_partial_checkpoint(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import wayfinder
    from theHarvester.lib.completed_result import CompletedResult

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def scenario():
        store = wayfinder.WayfinderStore()
        created = await store.create(wayfinder.RunRequest(target='example.com', sources=['crtsh']))
        claimed = await store.claim_next()
        assert claimed is not None
        artifact_dir = wayfinder._artifact_dir(created['run_id'])
        wayfinder._ensure_private_directory(artifact_dir)
        now = datetime.now(UTC)
        checkpoint = CompletedResult.finish(
            target='example.com',
            started_at=now,
            completed_at=now,
            groups={'email': ['saved@example.com']},
        )
        wayfinder._write_child_evidence(artifact_dir, checkpoint, partial=True)
        await store.recover_orphans()
        return await store.get(created['run_id'])

    recovered = asyncio.run(scenario())

    assert recovered is not None
    assert recovered['status'] == 'failed'
    assert recovered['evidence_status'] == 'partial'
    assert recovered['results'] == [{'type': 'email', 'value': 'saved@example.com', 'sources': []}]


def test_worker_lease_serializes_execution_owners(tmp_path) -> None:
    from theHarvester.lib.api.wayfinder import WayfinderStore

    async def scenario() -> tuple[bool, bool, bool]:
        store = WayfinderStore(tmp_path / 'wayfinder.sqlite')
        first = await store.acquire_worker_lease('worker-a')
        second = await store.acquire_worker_lease('worker-b')
        await store.release_worker_lease('worker-a')
        replacement = await store.acquire_worker_lease('worker-b')
        return first, second, replacement

    assert asyncio.run(scenario()) == (True, False, True)


def test_submission_fails_closed_when_worker_supervisor_stops(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, wayfinder

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(wayfinder, '_worker_enabled', lambda: True)
    monkeypatch.setattr(wayfinder, '_worker_task', type('StoppedTask', (), {'done': lambda self: True})())

    with TestClient(api.app) as client:
        response = client.post(
            '/api/wayfinder/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': 'example.com', 'sources': ['crtsh']},
        )

    assert response.status_code == 503
    assert response.json()['detail'] == 'Wayfinder execution worker is unavailable'

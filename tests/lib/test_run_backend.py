from __future__ import annotations

import asyncio
import inspect
import json
import os
import sqlite3
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient


class _FakeScreenshotBatch:
    async def reachable_targets(self, targets: list[str]) -> list[tuple[str, str]]:
        reachable: list[tuple[str, str]] = []
        for subject in targets:
            final_url, status = await self.visit(subject)
            if status:
                reachable.append((subject, final_url))
        return reachable

    async def capture_targets(self, targets, record) -> None:
        async def capture(subject: str, final_url: str) -> tuple[str, str, Path]:
            output_path = self.screenshot_path(subject)
            return subject, await self.take_screenshot(final_url, output_path=output_path), output_path

        tasks = [asyncio.create_task(capture(*target)) for target in targets]
        try:
            for task in asyncio.as_completed(tasks):
                await record(*await task)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, tuple):
                    await record(*outcome)
            raise
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def test_run_paths_use_one_expanded_database_and_artifact_root(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('THEHARVESTER_RUN_DB', '~/state/runs.sqlite')
    monkeypatch.delenv('THEHARVESTER_RUN_ARTIFACTS', raising=False)

    store = RunStore()

    assert store.database == tmp_path / 'state' / 'runs.sqlite'
    assert store.artifact_directory('run-id') == tmp_path / 'state' / 'run-artifacts' / 'run-id'


def test_run_store_does_not_change_caller_owned_directory_permissions(tmp_path) -> None:
    from theHarvester.lib.api.run_store import RunStore

    tmp_path.chmod(0o755)
    asyncio.run(RunStore(tmp_path / 'runs.sqlite').initialize())

    assert os.stat(tmp_path).st_mode & 0o777 == 0o755


def test_run_history_is_bounded_without_loading_completed_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    async def fail_load(*_args, **_kwargs):
        raise AssertionError('run summaries must not hydrate terminal evidence')

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        for index in range(4):
            await store.create(RunRequest(target=f'{index}.example.test', sources=['crtsh']))
        monkeypatch.setattr(store.results, 'load_run', fail_load)
        return await store.list_runs(limit=2, offset=1)

    history = asyncio.run(scenario())

    assert len(history) == 2
    assert [run['target'] for run in history] == ['2.example.test', '1.example.test']
    assert all(run['result_count'] == 0 for run in history)


def test_run_history_breaks_timestamp_ties_by_run_id(tmp_path) -> None:
    from theHarvester.lib.database import RunLifecycleStore

    async def scenario() -> list[str]:
        store = RunLifecycleStore(tmp_path / 'runs.sqlite')
        await store.initialize()
        for run_id in ('run-a', 'run-c', 'run-b'):
            await store.create(
                run_id=run_id,
                target='example.test',
                status='completed',
                origin='imported',
                created_at='2026-08-09T12:00:00+00:00',
                request_json='{}',
            )
        first = await store.list_records(limit=2, offset=0)
        second = await store.list_records(limit=2, offset=2)
        return [str(run['run_id']) for run in first + second]

    assert asyncio.run(scenario()) == ['run-c', 'run-b', 'run-a']


def test_api_lifespan_disposes_shared_sqlite_engines(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    disposed = False

    async def no_op() -> None:
        return None

    async def dispose() -> None:
        nonlocal disposed
        disposed = True

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(api, 'dispose_sqlite_databases', dispose)

    with TestClient(api.app):
        pass

    assert disposed is True


def test_static_assets_are_resolved_from_the_installed_module(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.chdir(tmp_path)

    assert api.STATIC_DIRECTORY == Path(api.__file__).resolve().parent / 'static'


def test_explicit_run_database_keeps_screenshot_artifacts_attached(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.delenv('THEHARVESTER_RUN_DB', raising=False)
    monkeypatch.delenv('THEHARVESTER_RUN_ARTIFACTS', raising=False)

    async def scenario():
        store = RunStore(tmp_path / 'state' / 'runs.sqlite')
        imported = await store.import_evidence(
            {
                'run_id': '4a6e5a15-fae5-462c-a34b-122ced6bb86d',
                'target': 'example.test',
                'status': 'complete',
                'started_at': '2026-08-09T12:00:00+00:00',
                'completed_at': '2026-08-09T12:01:00+00:00',
                'results': [{'type': 'hostname', 'value': 'owned.example.test', 'actions': []}],
                'source_executions': [],
                'action_executions': [
                    {
                        'action': 'screenshot',
                        'status': 'completed',
                        'duration_ms': 1,
                        'result_count': 0,
                        'error_type': None,
                        'stop_reason': None,
                    }
                ],
                'artifacts': [
                    {
                        'action': 'screenshot',
                        'kind': 'screenshot',
                        'subject': {'kind': 'hostname', 'value': 'owned.example.test'},
                        'file': {
                            'path': 'screenshots/owned.example.test.png',
                            'media_type': 'image/png',
                            'size_bytes': 3,
                            'sha256': '0' * 64,
                        },
                        'created_at': '2026-08-09T12:01:00+00:00',
                    }
                ],
            },
            'evidence.jsonl',
        )
        screenshot_dir = store.artifact_directory(imported['run_id']) / 'screenshots'
        screenshot_dir.mkdir(parents=True)
        (screenshot_dir / 'owned.example.test.png').write_bytes(b'png')
        return await store.get(imported['run_id'])

    run = asyncio.run(scenario())

    assert run is not None
    assert run['evidence']['run_id'] == run['run_id']
    assert run['request']['source_run_id'] == '4a6e5a15-fae5-462c-a34b-122ced6bb86d'
    assert [screenshot['name'] for screenshot in run['screenshots']] == ['owned.example.test.png']


def test_api_lifecycle_and_terminal_evidence_share_the_sqlalchemy_database(tmp_path) -> None:
    from theHarvester.lib.api import run_store as run_store_module
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    database = tmp_path / 'stash.sqlite'

    async def scenario() -> str:
        store = RunStore(database)
        queued = await store.create(RunRequest(target='example.test', sources=['crtsh']))
        await store.claim_next()
        await store.finish(
            queued['run_id'],
            {
                'run_id': '4a6e5a15-fae5-462c-a34b-122ced6bb86d',
                'target': 'example.test',
                'status': 'complete',
                'started_at': '2026-08-09T12:00:00+00:00',
                'completed_at': '2026-08-09T12:01:00+00:00',
                'results': [{'type': 'hostname', 'value': 'api.example.test', 'sources': ['crtsh']}],
                'source_executions': [
                    {
                        'source': 'crtsh',
                        'status': 'completed',
                        'duration_ms': 1,
                        'result_count': 1,
                        'error_type': None,
                        'stop_reason': None,
                    }
                ],
            },
            '',
        )
        return queued['run_id']

    lifecycle_run_id = asyncio.run(scenario())

    with sqlite3.connect(database) as db:
        evidence_run_id = db.execute(
            'SELECT evidence_run_id FROM run_records WHERE run_id = ?',
            (lifecycle_run_id,),
        ).fetchone()[0]
        stored_target = db.execute('SELECT target FROM runs WHERE run_id = ?', (evidence_run_id,)).fetchone()[0]
        schema_version = db.execute('PRAGMA user_version').fetchone()[0]
    assert evidence_run_id == lifecycle_run_id
    assert stored_target == 'example.test'
    assert schema_version == 8
    assert 'import aiosqlite' not in inspect.getsource(run_store_module)


def test_run_store_distinguishes_no_evidence_from_a_broken_evidence_link(tmp_path) -> None:
    from uuid import uuid4

    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.database import ResultStoreError

    database = tmp_path / 'runs.sqlite'
    store = RunStore(database)
    queued = asyncio.run(store.create(RunRequest(target='example.test', sources=['crtsh'])))
    assert asyncio.run(store.load_completed_result(queued['run_id'])) is None

    with sqlite3.connect(database) as db:
        db.execute(
            'UPDATE run_records SET evidence_run_id = ? WHERE run_id = ?',
            (str(uuid4()), queued['run_id']),
        )

    with pytest.raises(ResultStoreError, match='Attached run evidence does not exist'):
        asyncio.run(store.load_completed_result(queued['run_id']))


def test_child_execution_passes_the_configured_database_to_core(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.run_worker import _child_execute
    from theHarvester.lib.completed_result import CompletedResult

    database = tmp_path / 'state' / 'runs.sqlite'
    seen_database = None
    seen_run_id = None

    async def fake_start(_args, **kwargs):
        nonlocal seen_database, seen_run_id
        seen_database = kwargs.get('result_database')
        seen_run_id = kwargs.get('completed_run_id')
        now = datetime.now(UTC)
        result = CompletedResult.finish(
            run_id=seen_run_id,
            target='example.test',
            started_at=now,
            completed_at=now,
            groups={},
        )
        return (result,)

    async def scenario() -> None:
        store = RunStore(database)
        queued = await store.create(RunRequest(target='example.test', sources=['crtsh']))
        await store.claim_next()
        monkeypatch.setattr(main_module, 'start', fake_start)
        await _child_execute(queued['run_id'], database)

    asyncio.run(scenario())

    assert seen_database == database
    with sqlite3.connect(database) as db:
        lifecycle_run_id = db.execute('SELECT run_id FROM run_records').fetchone()[0]
    assert str(seen_run_id) == lifecycle_run_id


def test_child_screenshot_run_persists_downloadable_artifact_metadata(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api.run_artifacts import read_child_evidence
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.run_worker import _child_execute

    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            return f'https://{host}', 'reachable'

        def screenshot_path(self, url: str) -> Path:
            return Path(self.output) / f'{url.removeprefix("https://")}.png'

        async def take_screenshot(self, url: str, *, output_path: Path | None = None) -> str:
            captured_url = url if url.startswith('https://') else f'https://{url}'
            (output_path or self.screenshot_path(captured_url)).write_bytes(b'png')
            return captured_url

    database = tmp_path / 'state' / 'runs.sqlite'
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(main_module, 'ScreenShotter', FakeScreenShotter)

    async def scenario():
        store = RunStore(database)
        queued = await store.create(RunRequest(target='api.example.test', sources=[], screenshot=True))
        await store.claim_next()
        await _child_execute(queued['run_id'], database)
        evidence, error = read_child_evidence(store.artifact_directory(queued['run_id']))
        assert error is None
        assert evidence is not None
        await store.finish(queued['run_id'], evidence, '')
        return await store.get(queued['run_id']), store.artifact_directory(queued['run_id'])

    run, artifact_dir = asyncio.run(scenario())

    assert run is not None
    assert run['action_executions'][0]['action'] == 'screenshot'
    assert run['action_executions'][0]['status'] == 'completed'
    assert run['results'] == [{'type': 'hostname', 'value': 'api.example.test', 'sources': [], 'actions': []}]
    assert [screenshot['name'] for screenshot in run['screenshots']] == ['api.example.test.png']
    assert (artifact_dir / 'screenshots' / 'api.example.test.png').read_bytes() == b'png'


def test_child_screenshot_cancellation_reuses_the_checkpointed_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api.run_artifacts import read_child_evidence
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.api.run_worker import _child_execute

    first_captured = asyncio.Event()

    class FakeScreenShotter(_FakeScreenshotBatch):
        slash = '/'

        def __init__(self, output: str) -> None:
            self.output = output

        def verify_path(self) -> bool:
            return True

        async def visit(self, host: str) -> tuple[str, str]:
            return f'https://{host}', 'reachable'

        async def take_screenshot(self, url: str, *, output_path: Path | None = None) -> str:
            assert output_path is not None
            if 'first.' in url:
                output_path.write_bytes(b'png')  # noqa: ASYNC240 - tiny in-memory screenshot fixture
                first_captured.set()
                return url
            await first_captured.wait()
            raise asyncio.CancelledError

        def screenshot_path(self, url: str) -> Path:
            return Path(self.output) / f'{url.removeprefix("https://")}.png'

    class TwoHostSource:
        def __init__(self, _word: str) -> None:
            pass

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_hostnames(self) -> set[str]:
            return {'first.example.test', 'second.example.test'}

    database = tmp_path / 'runs.sqlite'
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', TwoHostSource)
    monkeypatch.setattr(main_module, 'ScreenShotter', FakeScreenShotter)

    async def scenario():
        store = RunStore(database)
        queued = await store.create(RunRequest(target='example.test', sources=['crtsh'], screenshot=True))
        await store.claim_next()
        await _child_execute(queued['run_id'], database)
        evidence, error = read_child_evidence(store.artifact_directory(queued['run_id']))
        assert error is None
        assert evidence is not None
        await store.fail(queued['run_id'], 'cancelled', '', cancelled=True, evidence=evidence)
        return await store.get(queued['run_id'])

    run = asyncio.run(scenario())

    assert run is not None
    assert run['status'] == 'cancelled'
    assert run['action_executions'][0]['status'] == 'partial'
    assert [screenshot['target'] for screenshot in run['screenshots']] == ['first.example.test']


def test_sqlite_import_preserves_run_ids_and_is_idempotent(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_store
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult
    from theHarvester.lib.database import ResultStore, dispose_sqlite_databases

    source_database = tmp_path / 'source.sqlite'
    destination_database = tmp_path / 'destination.sqlite'
    now = datetime.now(UTC)
    first = CompletedResult.finish(
        target='first.example.test',
        started_at=now,
        completed_at=now,
        groups={'hostname': ['api.first.example.test']},
    )
    second = CompletedResult.finish(
        target='second.example.test',
        started_at=now,
        completed_at=now,
        groups={'email': ['security@second.example.test']},
    )
    list_calls: list[tuple[int | None, int]] = []
    original_list_runs = ResultStore.list_runs

    async def track_source_batches(self, *, limit=50, offset=0):
        if Path(self.database) == source_database.resolve():
            list_calls.append((limit, offset))
        return await original_list_runs(self, limit=limit, offset=offset)

    monkeypatch.setattr(run_store, 'DATABASE_IMPORT_BATCH_SIZE', 1)
    monkeypatch.setattr(ResultStore, 'list_runs', track_source_batches)

    async def scenario():
        source = ResultStore(source_database)
        await source.initialize()
        await source.save_run(first)
        await source.save_run(second)
        await dispose_sqlite_databases()
        destination = RunStore(destination_database)
        imported = await destination.import_database(source_database, 'source.sqlite')
        first_import_calls = list(list_calls)
        list_calls.clear()
        repeated = await destination.import_database(source_database, 'source.sqlite')
        history = await destination.list_runs()
        return imported, repeated, history, first_import_calls

    imported, repeated, history, first_import_calls = asyncio.run(scenario())

    expected_ids = sorted((str(first.run_id), str(second.run_id)))
    assert imported == {'filename': 'source.sqlite', 'imported_run_ids': expected_ids, 'skipped_run_ids': []}
    assert repeated == {'filename': 'source.sqlite', 'imported_run_ids': [], 'skipped_run_ids': expected_ids}
    assert sorted(run['run_id'] for run in history) == expected_ids
    assert first_import_calls == [(1, 0), (1, 1), (1, 2), (1, 0), (1, 1), (1, 2)]


def test_orphan_recovery_reattaches_partial_checkpoint_and_leaves_queued_work(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_artifacts import ensure_private_directory, write_child_evidence
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def scenario():
        store = RunStore()
        for target in ('first.example', 'second.example', 'third.example'):
            await store.create(RunRequest(target=target, sources=['crtsh']))
        cancelling = await store.claim_next()
        assert cancelling is not None
        await store.cancel(cancelling['run_id'])
        artifact_dir = store.artifact_directory(cancelling['run_id'])
        ensure_private_directory(artifact_dir)
        now = datetime.now(UTC)
        checkpoint = CompletedResult.finish(
            target='first.example',
            started_at=now,
            completed_at=now,
            groups={'email': ['saved@first.example']},
        )
        write_child_evidence(artifact_dir, checkpoint, partial=True)
        running = await store.claim_next()
        assert running is not None
        persisted = CompletedResult.finish(
            run_id=UUID(running['run_id']),
            target=str(running['target']),
            started_at=now,
            completed_at=now,
            groups={'hostname': [f'api.{running["target"]}']},
        )
        await store.results.save_run(persisted)
        await store.recover_orphans()
        return await store.get(cancelling['run_id']), await store.get(running['run_id']), await store.list_runs()

    cancelling, running, history = asyncio.run(scenario())

    assert cancelling is not None
    assert cancelling['status'] == 'failed'
    assert cancelling['evidence_status'] == 'partial'
    assert cancelling['results'] == [{'type': 'email', 'value': 'saved@first.example', 'sources': [], 'actions': []}]
    assert running is not None
    assert running['status'] == 'failed'
    assert running['results'] == [{'type': 'hostname', 'value': f'api.{running["target"]}', 'sources': [], 'actions': []}]
    assert {run['target']: run['status'] for run in history}['third.example'] == 'queued'


def test_orphan_checkpoint_read_does_not_block_the_event_loop(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_store as run_store_module
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    heartbeat_ran = threading.Event()
    heartbeat_seen_before_release: list[bool] = []
    release_read = threading.Event()

    def blocking_read(*_args):
        release_read.wait(timeout=1)
        return None, None

    def release() -> None:
        heartbeat_seen_before_release.append(heartbeat_ran.is_set())
        release_read.set()

    monkeypatch.setattr(run_store_module, 'read_child_evidence', blocking_read)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        await store.create(RunRequest(target='example.test', sources=['crtsh']))
        assert await store.claim_next() is not None
        timer = threading.Timer(0.2, release)
        timer.start()
        try:
            recover = asyncio.create_task(store.recover_orphans())
            heartbeat = asyncio.create_task(asyncio.sleep(0))
            heartbeat.add_done_callback(lambda _task: heartbeat_ran.set())
            await asyncio.gather(recover, heartbeat)
        finally:
            timer.join()

    asyncio.run(scenario())

    assert heartbeat_seen_before_release == [True]


def test_concurrent_lifecycle_tasks_use_distinct_async_sessions(tmp_path, monkeypatch) -> None:
    from theHarvester.lib import database as database_module
    from theHarvester.lib.database import RunLifecycleStore

    async def scenario() -> tuple[int, int]:
        lifecycle = RunLifecycleStore(tmp_path / 'runs.sqlite')
        await lifecycle.initialize()
        database = database_module._database_for(lifecycle.database)
        original_sessions = database.sessions
        tasks = []
        sessions = []

        def tracking_sessions():
            session = original_sessions()
            tasks.append(asyncio.current_task())
            sessions.append(session)
            return session

        monkeypatch.setattr(database, 'sessions', tracking_sessions)
        await asyncio.gather(lifecycle.get('first'), lifecycle.get('second'))
        return len({id(task) for task in tasks}), len({id(session) for session in sessions})

    assert asyncio.run(scenario()) == (2, 2)


def test_orphan_recovery_does_not_attach_same_id_evidence_for_another_target(tmp_path) -> None:
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        queued = await store.create(RunRequest(target='expected.example', sources=['crtsh']))
        await store.claim_next()
        now = datetime.now(UTC)
        await store.results.save_run(
            CompletedResult.finish(
                run_id=UUID(queued['run_id']),
                target='different.example',
                started_at=now,
                completed_at=now,
                groups={'hostname': ['api.different.example']},
            )
        )
        await store.recover_orphans()
        return await store.get(queued['run_id'])

    run = asyncio.run(scenario())

    assert run is not None
    assert run['status'] == 'failed'
    assert run['results'] == []


def test_orphan_recovery_rejects_checkpoint_for_another_target(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api.run_artifacts import ensure_private_directory, write_child_evidence
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        queued = await store.create(RunRequest(target='expected.example', sources=['crtsh']))
        await store.claim_next()
        artifact_dir = store.artifact_directory(queued['run_id'])
        ensure_private_directory(artifact_dir)
        now = datetime.now(UTC)
        write_child_evidence(
            artifact_dir,
            CompletedResult.finish(
                target='different.example',
                started_at=now,
                completed_at=now,
                groups={'hostname': ['api.different.example']},
            ),
            partial=True,
        )
        await store.recover_orphans()
        return await store.get(queued['run_id'])

    run = asyncio.run(scenario())

    assert run is not None
    assert run['status'] == 'failed'
    assert run['results'] == []
    assert 'does not match run target' in run['error']


@pytest.mark.parametrize('operation', ['finish', 'fail'])
def test_terminal_run_rejects_evidence_for_another_target(tmp_path, operation) -> None:
    from fastapi import HTTPException

    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        queued = await store.create(RunRequest(target='expected.example', sources=['crtsh']))
        await store.claim_next()
        now = datetime.now(UTC)
        evidence = CompletedResult.finish(
            target='different.example',
            started_at=now,
            completed_at=now,
            groups={'hostname': ['api.different.example']},
        ).evidence_dict()
        terminal = (
            store.finish(queued['run_id'], evidence, '')
            if operation == 'finish'
            else store.fail(queued['run_id'], 'failed', '', evidence=evidence)
        )
        with pytest.raises(HTTPException, match='Evidence target does not match run target'):
            await terminal
        with pytest.raises(LookupError):
            await store.results.load_run(UUID(queued['run_id']))

    asyncio.run(scenario())


def test_worker_lease_serializes_execution_owners(tmp_path) -> None:
    from theHarvester.lib.api.run_store import RunStore

    async def scenario() -> tuple[bool, bool, bool]:
        store = RunStore(tmp_path / 'runs.sqlite')
        first = await store.acquire_worker_lease('worker-a')
        second = await store.acquire_worker_lease('worker-b')
        await store.release_worker_lease('worker-a')
        replacement = await store.acquire_worker_lease('worker-b')
        return first, second, replacement

    assert asyncio.run(scenario()) == (True, False, True)


@pytest.mark.parametrize('failure_stage', ['heartbeat', 'database', 'output-reader', 'evidence-read', 'persistence'])
def test_worker_reaps_child_when_a_helper_stage_fails(tmp_path, monkeypatch, failure_stage) -> None:
    from theHarvester.lib.api import run_worker

    child = None

    class FailingStore:
        database = tmp_path / 'runs.sqlite'

        @staticmethod
        def artifact_directory(_run_id):
            return tmp_path / 'artifacts'

        @staticmethod
        async def heartbeat_worker_lease(_owner_id):
            if failure_stage == 'heartbeat':
                raise RuntimeError('heartbeat failed')
            return True

        @staticmethod
        async def get(_run_id):
            if failure_stage == 'database':
                raise RuntimeError('database failed')
            return {'status': 'running'}

        @staticmethod
        async def fail(*_args, **_kwargs):
            if failure_stage == 'persistence':
                raise RuntimeError('persistence failed')

    async def process_factory(_run_id, _database, _artifact_dir):
        nonlocal child
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import time; time.sleep(60)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return child

    async def fail_output(_process):
        raise RuntimeError('output reader failed')

    monkeypatch.setattr(run_worker, '_process_factory', process_factory)
    monkeypatch.setattr(run_worker, '_worker_stop', None)
    if failure_stage == 'output-reader':
        monkeypatch.setattr(run_worker, '_process_output', fail_output)
    if failure_stage == 'evidence-read':
        monkeypatch.setattr(
            run_worker,
            'read_child_evidence',
            lambda *_args: (_ for _ in ()).throw(RuntimeError('evidence read failed')),
        )

    async def scenario() -> None:
        try:
            with pytest.raises(RuntimeError, match=failure_stage.split('-')[0]):
                await asyncio.wait_for(
                    run_worker._execute_claimed(
                        FailingStore(),
                        {
                            'run_id': 'run-id',
                            'target': 'example.test',
                            'request': {'deadline_seconds': 0 if failure_stage in {'evidence-read', 'persistence'} else 60},
                        },
                        'worker-id',
                    ),
                    timeout=1,
                )
            assert child is not None
            assert child.returncode is not None
        finally:
            if child is not None and child.returncode is None:
                child.kill()
                await child.wait()

    asyncio.run(scenario())


@pytest.mark.parametrize('failure_stage', ['checkpoint', 'terminal'])
def test_child_serialization_failure_ends_enumeration_task(tmp_path, monkeypatch, failure_stage) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    enumeration_finished = asyncio.Event()

    async def fake_start(options, *, completed_result_checkpoint, **_kwargs):
        now = datetime.now(UTC)
        evidence = CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={})
        try:
            if failure_stage == 'checkpoint':
                await completed_result_checkpoint(evidence)
            return (evidence,)
        finally:
            enumeration_finished.set()

    def fail_serialization(_evidence, *, partial):
        if partial is (failure_stage == 'checkpoint'):
            raise RuntimeError(f'{failure_stage} serialization failed')
        return '{}'

    monkeypatch.setattr(main_module, 'start', fake_start)
    monkeypatch.setattr(run_worker, 'serialize_child_evidence', fail_serialization)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(RunRequest(target='example.test', sources=['crtsh']))
        assert await store.claim_next() is not None
        with pytest.raises(RuntimeError, match=f'{failure_stage} serialization failed'):
            await run_worker._child_execute(created['run_id'], store.database)
        assert enumeration_finished.is_set()

    asyncio.run(scenario())


def test_worker_cancellation_reaps_child_and_output_reader(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker

    child = None
    child_started = asyncio.Event()
    output_reader_finished = asyncio.Event()

    class Store:
        database = tmp_path / 'runs.sqlite'

        @staticmethod
        def artifact_directory(_run_id):
            return tmp_path / 'artifacts'

        @staticmethod
        async def get(_run_id):
            return {'status': 'running'}

    async def process_factory(_run_id, _database, _artifact_dir):
        nonlocal child
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import time; time.sleep(60)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        child_started.set()
        return child

    original_process_output = run_worker._process_output

    async def observe_output(process):
        try:
            return await original_process_output(process)
        finally:
            output_reader_finished.set()

    monkeypatch.setattr(run_worker, '_process_factory', process_factory)
    monkeypatch.setattr(run_worker, '_process_output', observe_output)
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    async def scenario() -> None:
        task = asyncio.create_task(
            run_worker._execute_claimed(
                Store(),
                {'run_id': 'run-id', 'target': 'example.test', 'request': {'deadline_seconds': 60}},
            )
        )
        await child_started.wait()
        task.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await task
            assert child.returncode is not None
            assert output_reader_finished.is_set()
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()

    asyncio.run(scenario())


def test_worker_caps_each_output_stream_with_an_explicit_marker() -> None:
    from theHarvester.lib.api import run_worker

    async def scenario() -> str:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import sys; sys.stdout.write("o" * 120000); sys.stderr.write("e" * 120000)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        output, _ = await asyncio.gather(run_worker._process_output(process), process.wait())
        return output

    output = asyncio.run(scenario())

    assert len(output.encode()) <= run_worker.MAX_CAPTURED_OUTPUT_BYTES
    assert '[stdout truncated:' in output
    assert '[stderr truncated:' in output


def test_worker_caps_decoded_non_utf8_output() -> None:
    from theHarvester.lib.api import run_worker

    async def scenario() -> str:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import os; os.write(1, b"\\xff" * 120000); os.write(2, b"\\xfe" * 120000)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        output, _ = await asyncio.gather(run_worker._process_output(process), process.wait())
        return output

    output = asyncio.run(scenario())

    assert len(output.encode()) <= run_worker.MAX_CAPTURED_OUTPUT_BYTES
    assert '[stdout truncated' in output
    assert '[stderr truncated' in output


def test_output_reader_failure_cancels_its_sibling() -> None:
    from theHarvester.lib.api import run_worker

    sibling_finished = asyncio.Event()

    class FailingReader:
        @staticmethod
        async def read(_size):
            raise RuntimeError('reader failed')

    class WaitingReader:
        @staticmethod
        async def read(_size):
            try:
                await asyncio.Event().wait()
            finally:
                sibling_finished.set()

    async def scenario() -> None:
        process = type('Process', (), {'stdout': FailingReader(), 'stderr': WaitingReader()})()
        with pytest.raises(RuntimeError, match='reader failed'):
            await run_worker._process_output(process)
        assert sibling_finished.is_set()

    asyncio.run(scenario())


def test_worker_bounds_output_reader_after_process_exit(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker

    output_reader_finished = asyncio.Event()
    stored_logs = []

    class Store:
        database = tmp_path / 'runs.sqlite'

        @staticmethod
        def artifact_directory(_run_id):
            return tmp_path / 'artifacts'

        @staticmethod
        async def get(_run_id):
            return {'status': 'running'}

        @staticmethod
        async def fail(_run_id, _error, log, **_kwargs):
            stored_logs.append(log)

    async def process_factory(_run_id, _database, _artifact_dir):
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'pass',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def stuck_output(_process):
        try:
            await asyncio.Event().wait()
        finally:
            output_reader_finished.set()

    monkeypatch.setattr(run_worker, '_process_factory', process_factory)
    monkeypatch.setattr(run_worker, '_process_output', stuck_output)
    monkeypatch.setattr(run_worker, '_OUTPUT_DRAIN_SECONDS', 0.01)
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    async def scenario() -> None:
        await run_worker._execute_claimed(
            Store(),
            {'run_id': 'run-id', 'target': 'example.test', 'request': {'deadline_seconds': 60}},
        )
        assert output_reader_finished.is_set()
        assert stored_logs == ['[child output collection timed out and was truncated]']

    asyncio.run(scenario())


@pytest.mark.parametrize('stop_reason', ['cancellation', 'deadline'])
def test_early_stop_bounds_held_open_output_reader(tmp_path, monkeypatch, stop_reason) -> None:
    from theHarvester.lib.api import run_worker

    output_reader_finished = asyncio.Event()
    failures = []

    class Store:
        database = tmp_path / 'runs.sqlite'

        @staticmethod
        def artifact_directory(_run_id):
            return tmp_path / 'artifacts'

        @staticmethod
        async def get(_run_id):
            return {'status': 'cancelling' if stop_reason == 'cancellation' else 'running'}

        @staticmethod
        async def fail(_run_id, error, log, **kwargs):
            failures.append((error, log, kwargs))

    async def process_factory(_run_id, _database, _artifact_dir):
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import time; time.sleep(60)',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def stuck_output(_process):
        try:
            await asyncio.Event().wait()
        finally:
            output_reader_finished.set()

    monkeypatch.setattr(run_worker, '_process_factory', process_factory)
    monkeypatch.setattr(run_worker, '_process_output', stuck_output)
    monkeypatch.setattr(run_worker, '_OUTPUT_DRAIN_SECONDS', 0.01)
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    async def scenario() -> None:
        await asyncio.wait_for(
            run_worker._execute_claimed(
                Store(),
                {
                    'run_id': 'run-id',
                    'target': 'example.test',
                    'request': {'deadline_seconds': 0 if stop_reason == 'deadline' else 60},
                },
            ),
            timeout=1,
        )
        assert output_reader_finished.is_set()

    asyncio.run(scenario())

    assert len(failures) == 1
    assert failures[0][1] == '[child output collection timed out and was truncated]'
    assert bool(failures[0][2].get('cancelled')) is (stop_reason == 'cancellation')


def test_windows_forced_cleanup_uses_retained_job(monkeypatch) -> None:
    from theHarvester.lib.api import run_worker

    terminated = []
    process = type('Process', (), {'returncode': 0})()
    run_worker._process_jobs[process] = 42
    monkeypatch.setattr(run_worker.os, 'name', 'nt')
    monkeypatch.setattr(run_worker, '_terminate_windows_job', terminated.append)

    asyncio.run(run_worker._signal_process_tree(process, force=True))

    assert terminated == [42]
    run_worker._process_jobs.pop(process, None)


def test_windows_child_is_suspended_until_assigned_to_job(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker

    calls = []

    class Process:
        pid = 123

    async def create_process(*_args, **kwargs):
        calls.append(('create', kwargs['creationflags']))
        return Process()

    def assign(process_id):
        calls.append(('assign', process_id))
        return 42

    def resume(process_id):
        calls.append(('resume', process_id))

    monkeypatch.setattr(run_worker.os, 'name', 'nt')
    monkeypatch.setattr(run_worker.asyncio, 'create_subprocess_exec', create_process)
    monkeypatch.setattr(run_worker, '_assign_windows_job', assign)
    monkeypatch.setattr(run_worker, '_resume_windows_process', resume)

    process = asyncio.run(run_worker._default_process_factory('run-id', tmp_path / 'runs.sqlite', tmp_path))

    assert calls[0][0] == 'create'
    assert calls[0][1] & 0x4
    assert calls[1:] == [('assign', 123), ('resume', 123)]
    assert run_worker._process_jobs[process] == 42
    run_worker._process_jobs.pop(process, None)


@pytest.mark.parametrize('failure_stage', ['assignment', 'resume'])
def test_windows_startup_failure_reaps_child_without_masking_original(tmp_path, monkeypatch, failure_stage) -> None:
    from theHarvester.lib.api import run_worker

    calls = []

    class Process:
        pid = 123
        returncode = None

        def kill(self):
            calls.append('kill')

        async def wait(self):
            calls.append('wait')
            self.returncode = 1
            return 1

    async def create_process(*_args, **_kwargs):
        return Process()

    def assign(_process_id):
        calls.append('assign')
        if failure_stage == 'assignment':
            raise RuntimeError('assignment failed')
        return 42

    def resume(_process_id):
        calls.append('resume')
        raise RuntimeError('resume failed')

    def terminate(_job):
        calls.append('terminate')
        raise OSError('terminate failed')

    def close(_job):
        calls.append('close')
        raise OSError('close failed')

    monkeypatch.setattr(run_worker.os, 'name', 'nt')
    monkeypatch.setattr(run_worker.asyncio, 'create_subprocess_exec', create_process)
    monkeypatch.setattr(run_worker, '_assign_windows_job', assign)
    monkeypatch.setattr(run_worker, '_resume_windows_process', resume)
    monkeypatch.setattr(run_worker, '_terminate_windows_job', terminate)
    monkeypatch.setattr(run_worker, '_close_windows_job', close)

    with pytest.raises(RuntimeError, match=f'{failure_stage} failed'):
        asyncio.run(run_worker._default_process_factory('run-id', tmp_path / 'runs.sqlite', tmp_path))

    expected = ['assign']
    if failure_stage == 'resume':
        expected += ['resume', 'terminate', 'close']
    assert calls == [*expected, 'kill', 'wait']


@pytest.mark.parametrize('exit_mode', ['normal', 'exception', 'cancel'])
def test_windows_execution_cleanup_terminates_closes_and_forgets_job(tmp_path, monkeypatch, exit_mode) -> None:
    from theHarvester.lib.api import run_worker

    process_started = asyncio.Event()
    process_finished = asyncio.Event()
    terminated = []
    closed = []

    class Process:
        pid = 123
        returncode = 0 if exit_mode == 'normal' else None
        stdout = None
        stderr = None

        async def wait(self):
            if self.returncode is None:
                await process_finished.wait()
            return int(self.returncode or 0)

        def send_signal(self, _signal):
            self.returncode = -15
            process_finished.set()

        def kill(self):
            self.returncode = -9
            process_finished.set()

    process = Process()

    class Store:
        database = tmp_path / 'runs.sqlite'

        @staticmethod
        def artifact_directory(_run_id):
            return tmp_path / 'artifacts'

        @staticmethod
        async def get(_run_id):
            if exit_mode == 'exception':
                raise RuntimeError('database failed')
            return {'status': 'running'}

        @staticmethod
        async def finish(*_args, **_kwargs):
            return None

        @staticmethod
        async def fail(*_args, **_kwargs):
            return None

    async def process_factory(*_args):
        run_worker._process_jobs[process] = 42
        process_started.set()
        return process

    def terminate(job):
        terminated.append(job)
        process.returncode = -9
        process_finished.set()

    monkeypatch.setattr(run_worker.os, 'name', 'nt')
    monkeypatch.setattr(run_worker, '_process_factory', process_factory)
    monkeypatch.setattr(run_worker, '_terminate_windows_job', terminate)
    monkeypatch.setattr(run_worker, '_close_windows_job', closed.append)
    monkeypatch.setattr(run_worker, 'read_child_evidence', lambda *_args: ({'target': 'example.test'}, None))
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    async def scenario() -> None:
        task = asyncio.create_task(
            run_worker._execute_claimed(
                Store(),
                {'run_id': 'run-id', 'target': 'example.test', 'request': {'deadline_seconds': 60}},
            )
        )
        await process_started.wait()
        if exit_mode == 'cancel':
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif exit_mode == 'exception':
            with pytest.raises(RuntimeError, match='database failed'):
                await task
        else:
            await task

    asyncio.run(scenario())

    assert terminated == [42]
    assert closed == [42]
    assert process not in run_worker._process_jobs
    assert process not in run_worker._stopped_process_trees


def test_windows_runtime_cleanup_reaps_child_when_job_termination_fails(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker

    process_finished = asyncio.Event()
    calls = []

    class Process:
        pid = 123
        returncode = None
        stdout = None
        stderr = None

        async def wait(self):
            calls.append('wait')
            await process_finished.wait()
            calls.append('reaped')
            return int(self.returncode or 0)

        def send_signal(self, _signal):
            calls.append('signal')
            process_finished.set()

        def kill(self):
            calls.append('kill')
            self.returncode = -9
            process_finished.set()

    process = Process()

    class Store:
        database = tmp_path / 'runs.sqlite'

        @staticmethod
        def artifact_directory(_run_id):
            return tmp_path / 'artifacts'

        @staticmethod
        async def get(_run_id):
            raise RuntimeError('database failed')

        @staticmethod
        async def fail(*_args, **_kwargs):
            return None

    async def process_factory(*_args):
        run_worker._process_jobs[process] = 42
        return process

    def terminate(_job):
        calls.append('terminate')
        raise OSError('job termination failed')

    monkeypatch.setattr(run_worker.os, 'name', 'nt')
    monkeypatch.setattr(run_worker, '_process_factory', process_factory)
    monkeypatch.setattr(run_worker, '_terminate_windows_job', terminate)
    monkeypatch.setattr(run_worker, '_close_windows_job', lambda job: calls.append(('close', job)))
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    with pytest.raises(OSError, match='job termination failed'):
        asyncio.run(
            run_worker._execute_claimed(
                Store(),
                {'run_id': 'run-id', 'target': 'example.test', 'request': {'deadline_seconds': 60}},
            )
        )

    assert calls.count('kill') == 1
    assert calls.count('reaped') == 1
    assert calls.count(('close', 42)) == 1
    assert process not in run_worker._process_jobs
    assert process not in run_worker._stopped_process_trees


@pytest.mark.skipif(os.name == 'nt', reason='POSIX process-group regression')
def test_worker_reaps_process_group_when_leader_exits_with_inherited_output(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker

    grandchild_pid_path = tmp_path / 'grandchild.pid'
    helper_tasks: list[asyncio.Task] = []

    class Store:
        database = tmp_path / 'runs.sqlite'

        @staticmethod
        def artifact_directory(_run_id):
            return tmp_path / 'artifacts'

        @staticmethod
        async def get(_run_id):
            return {'status': 'running'}

        @staticmethod
        async def fail(*_args, **_kwargs):
            return None

    async def process_factory(_run_id, _database, _artifact_dir):
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            (
                'import pathlib, subprocess, sys; '
                'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); '
                f'pathlib.Path({str(grandchild_pid_path)!r}).write_text(str(child.pid))'
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        run_worker._process_groups[process] = process.pid
        return process

    original_create_task = asyncio.create_task

    def track_task(coroutine):
        task = original_create_task(coroutine)
        helper_tasks.append(task)
        return task

    monkeypatch.setattr(run_worker, '_process_factory', process_factory)
    monkeypatch.setattr(run_worker.asyncio, 'create_task', track_task)
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    async def scenario() -> None:
        await asyncio.wait_for(
            run_worker._execute_claimed(
                Store(),
                {'run_id': 'run-id', 'target': 'example.test', 'request': {'deadline_seconds': 60}},
            ),
            timeout=5,
        )
        grandchild_pid = int(grandchild_pid_path.read_text())

        def grandchild_stopped() -> bool:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(grandchild_pid, 0)
                except ProcessLookupError:
                    return True
                time.sleep(0.01)
            return False

        assert await asyncio.to_thread(grandchild_stopped)
        assert all(task.done() for task in helper_tasks)

    asyncio.run(scenario())


@pytest.mark.skipif(os.name == 'nt', reason='POSIX process-group regression')
def test_worker_cancellation_reaps_child_and_grandchild_process_group(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker

    grandchild_pid_path = tmp_path / 'grandchild.pid'
    leader = None

    class Store:
        database = tmp_path / 'runs.sqlite'

        @staticmethod
        def artifact_directory(_run_id):
            return tmp_path / 'artifacts'

        @staticmethod
        async def get(_run_id):
            return {'status': 'running'}

    async def process_factory(_run_id, _database, _artifact_dir):
        nonlocal leader
        leader = await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            (
                'import pathlib, subprocess, sys, time; '
                'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); '
                f'pathlib.Path({str(grandchild_pid_path)!r}).write_text(str(child.pid)); '
                'time.sleep(60)'
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        run_worker._process_groups[leader] = leader.pid
        return leader

    monkeypatch.setattr(run_worker, '_process_factory', process_factory)
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    async def scenario() -> None:
        task = asyncio.create_task(
            run_worker._execute_claimed(
                Store(),
                {'run_id': 'run-id', 'target': 'example.test', 'request': {'deadline_seconds': 60}},
            )
        )

        def grandchild_started() -> bool:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if grandchild_pid_path.exists():
                    return True
                time.sleep(0.01)
            return False

        assert await asyncio.to_thread(grandchild_started)
        grandchild_pid = int(grandchild_pid_path.read_text())
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        def process_tree_stopped() -> bool:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(grandchild_pid, 0)
                except ProcessLookupError:
                    return leader is not None and leader.returncode is not None
                time.sleep(0.01)
            return False

        assert await asyncio.to_thread(process_tree_stopped)

    asyncio.run(scenario())


@pytest.mark.parametrize('failure_stage', ['wait', 'finish', 'bookkeeping', 'task-creation'])
def test_worker_reaps_child_on_remaining_post_spawn_failures(tmp_path, monkeypatch, failure_stage) -> None:
    from theHarvester.lib.api import run_worker

    child = None
    original_wait = None

    class Store:
        database = tmp_path / 'runs.sqlite'

        @staticmethod
        def artifact_directory(_run_id):
            return tmp_path / 'artifacts'

        @staticmethod
        async def get(_run_id):
            return {'status': 'running'}

        @staticmethod
        async def finish(*_args, **_kwargs):
            if failure_stage == 'finish':
                raise RuntimeError('finish failed')

        @staticmethod
        async def fail(*_args, **_kwargs):
            return None

    class BrokenRequest(dict):
        def __getitem__(self, key):
            if failure_stage == 'bookkeeping' and key == 'deadline_seconds':
                raise RuntimeError('bookkeeping failed')
            return super().__getitem__(key)

    async def process_factory(_run_id, _database, _artifact_dir):
        nonlocal child, original_wait
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'import time; time.sleep(60)' if failure_stage != 'finish' else 'pass',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        original_wait = child.wait
        if failure_stage == 'wait':

            async def fail_wait():
                raise RuntimeError('wait failed')

            child.wait = fail_wait
        return child

    monkeypatch.setattr(run_worker, '_process_factory', process_factory)
    monkeypatch.setattr(run_worker, '_worker_stop', None)
    if failure_stage == 'finish':
        monkeypatch.setattr(run_worker, 'read_child_evidence', lambda *_args: ({'target': 'example.test'}, None))
    if failure_stage == 'task-creation':
        original_create_task = asyncio.create_task
        creation_calls = 0

        def fail_first_task(coroutine):
            nonlocal creation_calls
            creation_calls += 1
            if creation_calls == 1:
                coroutine.close()
                raise RuntimeError('task-creation failed')
            return original_create_task(coroutine)

        monkeypatch.setattr(run_worker.asyncio, 'create_task', fail_first_task)

    async def scenario() -> None:
        try:
            with pytest.raises(RuntimeError, match=failure_stage):
                await asyncio.wait_for(
                    run_worker._execute_claimed(
                        Store(),
                        {
                            'run_id': 'run-id',
                            'target': 'example.test',
                            'request': BrokenRequest(deadline_seconds=60),
                        },
                    ),
                    timeout=2,
                )
            assert child is not None
            if original_wait is not None:
                await asyncio.wait_for(original_wait(), timeout=1)
            assert child.returncode is not None
        finally:
            if child is not None and child.returncode is None:
                child.kill()
                if original_wait is not None:
                    await original_wait()

    asyncio.run(scenario())


def test_worker_rechecks_queue_after_clearing_wakeup(monkeypatch) -> None:
    from theHarvester.lib.api import run_worker

    claims = 0

    class Store:
        @staticmethod
        async def heartbeat_worker_lease(_owner_id):
            return True

        @staticmethod
        async def claim_next():
            nonlocal claims
            claims += 1
            if claims == 1:
                run_worker.wake_worker()
                return None
            return {'run_id': 'run-id'}

    async def execute(_store, _run, _owner_id):
        assert run_worker._worker_stop is not None
        run_worker._worker_stop.set()

    monkeypatch.setattr(run_worker, '_execute_claimed', execute)

    async def scenario() -> None:
        run_worker._worker_stop = asyncio.Event()
        run_worker._worker_wakeup = asyncio.Event()
        try:
            await asyncio.wait_for(run_worker._worker_loop(Store(), 'worker-id'), timeout=0.1)
        finally:
            run_worker._worker_stop = None
            run_worker._worker_wakeup = None

    asyncio.run(scenario())

    assert claims == 2


def test_submission_fails_closed_when_worker_supervisor_stops(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(run_worker, 'worker_enabled', lambda: True)
    monkeypatch.setattr(run_worker, '_worker_task', type('StoppedTask', (), {'done': lambda self: True})())

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': 'example.com', 'sources': ['crtsh']},
        )
        history = client.get('/api/v1/runs', headers={'X-API-Key': 'test-key'})

    assert response.status_code == 503
    assert response.json()['detail'] == 'theHarvester execution worker is unavailable'
    assert history.json() == []


def test_authenticated_operator_can_queue_direct_activity_for_selected_target(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(run_worker, 'worker_enabled', lambda: True)
    monkeypatch.setattr(run_worker, '_worker_task', type('RunningTask', (), {'done': lambda self: False})())

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': '192.0.2.8', 'sources': ['criminalip']},
        )

    assert response.status_code == 201
    assert response.json()['target'] == '192.0.2.8'
    assert response.json()['activities'] == ['P2']


def test_authenticated_operator_can_queue_screenshot_only_run(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(run_worker, 'worker_enabled', lambda: True)
    monkeypatch.setattr(run_worker, '_worker_task', type('RunningTask', (), {'done': lambda self: False})())

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': 'api.example.com', 'sources': [], 'screenshot': True},
        )

    assert response.status_code == 201
    assert response.json()['target'] == 'api.example.com'
    assert response.json()['sources'] == []
    assert response.json()['activities'] == ['P2']


def test_authenticated_operator_can_queue_routeviews_only_ip_run(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(run_worker, 'worker_enabled', lambda: True)
    monkeypatch.setattr(run_worker, '_worker_task', type('RunningTask', (), {'done': lambda self: False})())

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={'target': '192.0.2.7', 'sources': [], 'routeviews': True},
        )

    assert response.status_code == 201
    assert response.json()['activities'] == ['P0']
    assert response.json()['request']['routeviews'] is True


def test_dns_brute_run_accepts_operator_resolver_list(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

    async def no_op() -> None:
        return None

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setattr(api, 'start_worker', no_op)
    monkeypatch.setattr(api, 'stop_worker', no_op)
    monkeypatch.setattr(run_worker, 'worker_enabled', lambda: True)
    monkeypatch.setattr(run_worker, '_worker_task', type('RunningTask', (), {'done': lambda self: False})())

    with TestClient(api.app) as client:
        response = client.post(
            '/api/v1/runs',
            headers={'X-API-Key': 'test-key'},
            json={
                'target': 'dev.api.example.com',
                'sources': [],
                'dns_brute': True,
                'dns_resolvers': ['192.0.2.53'],
            },
        )

    assert response.status_code == 201
    assert response.json()['activities'] == ['P1']
    assert response.json()['request']['dns_resolvers'] == ['192.0.2.53']


def test_dns_brute_child_uses_operator_resolver_list(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_options = []

    async def fake_start(options, **_kwargs):
        received_options.append(options)
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(
            RunRequest(
                target='dev.api.example.com',
                sources=[],
                dns_brute=True,
                dns_resolvers=['192.0.2.53'],
            )
        )
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_options[0].source == ''
    assert received_options[0].dns_brute is True
    assert received_options[0].dns_resolve == ''
    assert received_options[0].dns_resolvers == ('192.0.2.53',)


def test_routeviews_child_receives_explicit_action_without_source_limit_controls(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_options = []

    async def fake_start(options, **_kwargs):
        received_options.append(options)
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(RunRequest(target='192.0.2.7', sources=[], routeviews=True, limit=9_999))
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_options[0].source == ''
    assert received_options[0].routeviews is True
    assert received_options[0].limit == 9_999


@pytest.mark.parametrize(
    ('field', 'value', 'option'),
    [
        ('shodan', True, '--shodan'),
        ('dns_resolve', True, '--dns-resolve'),
        ('dns_lookup', True, '--dns-lookup'),
        ('dns_brute', True, '--dns-brute'),
        ('dns_recursive_depth', 1, '--dns-recursive-depth'),
        ('takeover', True, '--take-over'),
        ('screenshot', True, '--screenshot'),
        ('vhost', True, '--vhost'),
    ],
)
def test_no_hosts_rejects_hostname_dependent_actions(field: str, value: object, option: str) -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    with pytest.raises(ValidationError, match=rf'--no-hosts cannot be combined with: {option}'):
        RunRequest(target='example.test', sources=['bufferoverun'], no_hosts=True, **{field: value})


def test_no_hosts_allows_target_only_api_scan() -> None:
    from theHarvester.lib.api.run_models import RunRequest

    request = RunRequest(target='example.test', sources=[], no_hosts=True, api_scan=True)

    assert request.no_hosts is True
    assert request.api_scan is True


def test_no_hosts_conflict_precedes_virtual_host_input_validation() -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    with pytest.raises(ValidationError, match=r'--no-hosts cannot be combined with: --vhost'):
        RunRequest(target='example.test', sources=[], no_hosts=True, vhost=True)


def test_no_hosts_child_preserves_the_run_request(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_options = []

    async def fake_start(options, **_kwargs):
        received_options.append(options)
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(RunRequest(target='example.test', sources=['bufferoverun'], no_hosts=True))
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_options[0].source == 'bufferoverun'
    assert received_options[0].no_hosts is True


def test_virtual_host_request_normalizes_a_self_contained_target_action() -> None:
    from pydantic import ValidationError

    from theHarvester.lib.api.run_models import RunRequest

    request = RunRequest(
        target='Example.Test.',
        sources=[],
        vhost_endpoint='https://192.0.2.8',
        vhost_candidates=['ADMIN.Example.Test.'],
    )

    assert request.vhost is True
    assert request.vhost_endpoint == 'https://192.0.2.8:443/'
    assert request.vhost_candidates == ['admin.example.test']
    assert (
        RunRequest(
            target='example.test',
            sources=['crtsh'],
            vhost_endpoint='http://192.0.2.9',
        ).vhost
        is True
    )
    assert (
        RunRequest(
            target='example.test',
            sources=['crtsh'],
            vhost_candidates=['admin.example.test'],
        ).vhost
        is True
    )
    with pytest.raises(ValidationError, match='discovery source'):
        RunRequest(target='example.test', sources=[], vhost_endpoint='https://192.0.2.8')
    with pytest.raises(ValidationError, match='discovery source'):
        RunRequest(target='example.test', sources=[], vhost_candidates=['admin.example.test'])
    with pytest.raises(ValidationError, match='discovery source'):
        RunRequest(target='example.test', sources=[], vhost=True)
    with pytest.raises(ValidationError, match='hostname target'):
        RunRequest(target='192.0.2.8', sources=['crtsh'], vhost=True)
    with pytest.raises(ValidationError, match='direct transport'):
        RunRequest(target='example.test', sources=['crtsh'], vhost=True, proxies=True)


def test_virtual_host_child_receives_bounded_controls_and_persistence_identity(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    captured = None
    captured_database = None
    captured_run_id = None

    async def fake_start(options, **kwargs):
        nonlocal captured, captured_database, captured_run_id
        captured = options
        captured_database = kwargs.get('result_database')
        captured_run_id = kwargs.get('completed_run_id')
        now = datetime.now(UTC)
        return (
            CompletedResult.finish(
                run_id=captured_run_id,
                target=options.domain,
                started_at=now,
                completed_at=now,
                groups={},
            ),
        )

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> tuple[Path, str]:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(
            RunRequest(
                target='example.test',
                sources=[],
                vhost_endpoint='https://192.0.2.8',
                vhost_candidates=['admin.example.test'],
                vhost_request_limit=12,
                vhost_runtime_seconds=9,
                vhost_timeout_seconds=2,
                vhost_concurrency=1,
                vhost_insecure=True,
            )
        )
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)
        return store.database, created['run_id']

    database, run_id = asyncio.run(scenario())

    assert captured is not None
    assert captured.vhost is True
    assert captured.vhost_endpoint == 'https://192.0.2.8:443/'
    assert captured.vhost_candidates == ('admin.example.test',)
    assert captured.vhost_request_limit == 12
    assert captured.vhost_runtime_seconds == 9
    assert captured.vhost_timeout_seconds == 2
    assert captured.vhost_concurrency == 1
    assert captured.vhost_insecure is True
    assert captured_database == database
    assert str(captured_run_id) == run_id


def test_api_scan_child_uses_operator_endpoint_paths(tmp_path, monkeypatch) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore
    from theHarvester.lib.completed_result import CompletedResult

    received_wordlists: list[Path] = []

    async def fake_start(options, **_kwargs):
        received_wordlists.append(Path(options.wordlist))
        now = datetime.now(UTC)
        return (CompletedResult.finish(target=options.domain, started_at=now, completed_at=now, groups={}),)

    monkeypatch.setattr(main_module, 'start', fake_start)

    async def scenario() -> None:
        store = RunStore(tmp_path / 'runs.sqlite')
        created = await store.create(
            RunRequest(
                target='api.example.test',
                sources=[],
                api_scan=True,
                api_scan_paths=['/api/v2', '/health'],
            )
        )
        assert await store.claim_next() is not None
        await run_worker._child_execute(created['run_id'], store.database)

    asyncio.run(scenario())

    assert received_wordlists[0].read_text(encoding='utf-8') == '/api/v2\n/health\n'


def test_running_cancellation_terminates_child_and_retains_partial_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, run_worker

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'enabled')

    async def slow_process(_run_id, _database, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {
                    'target': 'example.test',
                    'status': 'partial',
                    'results': [{'type': 'email', 'value': 'saved@example.test'}],
                }
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

    monkeypatch.setattr(run_worker, '_process_factory', slow_process)
    headers = {'X-API-Key': 'test-key'}
    with TestClient(api.app) as client:
        submitted = client.post(
            '/api/v1/runs',
            headers=headers,
            json={'target': 'example.test', 'sources': ['crtsh'], 'deadline_seconds': 60},
        ).json()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            detail = client.get(f'/api/v1/runs/{submitted["run_id"]}', headers=headers).json()
            if detail['status'] == 'running':
                break
            time.sleep(0.02)
        requested = client.post(f'/api/v1/runs/{submitted["run_id"]}/cancel', headers=headers)
        while time.monotonic() < deadline:
            detail = client.get(f'/api/v1/runs/{submitted["run_id"]}', headers=headers).json()
            if detail['status'] == 'cancelled':
                break
            time.sleep(0.02)

    assert requested.json()['status'] == 'cancelling'
    assert detail['status'] == 'cancelled'
    assert detail['completed_at'] is not None
    assert detail['evidence_status'] == 'partial'
    assert detail['results'] == [{'type': 'email', 'value': 'saved@example.test', 'sources': [], 'actions': []}]


def test_whole_run_deadline_terminates_child_and_retains_partial_evidence(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    async def slow_process(_run_id, _database, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {
                    'target': 'example.test',
                    'status': 'partial',
                    'results': [{'type': 'email', 'value': 'saved@example.test'}],
                }
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

    monkeypatch.setattr(run_worker, '_process_factory', slow_process)

    async def scenario():
        store = RunStore()
        await store.create(RunRequest(target='example.test', sources=['crtsh']))
        run = await store.claim_next()
        assert run is not None
        run['request']['deadline_seconds'] = 0
        await run_worker._execute_claimed(store, run)
        return await store.get(run['run_id'])

    detail = asyncio.run(scenario())

    assert detail is not None
    assert detail['status'] == 'failed'
    assert 'deadline' in detail['error']
    assert detail['evidence_status'] == 'partial'
    assert detail['results'] == [{'type': 'email', 'value': 'saved@example.test', 'sources': [], 'actions': []}]


def test_worker_fails_run_without_attaching_child_evidence_for_another_target(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import run_worker
    from theHarvester.lib.api.run_models import RunRequest
    from theHarvester.lib.api.run_store import RunStore

    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(run_worker, '_worker_stop', None)

    async def mismatched_process(_run_id, _database, artifact_dir):
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / 'evidence.json').write_text(
            json.dumps(
                {
                    'target': 'different.example',
                    'status': 'complete',
                    'results': [{'type': 'email', 'value': 'saved@different.example'}],
                }
            ),
            encoding='utf-8',
        )
        return await asyncio.create_subprocess_exec(
            sys.executable,
            '-c',
            'pass',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    monkeypatch.setattr(run_worker, '_process_factory', mismatched_process)

    async def scenario():
        store = RunStore(tmp_path / 'runs.sqlite')
        await store.create(RunRequest(target='expected.example', sources=['crtsh']))
        run = await store.claim_next()
        assert run is not None
        await run_worker._execute_claimed(store, run)
        return await store.get(run['run_id'])

    detail = asyncio.run(scenario())

    assert detail is not None
    assert detail['status'] == 'failed'
    assert detail['results'] == []
    assert 'does not match run target' in detail['error']

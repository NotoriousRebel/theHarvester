from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4
from weakref import WeakKeyDictionary, WeakSet

import anyio

from theHarvester.lib.enumeration import (
    DEFAULT_RESULT_START,
    DEFAULT_SOURCE_WORKERS,
    EnumerationOptions,
)
from theHarvester.lib.resolver_selection import DEFAULT_DNS_RESOLVERS
from theHarvester.lib.virtual_host import (
    DEFAULT_VHOST_CONCURRENCY,
    DEFAULT_VHOST_REQUEST_LIMIT,
    DEFAULT_VHOST_RUNTIME_SECONDS,
    DEFAULT_VHOST_TIMEOUT_SECONDS,
)

from .run_artifacts import (
    ensure_private_directory,
    read_child_evidence,
    serialize_child_evidence,
    write_child_evidence_payload,
)
from .run_store import RunStore

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

_worker_task: asyncio.Task[None] | None = None
_worker_stop: asyncio.Event | None = None
_worker_wakeup: asyncio.Event | None = None
_worker_owner: str | None = None
_process_groups: WeakKeyDictionary[asyncio.subprocess.Process, int] = WeakKeyDictionary()
_process_jobs: WeakKeyDictionary[asyncio.subprocess.Process, int] = WeakKeyDictionary()
_stopped_process_trees: WeakSet[asyncio.subprocess.Process] = WeakSet()
MAX_CAPTURED_OUTPUT_BYTES = 200_000
_MAX_CAPTURED_STREAM_BYTES = 99_900
_OUTPUT_READ_BYTES = 64 * 1024
_OUTPUT_DRAIN_SECONDS = 2
_OUTPUT_TIMEOUT_MARKER = '[child output collection timed out and was truncated]'


def _assign_windows_job(process_id: int) -> int:
    import ctypes
    from ctypes import wintypes

    kernel32 = vars(ctypes)['WinDLL']('kernel32', use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise vars(ctypes)['WinError'](vars(ctypes)['get_last_error']())
    process_handle = kernel32.OpenProcess(0x0101, False, process_id)
    if not process_handle:
        kernel32.CloseHandle(job)
        raise vars(ctypes)['WinError'](vars(ctypes)['get_last_error']())
    try:
        if not kernel32.AssignProcessToJobObject(job, process_handle):
            raise vars(ctypes)['WinError'](vars(ctypes)['get_last_error']())
    except BaseException:
        kernel32.CloseHandle(job)
        raise
    finally:
        kernel32.CloseHandle(process_handle)
    return int(job)


def _terminate_windows_job(job: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = vars(ctypes)['WinDLL']('kernel32', use_last_error=True)
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    if not kernel32.TerminateJobObject(job, 1):
        error = vars(ctypes)['get_last_error']()
        if error != 6:  # The handle may already be closed by completed cleanup.
            raise vars(ctypes)['WinError'](error)


def _resume_windows_process(process_id: int) -> None:
    import ctypes
    from ctypes import wintypes

    windows = vars(ctypes)
    kernel32 = windows['WinDLL']('kernel32', use_last_error=True)
    ntdll = windows['WinDLL']('ntdll')
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    ntdll.NtResumeProcess.restype = wintypes.LONG
    process_handle = kernel32.OpenProcess(0x0800, False, process_id)
    if not process_handle:
        raise windows['WinError'](windows['get_last_error']())
    try:
        status = ntdll.NtResumeProcess(process_handle)
        if status != 0:
            raise OSError(f'NtResumeProcess failed with status {status:#x}')
    finally:
        kernel32.CloseHandle(process_handle)


def _close_windows_job(job: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = vars(ctypes)['WinDLL']('kernel32', use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not kernel32.CloseHandle(job):
        error = vars(ctypes)['get_last_error']()
        if error != 6:
            raise vars(ctypes)['WinError'](error)


def worker_enabled() -> bool:
    return os.getenv('THEHARVESTER_RUN_WORKER', 'enabled').casefold() != 'disabled'


def worker_available() -> bool:
    return _worker_task is not None and not _worker_task.done()


async def _default_process_factory(run_id: str, database: Path, _artifact_dir_path: Path) -> asyncio.subprocess.Process:
    command = (
        sys.executable,
        '-m',
        'theHarvester.lib.api.run_worker',
        '--execute',
        run_id,
        '--database',
        str(database),
    )
    if os.name == 'nt':
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x200) | getattr(subprocess, 'CREATE_SUSPENDED', 0x4),
        )
    else:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    if process.pid is None:
        process.kill()
        await process.wait()
        raise RuntimeError('Child process started without a process identifier')
    process_job = None
    try:
        if os.name == 'nt':
            process_job = _assign_windows_job(process.pid)
            _resume_windows_process(process.pid)
            _process_jobs[process] = process_job
        else:
            _process_groups[process] = process.pid
    except BaseException:
        if process_job is not None:
            try:
                _terminate_windows_job(process_job)
            except BaseException:
                pass
            try:
                _close_windows_job(process_job)
            except BaseException:
                pass
        try:
            if process.returncode is None:
                process.kill()
        except BaseException:
            pass
        try:
            await process.wait()
        except BaseException:
            pass
        raise
    return process


_process_factory: Callable[[str, Path, Path], Awaitable[asyncio.subprocess.Process]] = _default_process_factory


async def _process_output(process: asyncio.subprocess.Process) -> str:
    async def read(name: str, stream: asyncio.StreamReader | None) -> str:
        if stream is None:
            return ''
        captured = bytearray()
        truncated = False
        while chunk := await stream.read(_OUTPUT_READ_BYTES):
            remaining = _MAX_CAPTURED_STREAM_BYTES - len(captured)
            if remaining > 0:
                captured.extend(chunk[:remaining])
            truncated = truncated or len(chunk) > remaining
        output = captured.decode('utf-8', errors='replace').strip()
        encoded = output.encode()
        truncated = truncated or len(encoded) > _MAX_CAPTURED_STREAM_BYTES
        if truncated:
            marker = f'[{name} truncated: {_MAX_CAPTURED_STREAM_BYTES}-byte log budget]'
            content_budget = _MAX_CAPTURED_STREAM_BYTES - len(marker.encode()) - 1
            output = encoded[:content_budget].decode('utf-8', errors='ignore').strip()
            output = f'{output}\n{marker}' if output else marker
        return output

    readers = [
        asyncio.create_task(read('stdout', process.stdout)),
        asyncio.create_task(read('stderr', process.stderr)),
    ]
    try:
        stdout, stderr = await asyncio.gather(*readers)
    finally:
        for reader in readers:
            if not reader.done():
                reader.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
    return '\n'.join(part for part in (stdout, stderr) if part).strip()


async def _signal_process_tree(process: asyncio.subprocess.Process, *, force: bool) -> None:
    process_job = _process_jobs.get(process)
    if process_job is not None and os.name == 'nt':
        if force:
            await asyncio.to_thread(_terminate_windows_job, process_job)
        elif process.returncode is None:
            try:
                process.send_signal(getattr(signal, 'CTRL_BREAK_EVENT', 1))
            except ProcessLookupError:
                pass
        return
    process_group = _process_groups.get(process)
    if process_group is not None and os.name != 'nt':
        try:
            os.killpg(process_group, signal.SIGKILL if force else signal.SIGTERM)
        except ProcessLookupError:
            pass
        return
    if process_group is not None and os.name == 'nt':
        if force:
            killer = await asyncio.create_subprocess_exec(
                'taskkill',
                '/PID',
                str(process.pid),
                '/T',
                '/F',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
        else:
            try:
                process.send_signal(getattr(signal, 'CTRL_BREAK_EVENT', 1))
            except ProcessLookupError:
                pass
        return
    try:
        process.kill() if force else process.terminate()
    except ProcessLookupError:
        pass


async def _stop_process(process: asyncio.subprocess.Process, wait_task: asyncio.Task[int]) -> None:
    if process in _stopped_process_trees:
        await wait_task
        return
    owns_process_tree = process in _process_groups or process in _process_jobs
    cleanup_error: BaseException | None = None
    try:
        if process.returncode is None or owns_process_tree:
            await _signal_process_tree(process, force=False)
    except BaseException as error:
        cleanup_error = error
    try:
        await asyncio.wait_for(asyncio.shield(wait_task), timeout=2)
    except TimeoutError:
        pass
    except BaseException as error:
        cleanup_error = cleanup_error or error
    if process.returncode is None or owns_process_tree:
        try:
            await _signal_process_tree(process, force=True)
        except BaseException as error:
            cleanup_error = cleanup_error or error
            try:
                if process.returncode is None:
                    process.kill()
            except ProcessLookupError:
                pass
            except BaseException as kill_error:
                cleanup_error = cleanup_error or kill_error
        _stopped_process_trees.add(process)
    try:
        await wait_task
    except BaseException as error:
        cleanup_error = cleanup_error or error
    if cleanup_error is not None:
        raise cleanup_error


async def _finish_output(
    process: asyncio.subprocess.Process,
    wait_task: asyncio.Task[int],
    output_task: asyncio.Task[str],
) -> str:
    await _stop_process(process, wait_task)
    try:
        return await asyncio.wait_for(asyncio.shield(output_task), timeout=_OUTPUT_DRAIN_SECONDS)
    except TimeoutError:
        output_task.cancel()
        await asyncio.gather(output_task, return_exceptions=True)
        return _OUTPUT_TIMEOUT_MARKER


async def _execute_claimed(store: RunStore, run: dict[str, Any], owner_id: str | None = None) -> None:
    run_id = run['run_id']
    artifact_dir = store.artifact_directory(run_id)
    await asyncio.to_thread(ensure_private_directory, artifact_dir)
    try:
        process = await _process_factory(run_id, store.database, artifact_dir)
    except (OSError, RuntimeError) as error:
        await store.fail(run_id, f'Could not start child process: {error}', '')
        return
    try:
        wait_task: asyncio.Task[int] | None = None
        output_task: asyncio.Task[str] | None = None
        wait_task = asyncio.create_task(process.wait())
        output_task = asyncio.create_task(_process_output(process))
        deadline = asyncio.get_running_loop().time() + int(run['request']['deadline_seconds'])
        next_heartbeat = 0.0
        while process.returncode is None and not wait_task.done():
            await asyncio.sleep(0.05)
            if output_task.done():
                output_task.result()
            if owner_id is not None and asyncio.get_running_loop().time() >= next_heartbeat:
                if not await store.heartbeat_worker_lease(owner_id):
                    log = await _finish_output(process, wait_task, output_task)
                    await store.fail(run_id, 'Worker lost its execution lease', log)
                    return
                next_heartbeat = asyncio.get_running_loop().time() + 5
            current = await store.get(run_id)
            stopping = _worker_stop is not None and _worker_stop.is_set()
            if current is not None and current['status'] == 'cancelling':
                log = await _finish_output(process, wait_task, output_task)
                evidence, evidence_error = await asyncio.to_thread(read_child_evidence, artifact_dir, str(run['target']))
                failure_message = 'Cancelled by operator' + (f'; {evidence_error}' if evidence_error else '')
                await store.fail(run_id, failure_message, log, cancelled=True, evidence=evidence)
                return
            if stopping:
                log = await _finish_output(process, wait_task, output_task)
                evidence, evidence_error = await asyncio.to_thread(read_child_evidence, artifact_dir, str(run['target']))
                failure_message = 'theHarvester stopped before child completion' + (
                    f'; {evidence_error}' if evidence_error else ''
                )
                await store.fail(run_id, failure_message, log, evidence=evidence)
                return
            if asyncio.get_running_loop().time() >= deadline:
                log = await _finish_output(process, wait_task, output_task)
                evidence, evidence_error = await asyncio.to_thread(read_child_evidence, artifact_dir, str(run['target']))
                failure_message = f'Run exceeded its {run["request"]["deadline_seconds"]} second deadline'
                if evidence_error:
                    failure_message += f'; {evidence_error}'
                await store.fail(
                    run_id,
                    failure_message,
                    log,
                    evidence=evidence,
                )
                return
        if wait_task.done():
            wait_task.result()
        log = await _finish_output(process, wait_task, output_task)
        current = await store.get(run_id)
        evidence, evidence_error = await asyncio.to_thread(read_child_evidence, artifact_dir, str(run['target']))
        if evidence_error:
            await store.fail(
                run_id,
                evidence_error,
                log,
                cancelled=current is not None and current['status'] == 'cancelling',
            )
            return
        if current is not None and current['status'] == 'cancelling':
            await store.finish(run_id, evidence, log)
        elif process.returncode == 0 and evidence is not None:
            await store.finish(run_id, evidence, log)
        else:
            await store.fail(
                run_id,
                f'Child process exited with status {process.returncode} without terminal completion',
                log,
                evidence=evidence,
            )
    finally:

        async def cleanup() -> None:
            cleanup_wait_task = wait_task or asyncio.get_running_loop().create_task(process.wait())
            try:
                await _stop_process(process, cleanup_wait_task)
            finally:
                helpers = [task for task in (cleanup_wait_task, output_task) if task is not None]
                for task in helpers:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*helpers, return_exceptions=True)
                process_job = _process_jobs.pop(process, None)
                if process_job is not None:
                    await asyncio.to_thread(_close_windows_job, process_job)
                _stopped_process_trees.discard(process)

        cleanup_task = asyncio.create_task(cleanup())
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            await cleanup_task
            raise


async def _worker_loop(store: RunStore, owner_id: str) -> None:
    assert _worker_stop is not None
    assert _worker_wakeup is not None
    while not _worker_stop.is_set():
        if not await store.heartbeat_worker_lease(owner_id):
            return
        run = await store.claim_next()
        if run is not None:
            await _execute_claimed(store, run, owner_id)
            continue
        _worker_wakeup.clear()
        run = await store.claim_next()
        if run is not None:
            await _execute_claimed(store, run, owner_id)
            continue
        try:
            await asyncio.wait_for(_worker_wakeup.wait(), timeout=0.5)
        except TimeoutError:
            continue


async def _supervise_worker(store: RunStore, owner_id: str) -> None:
    assert _worker_stop is not None
    assert _worker_wakeup is not None
    while not _worker_stop.is_set():
        if await store.acquire_worker_lease(owner_id):
            try:
                await store.recover_orphans()
            except BaseException:
                await store.release_worker_lease(owner_id)
                raise
            await _worker_loop(store, owner_id)
            return
        _worker_wakeup.clear()
        try:
            await asyncio.wait_for(_worker_wakeup.wait(), timeout=0.5)
        except TimeoutError:
            continue


async def start_worker() -> None:
    global _worker_owner, _worker_stop, _worker_task, _worker_wakeup
    if not worker_enabled():
        return
    if _worker_task is not None and not _worker_task.done():
        return
    store = RunStore()
    owner_id = str(uuid4())
    _worker_owner = owner_id
    _worker_stop = asyncio.Event()
    _worker_wakeup = asyncio.Event()
    _worker_task = asyncio.create_task(_supervise_worker(store, owner_id))


async def stop_worker() -> None:
    global _worker_owner, _worker_stop, _worker_task, _worker_wakeup
    task = _worker_task
    owner_id = _worker_owner
    try:
        if task is not None:
            if _worker_stop is not None:
                _worker_stop.set()
            if _worker_wakeup is not None:
                _worker_wakeup.set()
            await task
    finally:
        try:
            if owner_id is not None:
                await RunStore().release_worker_lease(owner_id)
        finally:
            _worker_task = None
            _worker_owner = None
            _worker_stop = None
            _worker_wakeup = None


def wake_worker() -> None:
    if _worker_wakeup is not None:
        _worker_wakeup.set()


async def _child_execute(run_id: str, database: Path) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.completed_result import CompletedResult

    store = RunStore(database)
    run = await store.get(run_id)
    if run is None or run['status'] not in {'running', 'cancelling'}:
        raise RuntimeError('theHarvester run is not executable')
    request = run['request']
    artifact_dir = store.artifact_directory(run_id)
    await asyncio.to_thread(ensure_private_directory, artifact_dir)
    screenshot_dir = artifact_dir / 'screenshots'
    if request.get('screenshot'):
        await asyncio.to_thread(ensure_private_directory, screenshot_dir)
    recursive_depth = request.get('dns_recursive_depth', 0)
    resolver_list = request.get('dns_resolvers', list(DEFAULT_DNS_RESOLVERS))
    api_scan_wordlist = ''
    if request.get('api_scan_paths'):
        api_scan_wordlist_path = artifact_dir / 'api-scan-paths.txt'
        await anyio.Path(api_scan_wordlist_path).write_text(
            ''.join(f'{path}\n' for path in request['api_scan_paths']),
            encoding='utf-8',
        )
        api_scan_wordlist = str(api_scan_wordlist_path)
    args = EnumerationOptions(
        api_scan=request.get('api_scan', False),
        dns_brute=request.get('dns_brute', False),
        dns_lookup=request.get('dns_lookup', False),
        dns_recursive_depth=recursive_depth,
        dns_recursive_query_limit=request.get('dns_recursive_query_limit'),
        dns_recursive_runtime_seconds=request.get('dns_recursive_runtime_seconds'),
        dns_resolve=','.join(resolver_list) if request.get('dns_resolve') else '',
        dns_resolvers=tuple(resolver_list),
        dns_server=None,
        domain=run['target'],
        filename='',
        limit=request['limit'],
        no_hosts=request.get('no_hosts', False),
        proxies=request.get('proxies', False),
        quiet=True,
        routeviews=request.get('routeviews', False),
        screenshot=str(screenshot_dir) if request.get('screenshot') else '',
        shodan=request.get('shodan', False),
        source=','.join(request['sources']),
        source_workers=request.get('source_workers', DEFAULT_SOURCE_WORKERS),
        start=request.get('start', DEFAULT_RESULT_START),
        take_over=request.get('takeover', False),
        vhost=request.get('vhost', False),
        vhost_candidates=tuple(request.get('vhost_candidates', ())),
        vhost_concurrency=request.get('vhost_concurrency', DEFAULT_VHOST_CONCURRENCY),
        vhost_endpoint=request.get('vhost_endpoint', ''),
        vhost_insecure=request.get('vhost_insecure', False),
        vhost_request_limit=request.get('vhost_request_limit', DEFAULT_VHOST_REQUEST_LIMIT),
        vhost_runtime_seconds=request.get('vhost_runtime_seconds', DEFAULT_VHOST_RUNTIME_SECONDS),
        vhost_timeout_seconds=request.get('vhost_timeout_seconds', DEFAULT_VHOST_TIMEOUT_SECONDS),
        wordlist=api_scan_wordlist,
    )
    checkpoint_lock = asyncio.Lock()

    async def checkpoint(evidence: CompletedResult) -> None:
        payload = await asyncio.to_thread(serialize_child_evidence, evidence, partial=True)
        async with checkpoint_lock:
            await asyncio.to_thread(write_child_evidence_payload, artifact_dir, payload)

    task = asyncio.create_task(
        main_module.start(
            args,
            completed_result_checkpoint=checkpoint,
            return_completed_result=True,
            result_database=database,
            completed_run_id=UUID(run_id),
        )
    )
    loop = asyncio.get_running_loop()
    signal_handler_installed = False
    if os.name != 'nt':
        try:
            loop.add_signal_handler(signal.SIGTERM, task.cancel)
            signal_handler_installed = True
        except (NotImplementedError, RuntimeError):
            pass
    try:
        response = await task
    except asyncio.CancelledError:
        return
    finally:
        if signal_handler_installed:
            loop.remove_signal_handler(signal.SIGTERM)
    evidence = response[-1]
    if not isinstance(evidence, CompletedResult):
        raise RuntimeError('theHarvester did not return terminal evidence')
    payload = await asyncio.to_thread(serialize_child_evidence, evidence, partial=False)
    async with checkpoint_lock:
        await asyncio.to_thread(write_child_evidence_payload, artifact_dir, payload)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--execute', required=True)
    parser.add_argument('--database', required=True, type=Path)
    child_args = parser.parse_args()
    asyncio.run(_child_execute(child_args.execute, child_args.database))

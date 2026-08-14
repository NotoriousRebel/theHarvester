#!/usr/bin/env python3
"""Offline benchmark using the production source runner and standard-library scripted adapters."""

from __future__ import annotations

import argparse
import asyncio
import heapq
import json
import math
import random
import statistics
import sys
import time
import tracemalloc
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Sequence

NEAR_PLATEAU_RATIO = 0.95
RESOURCE_PRESSURE_RATIO = 1.5
CANCELLATION_LATENCY_RATIO = 2.0
DEFAULT_CANDIDATES = (5, 6, 7, 8)
DEFAULT_REPEATS = 9
DEFAULT_SCALE = 0.05
DEFAULT_SEED = 289


class Execution(NamedTuple):
    source: str
    duration_ms: float
    result_count: int
    status: str
    error_type: str | None
    pressure_limit: int | None
    pressure_error: str | None
    memory_bytes: int


class HTTP429Error(RuntimeError):
    pass


class HTTP503Error(RuntimeError):
    pass


class DNSResolverError(RuntimeError):
    pass


_SCRIPTED_ERRORS: dict[str, type[Exception]] = {
    'DNSResolverError': DNSResolverError,
    'HTTP429Error': HTTP429Error,
    'HTTP503Error': HTTP503Error,
    'TimeoutError': TimeoutError,
}


def _execution(value: dict[str, Any]) -> Execution:
    source = value.get('source')
    duration_ms = value.get('duration_ms')
    result_count = value.get('result_count')
    status = value.get('status')
    error_type = value.get('error_type')
    pressure_limit = value.get('pressure_limit')
    pressure_error = value.get('pressure_error')
    memory_bytes = value.get('memory_bytes', 0)
    if (
        not isinstance(source, str)
        or not source.strip()
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, (int, float))
        or not math.isfinite(duration_ms)
        or duration_ms < 0
        or isinstance(result_count, bool)
        or not isinstance(result_count, int)
        or result_count < 0
        or not isinstance(status, str)
        or not status.strip()
        or (error_type is not None and not isinstance(error_type, str))
        or (
            pressure_limit is not None
            and (isinstance(pressure_limit, bool) or not isinstance(pressure_limit, int) or pressure_limit <= 0)
        )
        or (pressure_error is not None and pressure_error not in _SCRIPTED_ERRORS)
        or (pressure_error is None) != (pressure_limit is None)
        or isinstance(memory_bytes, bool)
        or not isinstance(memory_bytes, int)
        or memory_bytes < 0
    ):
        raise ValueError('invalid source execution in benchmark cohort')
    return Execution(
        source,
        float(duration_ms),
        result_count,
        status,
        error_type,
        pressure_limit,
        pressure_error,
        memory_bytes,
    )


def load_cohort(path: Path) -> list[Execution]:
    rows: list[Execution] = []
    for line_number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f'invalid JSON on line {line_number}') from error
        if not isinstance(record, dict):
            raise ValueError(f'benchmark line {line_number} must be an object')
        executions = record.get('source_executions')
        if executions is None:
            rows.append(_execution(record))
        elif isinstance(executions, list):
            if not all(isinstance(value, dict) for value in executions):
                raise ValueError(f'source_executions on line {line_number} must contain only objects')
            rows.extend(_execution(value) for value in executions)
        else:
            raise ValueError(f'source_executions on line {line_number} must be a list')
    if not rows:
        raise ValueError('benchmark cohort has no source executions')
    return rows


def _validate_candidates(candidates: Sequence[int]) -> None:
    if not candidates or any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in candidates):
        raise ValueError('candidate workers must be positive integers')


def _percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


class _ScriptState:
    def __init__(self) -> None:
        self.active = 0
        self.peak_active = 0


class _ScriptedAdapter:
    def __init__(self, execution: Execution, state: _ScriptState, scale: float) -> None:
        self.execution = execution
        self.execution_status = execution.status
        self.state = state
        self.scale = scale
        self.ready = False

    async def process(self, _proxy: bool) -> None:
        self.state.active += 1
        self.state.peak_active = max(self.state.peak_active, self.state.active)
        overloaded = self.execution.pressure_limit is not None and self.state.active > self.execution.pressure_limit
        memory = bytearray(self.execution.memory_bytes)
        try:
            await asyncio.sleep(self.execution.duration_ms / 1_000 * self.scale)
            if overloaded:
                assert self.execution.pressure_error is not None
                raise _SCRIPTED_ERRORS[self.execution.pressure_error]('scripted concurrency pressure')
            if self.execution.error_type is not None:
                error_type = _SCRIPTED_ERRORS.get(self.execution.error_type, RuntimeError)
                raise error_type('scripted baseline outcome')
            self.ready = True
        finally:
            self.state.active -= 1
            del memory

    async def get_hostnames(self) -> set[str]:
        if not self.ready:
            return set()
        return {f'result-{index}.{self.execution.source}.benchmark.invalid' for index in range(self.execution.result_count)}

    def __getattr__(self, name: str):
        if not name.startswith('get_'):
            raise AttributeError(name)

        async def empty() -> set[str]:
            return set()

        return empty


def _error_counts(outcomes: Sequence[Any]) -> dict[str, int]:
    errors = [outcome.execution.error_type.casefold() for outcome in outcomes if outcome.execution.error_type is not None]
    return {
        'http_429': sum('429' in value for value in errors),
        'http_503': sum('503' in value for value in errors),
        'timeouts': sum('timeout' in value for value in errors),
        'dns_failures': sum('dns' in value or 'resolver' in value for value in errors),
    }


def prescreen(rows: Sequence[Execution], *, candidates: Sequence[int]) -> dict[str, Any]:
    _validate_candidates(candidates)
    total_results = sum(value.result_count for value in rows)
    metrics = []
    for requested in candidates:
        workers = min(requested, len(rows))
        available = [0.0] * workers
        heapq.heapify(available)
        for execution in rows:
            started_at = heapq.heappop(available)
            heapq.heappush(available, started_at + execution.duration_ms)
        makespan_ms = max(available)
        metrics.append(
            {
                'workers': requested,
                'effective_workers': workers,
                'estimated_makespan_ms': round(makespan_ms, 3),
                'estimated_results_per_minute': round(total_results * 60_000 / makespan_ms, 3) if makespan_ms else None,
            }
        )
    return {
        'mode': 'duration-only-pre-screen',
        'selection_eligible': False,
        'selected_workers': None,
        'metrics': metrics,
    }


async def _run_once(rows: Sequence[Execution], worker_count: int, scale: float) -> tuple[float, tuple[Any, ...], int]:
    from theHarvester.lib.source_runner import SOURCE_FACTORIES, SourceJob, SourceRequest, run_source_jobs

    queues: dict[str, deque[Execution]] = {}
    for execution in rows:
        queues.setdefault(execution.source, deque()).append(execution)
    unknown_sources = set(queues) - set(SOURCE_FACTORIES)
    if unknown_sources:
        raise ValueError(f'benchmark cohort has unknown sources: {", ".join(sorted(unknown_sources))}')
    originals = {source: SOURCE_FACTORIES[source] for source in queues}
    state = _ScriptState()

    def factory(source: str):
        def create(_request: SourceRequest) -> _ScriptedAdapter:
            return _ScriptedAdapter(queues[source].popleft(), state, scale)

        return create

    for source in queues:
        SOURCE_FACTORIES[source] = factory(source)
    jobs = tuple(SourceJob(SourceRequest(execution.source, 'benchmark.invalid', 10_000, 0, False, True)) for execution in rows)
    started = time.perf_counter()
    try:
        outcomes = await run_source_jobs(jobs, workers=worker_count)
    finally:
        SOURCE_FACTORIES.update(originals)
    return (time.perf_counter() - started) * 1_000, outcomes, state.peak_active


async def _cancellation_latency(rows: Sequence[Execution], worker_count: int, scale: float) -> float:
    blocking = [
        execution._replace(
            duration_ms=max(execution.duration_ms, 60_000),
            error_type=None,
            pressure_limit=None,
            pressure_error=None,
        )
        for execution in rows[:worker_count]
    ]
    task = asyncio.create_task(_run_once(blocking, worker_count, max(scale, 0.001)))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    started = time.perf_counter()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return (time.perf_counter() - started) * 1_000


async def scripted_benchmark(
    rows: Sequence[Execution],
    *,
    candidates: Sequence[int],
    repeats: int,
    scale: float,
    seed: int,
) -> list[dict[str, Any]]:
    from theHarvester.lib import source_runner as _source_runner  # noqa: F401 - warm imports before memory sampling

    _validate_candidates(candidates)
    if repeats <= 0 or not math.isfinite(scale) or scale < 0:
        raise ValueError('repeats must be positive and scale must be finite and non-negative')
    metrics: list[dict[str, Any]] = []
    for requested in candidates:
        worker_count = min(requested, len(rows))
        run_durations: list[float] = []
        source_latencies: list[float] = []
        retained_counts: list[int] = []
        completed_counts: list[int] = []
        results_per_minute: list[float] = []
        errors: list[dict[str, int]] = []
        peak_tasks = 0
        rng = random.Random(seed)
        tracemalloc.start()
        try:
            for _repeat in range(repeats):
                shuffled = list(rows)
                rng.shuffle(shuffled)
                duration_ms, outcomes, active_tasks = await _run_once(shuffled, worker_count, scale)
                run_durations.append(duration_ms)
                retained = sum(outcome.execution.result_count for outcome in outcomes)
                retained_counts.append(retained)
                completed_counts.append(sum(outcome.execution.status == 'completed' for outcome in outcomes))
                results_per_minute.append(retained * 60_000 / duration_ms if duration_ms else 0)
                errors.append(_error_counts(outcomes))
                source_latencies.extend(outcome.execution.duration_ms for outcome in outcomes)
                peak_tasks = max(peak_tasks, active_tasks)
            _current_memory, peak_memory = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        metrics.append(
            {
                'workers': requested,
                'effective_workers': worker_count,
                'cohort_sources': len(rows),
                'retained_results': min(retained_counts),
                'completed_sources': min(completed_counts),
                'latency_ms_p50': round(statistics.median(source_latencies), 3),
                'latency_ms_p95': round(_percentile(source_latencies, 0.95), 3),
                'run_ms_p50': round(statistics.median(run_durations), 3),
                'run_ms_p95': round(_percentile(run_durations, 0.95), 3),
                'results_per_minute': round(statistics.median(results_per_minute), 3),
                'http_429': max(error['http_429'] for error in errors),
                'http_503': max(error['http_503'] for error in errors),
                'timeouts': max(error['timeouts'] for error in errors),
                'dns_failures': max(error['dns_failures'] for error in errors),
                'cancellation_latency_ms': round(await _cancellation_latency(rows, worker_count, scale), 3),
                'peak_active_tasks': peak_tasks,
                'peak_sockets': None,
                'peak_memory_bytes': peak_memory,
                'runner': 'run_source_jobs',
            }
        )
    return metrics


def select_default(
    metrics: Sequence[dict[str, Any]],
    *,
    near_plateau_ratio: float = NEAR_PLATEAU_RATIO,
    resource_pressure_ratio: float = RESOURCE_PRESSURE_RATIO,
    cancellation_latency_ratio: float = CANCELLATION_LATENCY_RATIO,
) -> int:
    if not metrics or not 0 < near_plateau_ratio <= 1 or resource_pressure_ratio < 1 or cancellation_latency_ratio < 1:
        raise ValueError('metrics and valid selection thresholds are required')
    max_results = max(int(value['retained_results']) for value in metrics)
    complete = [value for value in metrics if int(value['retained_results']) == max_results]
    max_sources = max(int(value['completed_sources']) for value in complete)
    complete = [value for value in complete if int(value['completed_sources']) == max_sources]
    baseline = min(metrics, key=lambda value: int(value['workers']))
    complete = [
        value
        for value in complete
        if all(int(value[field]) <= int(baseline[field]) for field in ('http_429', 'http_503', 'timeouts'))
    ]
    for field, ratio in (
        ('peak_active_tasks', resource_pressure_ratio),
        ('peak_memory_bytes', resource_pressure_ratio),
        ('peak_sockets', resource_pressure_ratio),
        ('cancellation_latency_ms', cancellation_latency_ratio),
    ):
        baseline_value = baseline.get(field)
        if baseline_value is None:
            continue
        limit = float(baseline_value) * ratio
        complete = [value for value in complete if value.get(field) is not None and float(value[field]) <= limit]
    if not complete:
        raise ValueError('no candidate retained maximum completeness within error and resource thresholds')
    best_throughput = max(float(value['results_per_minute']) for value in complete)
    near_plateau = [value for value in complete if float(value['results_per_minute']) >= best_throughput * near_plateau_ratio]
    return min(int(value['workers']) for value in near_plateau)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('durations', type=Path, help='theHarvester JSONL or one source execution object per JSONL line')
    parser.add_argument('--candidates', type=int, nargs='+', default=DEFAULT_CANDIDATES)
    parser.add_argument('--repeats', type=int, default=DEFAULT_REPEATS)
    parser.add_argument('--scale', type=float, default=DEFAULT_SCALE)
    parser.add_argument('--seed', type=int, default=DEFAULT_SEED)
    parser.add_argument('--prescreen-only', action='store_true')
    parser.add_argument('--output', type=Path)
    return parser


def main() -> None:
    args = _parser().parse_args()
    rows = load_cohort(args.durations)
    report: dict[str, Any] = {
        'cohort': str(args.durations),
        'cohort_source_executions': len(rows),
        'repeats': args.repeats,
        'scale': args.scale,
        'seed': args.seed,
        'selection_thresholds': {
            'near_plateau_ratio': NEAR_PLATEAU_RATIO,
            'resource_pressure_ratio': RESOURCE_PRESSURE_RATIO,
            'cancellation_latency_ratio': CANCELLATION_LATENCY_RATIO,
        },
        'duration_prescreen': prescreen(rows, candidates=args.candidates),
        'limitations': [
            'Scripted offline timings are not a provider guarantee.',
            'Duration-only results are a pre-screen and cannot select the shipping default.',
            'Scripted profiles open no sockets, so peak sockets are not observable.',
        ],
    }
    if args.prescreen_only:
        report['selection_eligible'] = False
        report['selected_workers'] = None
    else:
        metrics = asyncio.run(
            scripted_benchmark(
                rows,
                candidates=args.candidates,
                repeats=args.repeats,
                scale=args.scale,
                seed=args.seed,
            )
        )
        report['scripted_end_to_end'] = metrics
        report['selection_eligible'] = True
        report['selected_workers'] = select_default(metrics)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output is not None:
        args.output.write_text(payload, encoding='utf-8')
    sys.stdout.write(payload)


if __name__ == '__main__':
    main()

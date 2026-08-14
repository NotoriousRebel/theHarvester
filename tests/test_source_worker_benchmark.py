from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / 'scripts' / 'benchmark_source_workers.py'
COHORT = Path(__file__).parents[1] / 'docs' / 'benchmarks' / 'source-workers-offline-cohort.jsonl'
REPORT = Path(__file__).parents[1] / 'docs' / 'benchmarks' / 'source-workers-offline-report.json'


def load_benchmark_module():
    spec = importlib.util.spec_from_file_location('benchmark_source_workers', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_duration_jsonl_is_only_a_prescreen(tmp_path: Path) -> None:
    module = load_benchmark_module()
    cohort = tmp_path / 'durations.jsonl'
    cohort.write_text(
        '\n'.join(
            (
                json.dumps({'source': 'crtsh', 'duration_ms': 120, 'result_count': 4, 'status': 'completed'}),
                json.dumps({'source': 'urlscan', 'duration_ms': 80, 'result_count': 2, 'status': 'completed'}),
            )
        ),
        encoding='utf-8',
    )

    rows = module.load_cohort(cohort)
    report = module.prescreen(rows, candidates=(5, 6, 7, 8))

    assert [row.source for row in rows] == ['crtsh', 'urlscan']
    assert report['mode'] == 'duration-only-pre-screen'
    assert report['selection_eligible'] is False
    assert report['selected_workers'] is None


def test_duration_jsonl_rejects_an_entire_malformed_execution_list(tmp_path: Path) -> None:
    module = load_benchmark_module()
    cohort = tmp_path / 'durations.jsonl'
    cohort.write_text(
        json.dumps(
            {
                'source_executions': [
                    {'source': 'crtsh', 'duration_ms': 120, 'result_count': 4, 'status': 'completed'},
                    'malformed',
                ]
            }
        ),
        encoding='utf-8',
    )

    with pytest.raises(ValueError, match='source_executions on line 1 must contain only objects'):
        module.load_cohort(cohort)


def test_selection_hard_gates_completeness_and_errors_before_throughput() -> None:
    module = load_benchmark_module()
    metrics = [
        {'workers': 5, 'retained_results': 100, 'completed_sources': 20, 'http_429': 0, 'http_503': 0, 'timeouts': 0, 'results_per_minute': 900, 'peak_active_tasks': 5, 'peak_memory_bytes': 100, 'peak_sockets': None, 'cancellation_latency_ms': 1},
        {'workers': 6, 'retained_results': 100, 'completed_sources': 20, 'http_429': 0, 'http_503': 0, 'timeouts': 0, 'results_per_minute': 950, 'peak_active_tasks': 6, 'peak_memory_bytes': 120, 'peak_sockets': None, 'cancellation_latency_ms': 1.1},
        {'workers': 7, 'retained_results': 99, 'completed_sources': 20, 'http_429': 0, 'http_503': 0, 'timeouts': 0, 'results_per_minute': 2_000, 'peak_active_tasks': 7, 'peak_memory_bytes': 140, 'peak_sockets': None, 'cancellation_latency_ms': 1.2},
        {'workers': 8, 'retained_results': 100, 'completed_sources': 20, 'http_429': 1, 'http_503': 0, 'timeouts': 0, 'results_per_minute': 2_100, 'peak_active_tasks': 8, 'peak_memory_bytes': 160, 'peak_sockets': None, 'cancellation_latency_ms': 1.3},
    ]

    assert module.select_default(metrics, near_plateau_ratio=0.95) == 6


def test_selection_rejects_material_resource_pressure_before_throughput() -> None:
    module = load_benchmark_module()
    metrics = [
        {'workers': 5, 'retained_results': 100, 'completed_sources': 20, 'http_429': 0, 'http_503': 0, 'timeouts': 0, 'results_per_minute': 900, 'peak_active_tasks': 5, 'peak_memory_bytes': 100, 'peak_sockets': None, 'cancellation_latency_ms': 1},
        {'workers': 6, 'retained_results': 100, 'completed_sources': 20, 'http_429': 0, 'http_503': 0, 'timeouts': 0, 'results_per_minute': 950, 'peak_active_tasks': 6, 'peak_memory_bytes': 120, 'peak_sockets': None, 'cancellation_latency_ms': 1.1},
        {'workers': 7, 'retained_results': 100, 'completed_sources': 20, 'http_429': 0, 'http_503': 0, 'timeouts': 0, 'results_per_minute': 1_100, 'peak_active_tasks': 7, 'peak_memory_bytes': 151, 'peak_sockets': None, 'cancellation_latency_ms': 1.2},
    ]

    assert module.select_default(metrics, near_plateau_ratio=0.95, resource_pressure_ratio=1.5) == 6


def test_scripted_profiles_produce_candidate_dependent_runner_outcomes() -> None:
    module = load_benchmark_module()
    rows = [
        module.Execution(source, 100, 1, 'completed', None, 5, 'HTTP429Error', 1_024)
        for source in ('apis-guru', 'arquivo', 'baidu', 'brave', 'bufferoverun', 'censys', 'certspotter', 'commoncrawl')
    ]

    metrics = asyncio.run(module.scripted_benchmark(rows, candidates=(5, 6), repeats=1, scale=0.01, seed=289))
    by_workers = {metric['workers']: metric for metric in metrics}

    assert by_workers[5]['retained_results'] == 8
    assert by_workers[5]['completed_sources'] == 8
    assert by_workers[5]['http_429'] == 0
    assert by_workers[6]['retained_results'] < 8
    assert by_workers[6]['completed_sources'] < 8
    assert by_workers[6]['http_429'] > 0
    assert by_workers[6]['runner'] == 'run_source_jobs'


def test_full_cohort_regeneration_matches_report_and_shipping_default() -> None:
    from theHarvester.lib.enumeration import DEFAULT_SOURCE_WORKERS

    module = load_benchmark_module()

    assert module.DEFAULT_REPEATS >= 9
    assert module.DEFAULT_SCALE >= 0.01

    metrics = asyncio.run(
        module.scripted_benchmark(
            module.load_cohort(COHORT),
            candidates=module.DEFAULT_CANDIDATES,
            repeats=module.DEFAULT_REPEATS,
            scale=module.DEFAULT_SCALE,
            seed=module.DEFAULT_SEED,
        )
    )
    regenerated_default = module.select_default(metrics)
    committed_report = json.loads(REPORT.read_text(encoding='utf-8'))

    assert regenerated_default == committed_report['selected_workers'] == DEFAULT_SOURCE_WORKERS
    assert committed_report['repeats'] == module.DEFAULT_REPEATS
    assert committed_report['scale'] == module.DEFAULT_SCALE


@pytest.mark.parametrize('workers', [0, -1, True])
def test_prescreen_rejects_invalid_candidates(tmp_path: Path, workers: object) -> None:
    module = load_benchmark_module()
    cohort = tmp_path / 'durations.jsonl'
    cohort.write_text(
        json.dumps({'source': 'crtsh', 'duration_ms': 1, 'result_count': 1, 'status': 'completed'}),
        encoding='utf-8',
    )

    with pytest.raises(ValueError, match='candidate workers must be positive integers'):
        module.prescreen(module.load_cohort(cohort), candidates=(workers,))

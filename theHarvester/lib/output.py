from __future__ import annotations

import json
from collections import Counter
from collections.abc import Hashable, Iterable, Sequence
from typing import TYPE_CHECKING, Any, TypedDict, TypeVar
from xml.etree.ElementTree import Element, SubElement, tostring

from theHarvester.lib.run import Addressability, ScopeClass, legacy_hostnames

if TYPE_CHECKING:
    from collections.abc import Mapping

    from theHarvester.lib.run import MergedEntity, RunResult, SelectedObservation

T = TypeVar('T', bound=Hashable)


class _SourceYield(TypedDict):
    source: str
    source_family: str
    discovered_subdomains: int
    exclusive_subdomains: int
    currently_addressable_subdomains: int | None
    exclusive_currently_addressable_subdomains: int | None
    addressability_evaluated: bool


def sorted_unique[T: Hashable](items: Iterable[T]) -> list[T]:
    unique_items = list(dict.fromkeys(items))
    unique_items.sort(key=lambda item: str(item))
    return unique_items


def print_section(header: str, items: Iterable[str], separator: str) -> None:
    print(header)
    print(separator)
    for item in sorted_unique(items):
        print(item)


def print_linkedin_sections(
    engines: Sequence[str], people: Sequence[str], links: Sequence[str], separator: str = '---------------------'
) -> None:
    if len(people) == 0 and 'linkedin' in engines:
        print('\n[*] No LinkedIn users found.\n\n')
    elif len(people) >= 1:
        print('\n[*] LinkedIn Users found: ' + str(len(people)))
        print(separator)
        for usr in sorted_unique(people):
            print(usr)

    if 'linkedin' in engines or 'rocketreach' in engines:
        print(f'\n[*] LinkedIn Links found: {len(links)}')
        print(separator)
        for link in sorted_unique(links):
            print(link)


def _entity_line(entity: MergedEntity, selected: Sequence[SelectedObservation] = ()) -> str:
    sources = ','.join(sorted({observation.source for observation in entity.observations}))
    selected_status = ''.join(f'; {observation.kind}={observation.detail or "observed"}' for observation in selected)
    recursive = next(
        (observation for observation in entity.observations if observation.parent is not None),
        None,
    )
    recursive_status = f'; derivation={recursive.derivation}; parent={recursive.parent}' if recursive is not None else ''
    return f'{entity.value} [status={entity.addressability}; sources={sources}{selected_status}{recursive_status}]'


def _source_yield(result: RunResult) -> list[_SourceYield]:
    source_families = {
        execution.source: execution.source_family
        for execution in result.source_executions
        if not execution.source.startswith('action:')
    }
    for observation in result.observations:
        if not observation.source.startswith('action:'):
            source_families[observation.source] = observation.source_family

    discovered_counts: Counter[str] = Counter()
    exclusive_counts: Counter[str] = Counter()
    current_counts: Counter[str] = Counter()
    exclusive_current_counts: Counter[str] = Counter()
    addressability_evaluated: dict[str, bool] = {}
    for entity in result.entities:
        if ScopeClass.IN_SCOPE not in entity.scope_classes or not entity.value.endswith(f'.{result.target}'):
            continue
        sources = {observation.source for observation in entity.observations if not observation.source.startswith('action:')}
        for source in sources:
            discovered_counts[source] += 1
            is_exclusive = len(sources) == 1
            exclusive_counts[source] += is_exclusive
            is_current = entity.addressability is Addressability.CURRENT
            current_counts[source] += is_current
            exclusive_current_counts[source] += is_exclusive and is_current
            addressability_evaluated[source] = addressability_evaluated.get(source, True) and bool(entity.dns_validations)

    rows: list[_SourceYield] = [
        _SourceYield(
            source=source,
            source_family=source_families[source],
            discovered_subdomains=discovered_counts[source],
            exclusive_subdomains=exclusive_counts[source],
            currently_addressable_subdomains=(current_counts[source] if addressability_evaluated.get(source, False) else None),
            exclusive_currently_addressable_subdomains=(
                exclusive_current_counts[source] if addressability_evaluated.get(source, False) else None
            ),
            addressability_evaluated=addressability_evaluated.get(source, False),
        )
        for source in source_families
    ]
    return sorted(
        rows,
        key=lambda row: (
            -row['exclusive_subdomains'],
            -row['discovered_subdomains'],
            str(row['source']),
        ),
    )


def format_run_terminal(result: RunResult) -> str:
    """Render one concise terminal report from a completed evidence run."""
    primary = [
        entity
        for entity in result.entities
        if ScopeClass.IN_SCOPE in entity.scope_classes and entity.addressability is Addressability.CURRENT
    ]
    primary_values = {entity.value for entity in primary}
    secondary = [
        entity
        for entity in result.entities
        if entity.value not in primary_values
        and (
            ScopeClass.EXTERNAL_RELATIONSHIP in entity.scope_classes
            or (ScopeClass.IN_SCOPE in entity.scope_classes and entity.addressability is not Addressability.CURRENT)
        )
    ]
    reported_values = primary_values | {entity.value for entity in secondary}
    scope_extensions = [
        entity
        for entity in result.entities
        if entity.value not in reported_values and ScopeClass.SCOPE_EXTENSION in entity.scope_classes
    ]
    entity_values = {entity.value for entity in result.entities}
    terminal_selected = tuple(
        observation for observation in result.selected_observations if observation.source.startswith('action:')
    )
    selected_by_entity = {
        value: tuple(observation for observation in terminal_selected if observation.value == value) for value in entity_values
    }
    standalone_selected = [observation for observation in terminal_selected if observation.value not in entity_values]
    source_yield = _source_yield(result)
    sections = [
        f'[*] Run status: {result.status}',
        f'[*] Currently addressable subdomains ({len(primary)})',
        *(_entity_line(entity, selected_by_entity[entity.value]) for entity in primary),
        f'[*] Secondary evidence / needs review ({len(secondary)})',
        *(_entity_line(entity, selected_by_entity[entity.value]) for entity in secondary),
        f'[*] Scope-extension candidates ({len(scope_extensions)})',
        *(_entity_line(entity, selected_by_entity[entity.value]) for entity in scope_extensions),
        f'[*] Selected stage observations ({len(standalone_selected)})',
        *(
            f'{observation.value} [{observation.kind}={observation.detail or "observed"}; source={observation.source}]'
            for observation in standalone_selected
        ),
        '[*] Source yield',
        *(
            f'{row["source"]} [discovered={row["discovered_subdomains"]}; exclusive={row["exclusive_subdomains"]}; '
            f'currently-addressable={row["currently_addressable_subdomains"] if row["addressability_evaluated"] else "n/a"}; '
            f'exclusive-current={row["exclusive_currently_addressable_subdomains"] if row["addressability_evaluated"] else "n/a"}]'
            for row in source_yield
        ),
        '[*] Source executions',
        *(
            f'{execution.source} [status={execution.status}; results={execution.result_count}; '
            f'observations={execution.observation_count}'
            + (
                f'; queries={execution.query_count}; depth={execution.depth_reached}; '
                f'zero-yield={execution.zero_yield_batches}; stop={execution.stop_reason}'
                if execution.query_count is not None
                else ''
            )
            + ']'
            for execution in result.source_executions
        ),
    ]
    return '\n'.join(sections)


def run_result_jsonl(result: RunResult) -> str:
    """Serialize a completed run as versioned, normalized evidence records."""
    records: list[tuple[str, dict[str, Any]]] = [
        (
            'run',
            _run_record(result),
        ),
        *(('source_execution', execution.to_dict()) for execution in result.source_executions),
        *(('source_yield', dict(row)) for row in _source_yield(result)),
        *(('discovery_observation', observation.to_dict()) for observation in result.observations),
        *(('dns_validation_observation', _jsonl_validation(observation.to_dict())) for observation in result.dns_validations),
        *(('merged_result', _jsonl_entity(entity)) for entity in result.entities),
        *(('selected_observation', observation.to_dict()) for observation in result.selected_observations),
    ]
    return '\n'.join(
        json.dumps({'schema_version': 'theharvester-evidence-v1', 'record_type': record_type, 'data': data})
        for record_type, data in records
    )


def _jsonl_validation(data: dict[str, object]) -> dict[str, object]:
    data['validated_at'] = data.pop('queried_at')
    return data


def _jsonl_entity(entity: MergedEntity) -> dict[str, object]:
    return {
        'value': entity.value,
        'addressability': entity.addressability,
        'scope_classes': list(entity.scope_classes),
        'independent_corroboration_count': entity.independent_corroboration_count,
        'provenance': [observation.to_dict() for observation in entity.observations],
    }


def _evidence_summary(result: RunResult) -> dict[str, object]:
    summary = {
        **_run_record(result),
        'source_executions': [execution.to_dict() for execution in result.source_executions],
        'source_yield': _source_yield(result),
        'selected_observations': [observation.to_dict() for observation in result.selected_observations],
    }
    recursive_observations = [observation.to_dict() for observation in result.observations if observation.parent is not None]
    if recursive_observations:
        summary['recursive_observations'] = recursive_observations
    return summary


def _run_record(result: RunResult) -> dict[str, object]:
    return {
        'run_id': result.run_id,
        'target': result.target,
        'status': result.status,
        'started_at': result.started_at.isoformat(),
        'completed_at': result.completed_at.isoformat(),
    }


def legacy_json_result(result: RunResult, existing: Mapping[str, object] | None = None) -> dict[str, object]:
    adapted = dict(existing or {})
    existing_hosts = adapted.get('hosts', [])
    hosts = list(existing_hosts) if isinstance(existing_hosts, list) else []
    adapted['hosts'] = list(dict.fromkeys([*hosts, *legacy_hostnames(result)]))
    adapted['evidence_run'] = _evidence_summary(result)
    return adapted


def evidence_xml_fragment(result: RunResult) -> str:
    return tostring(_evidence_xml_element(result), encoding='unicode')


def _evidence_xml_element(result: RunResult) -> Element:
    evidence_run = Element('evidence_run', run_id=result.run_id, status=result.status)
    for execution in result.source_executions:
        attributes = {'name': execution.source, 'status': execution.status}
        if execution.query_count is not None:
            attributes.update(
                {
                    'query_count': str(execution.query_count),
                    'depth_reached': str(execution.depth_reached),
                    'zero_yield_batches': str(execution.zero_yield_batches),
                    'stop_reason': execution.stop_reason or '',
                }
            )
        SubElement(evidence_run, 'source', attributes)
    for recursive_observation in result.observations:
        if recursive_observation.parent is None:
            continue
        SubElement(
            evidence_run,
            'discovery_observation',
            {
                'source': recursive_observation.source,
                'value': recursive_observation.value,
                'derivation': recursive_observation.derivation,
                'parent': recursive_observation.parent,
                'collected_at': recursive_observation.collected_at.isoformat(),
            },
        )
    for selected_observation in result.selected_observations:
        attributes = {
            'source': selected_observation.source,
            'kind': selected_observation.kind,
            'value': selected_observation.value,
            'collected_at': selected_observation.collected_at.isoformat(),
        }
        if selected_observation.detail is not None:
            attributes['detail'] = selected_observation.detail
        SubElement(evidence_run, 'selected_observation', attributes)
    return evidence_run

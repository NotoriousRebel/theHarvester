from __future__ import annotations

import json
import logging
import sys
from collections.abc import Hashable, Iterable, Mapping, Sequence
from typing import TypeVar
from xml.etree.ElementTree import Element, SubElement, tostring

from theHarvester.lib.dns_validation import Addressability
from theHarvester.lib.run import Derivation, RunResult, ScopeClass

T = TypeVar('T', bound=Hashable)


class _OperatorOutputHandler(logging.Handler):
    """Write operator-facing messages to the current stdout stream."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stdout.write(f'{self.format(record)}\n')
        except Exception:
            self.handleError(record)


output_logger = logging.getLogger('theHarvester.output')


def configure_logging(*, verbose: bool) -> None:
    """Configure CLI diagnostics without taking ownership from an embedding host."""
    if not any(isinstance(handler, _OperatorOutputHandler) for handler in output_logger.handlers):
        output_logger.addHandler(_OperatorOutputHandler())
    output_logger.setLevel(logging.INFO)
    output_logger.propagate = False

    root_logger = logging.getLogger()
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(levelname)s %(name)s: %(message)s'))
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.WARNING)

    package_logger = logging.getLogger('theHarvester')
    logger_state = package_logger.__dict__
    if verbose and package_logger.level != logging.INFO:
        logger_state.setdefault('_theharvester_level_before_verbose', package_logger.level)
        package_logger.setLevel(logging.INFO)
    elif not verbose and '_theharvester_level_before_verbose' in logger_state:
        previous_level = logger_state.pop('_theharvester_level_before_verbose')
        if package_logger.level == logging.INFO:
            package_logger.setLevel(previous_level)


def sorted_unique[T: Hashable](items: Iterable[T]) -> list[T]:
    unique_items = list(dict.fromkeys(items))
    unique_items.sort(key=lambda item: str(item))
    return unique_items


def print_section(header: str, items: Iterable[str], separator: str) -> None:
    output_logger.info(header)
    output_logger.info(separator)
    for item in sorted_unique(items):
        output_logger.info(item)


def print_linkedin_sections(
    engines: Sequence[str], people: Sequence[str], links: Sequence[str], separator: str = '---------------------'
) -> None:
    if len(people) == 0 and 'linkedin' in engines:
        output_logger.info('\n[*] No LinkedIn users found.\n\n')
    elif len(people) >= 1:
        output_logger.info(f'\n[*] LinkedIn Users found: {len(people)}')
        output_logger.info(separator)
        for usr in sorted_unique(people):
            output_logger.info(usr)

    if 'linkedin' in engines or 'rocketreach' in engines:
        output_logger.info(f'\n[*] LinkedIn Links found: {len(links)}')
        output_logger.info(separator)
        for link in sorted_unique(links):
            output_logger.info(link)


_RESULT_LABELS = {
    'subdomain': 'Subdomains',
    'additional-hostname': 'Additional subdomains',
    'ip': 'IP addresses',
    'asn': 'ASNs',
    'email': 'Emails',
    'url': 'URLs',
    'person': 'People',
}


def format_run_terminal(result: RunResult, *, configuration: Sequence[str] = ()) -> str:
    """Render one completed run for a human operator."""
    lines = [f'[*] Run status: {result.status}']
    if configuration:
        lines.append(configuration[0])
    lines.append(f'Target: {result.target}')
    lines.extend(configuration[1:])

    hostname_groups: dict[str, list[str]] = {}
    for entity in result.entities:
        if entity.value == result.target:
            continue
        sources = ', '.join(sorted({observation.source for observation in entity.observations}))
        if ScopeClass.SCOPE_EXTENSION in entity.scope_classes:
            label = 'Scope-extension candidates'
            status = str(ScopeClass.SCOPE_EXTENSION)
        elif ScopeClass.EXTERNAL_RELATIONSHIP in entity.scope_classes:
            label = 'External relationship evidence'
            status = str(ScopeClass.EXTERNAL_RELATIONSHIP)
        elif entity.addressability is Addressability.CURRENT:
            label = 'Currently addressable subdomains'
            status = str(entity.addressability)
        elif entity.addressability is None:
            if all(observation.derivation is Derivation.PROVIDER for observation in entity.observations) and not any(
                execution.name == 'dns-resolution' for execution in result.executions
            ):
                label = 'Subdomains (DNS validation not requested)'
                status = 'dns-not-requested'
            else:
                label = 'Secondary subdomain evidence'
                status = 'not-consensus-validated'
        else:
            label = 'Secondary subdomain evidence'
            status = str(entity.addressability)
        hostname_groups.setdefault(label, []).append(f'{entity.value} [{status}; sources: {sources}]')

    for label, values in hostname_groups.items():
        lines.append(f'[*] {label} ({len(values)})')
        lines.extend(sorted_unique(values))

    grouped: dict[str, list[str]] = {}
    rendered_hostnames = {entity.value for entity in result.entities}
    for record in result.results:
        result_type = record.type
        if result_type in {'subdomain', 'scope-extension', 'external-relationship'} and record.value in rendered_hostnames:
            continue
        if result_type == 'subdomain' and hostname_groups:
            result_type = 'additional-hostname'
        grouped.setdefault(result_type, []).append(record.value)
    for result_type, values in grouped.items():
        unique_values = sorted_unique(values)
        lines.append(f'[*] {_RESULT_LABELS.get(result_type, result_type.replace("-", " ").title())} ({len(unique_values)})')
        lines.extend(unique_values)

    lines.append('[*] Executions')
    for execution in result.executions:
        error = f'; error={execution.error_type}' if execution.error_type else ''
        lines.append(f'{execution.name} [{execution.activity}: {execution.status}; results={execution.result_count}{error}]')
    return '\n'.join(lines)


def run_result_jsonl(result: RunResult) -> str:
    """Serialize a compact summary followed by flat operator results."""
    counts: dict[str, int] = {}
    for record in result.results:
        counts[record.type] = counts.get(record.type, 0) + 1
    records = [
        {
            'type': 'summary',
            'schema': 'theharvester-results-v1',
            'target': result.target,
            'status': result.status,
            'counts': dict(sorted(counts.items())),
        },
        *({'type': record.type, 'value': record.value} for record in result.results),
    ]
    return '\n'.join(json.dumps(record, separators=(',', ':'), sort_keys=True) for record in records)


def legacy_json_result(result: RunResult, existing: Mapping[str, object] | None = None) -> dict[str, object]:
    """Add completed run data without replacing legacy JSON fields."""
    adapted = dict(existing or {})
    adapted['run'] = result.to_dict()
    return adapted


def legacy_report_hosts(discovered: Iterable[str], resolved: Iterable[str]) -> list[str]:
    """Prefer resolved host forms without dropping discoveries that did not resolve."""
    resolved_values = sorted_unique(resolved)
    resolved_names = {value.split(':', 1)[0] for value in resolved_values}
    return sorted_unique([*resolved_values, *(host for host in discovered if host not in resolved_names)])


def run_result_xml(result: RunResult) -> str:
    """Return an additive completed-run fragment for the legacy XML report."""
    root = Element('run', status=str(result.status), target=result.target)
    results = SubElement(root, 'results')
    for record in result.results:
        SubElement(results, 'result', type=record.type).text = record.value
    executions = SubElement(root, 'executions')
    for execution in result.executions:
        SubElement(
            executions,
            'execution',
            name=execution.name,
            activity=str(execution.activity),
            status=str(execution.status),
            results=str(execution.result_count),
        )
    return tostring(root, encoding='unicode')

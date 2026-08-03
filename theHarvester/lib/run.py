from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.hostnames import normalize_hostname
from theHarvester.lib.source_catalog import ResultRoute, get_source_spec

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

logger = logging.getLogger(__name__)


class ScopeClass(StrEnum):
    IN_SCOPE = 'in-scope'
    OUT_OF_SCOPE = 'out-of-scope'


class SourceStatus(StrEnum):
    SUCCEEDED = 'succeeded'
    EMPTY = 'empty'
    PARTIAL = 'partial'
    FAILED = 'failed'
    SKIPPED = 'skipped'


_ROUTE_GETTERS = {
    ResultRoute.SUBDOMAINS: 'get_hostnames',
    ResultRoute.EMAILS: 'get_emails',
    ResultRoute.IPS: 'get_ips',
    ResultRoute.ASNS: 'get_asns',
    ResultRoute.PEOPLE: 'get_people',
    ResultRoute.LINKS: 'get_links',
    ResultRoute.INTERESTING_URLS: 'get_interestingurls',
}


class DiscoveryAdapter(Protocol):
    async def process(self, proxy: bool = False) -> None: ...


@dataclass(frozen=True)
class DiscoveryObservation:
    value: str
    source: str
    scope_class: ScopeClass


@dataclass(frozen=True)
class SourceOutcome:
    source: str
    status: SourceStatus
    process_succeeded: bool
    error_type: str | None = None


@dataclass(frozen=True)
class CollectionResult:
    target: str
    outcome: SourceOutcome
    observations: tuple[DiscoveryObservation, ...]
    route_values: Mapping[ResultRoute, tuple[Any, ...]]


async def execute_collection(
    target: str,
    source: str,
    adapter_factory: Callable[[], DiscoveryAdapter],
    proxy: bool = False,
) -> CollectionResult:
    normalized_target = normalize_hostname(target)
    if normalized_target is None:
        raise ValueError('target must be a hostname')
    normalized_target = normalized_target.removeprefix('www.')
    spec = get_source_spec(source)
    process_succeeded = False
    try:
        search = adapter_factory()
    except Exception as error:
        status = SourceStatus.SKIPPED if isinstance(error, MissingKey) else SourceStatus.FAILED
        if status is SourceStatus.SKIPPED:
            logger.info(f'Source {spec.name} completed with status {status}')
        else:
            logger.exception(f'Source {spec.name} failed')
        return CollectionResult(
            normalized_target,
            SourceOutcome(spec.name, status, False, type(error).__name__),
            (),
            {},
        )

    execution_error: Exception | None = None
    try:
        await search.process(proxy)
        process_succeeded = True
    except Exception as error:
        execution_error = error

    route_values: dict[ResultRoute, tuple[Any, ...]] = {}
    observations: tuple[DiscoveryObservation, ...] = ()
    had_unusable_values = False
    for route in ResultRoute:
        if route not in spec.routes:
            continue
        try:
            values = tuple(await getattr(search, _ROUTE_GETTERS[route])())
        except Exception as error:
            if execution_error is None:
                execution_error = error
            route_values[route] = ()
            continue
        if route is ResultRoute.SUBDOMAINS:
            normalized_observations = []
            for candidate in values:
                value = normalize_hostname(candidate)
                if value is None:
                    had_unusable_values = True
                    continue
                normalized_observations.append(
                    DiscoveryObservation(
                        value=value,
                        source=spec.name,
                        scope_class=(
                            ScopeClass.IN_SCOPE
                            if value == normalized_target or value.endswith(f'.{normalized_target}')
                            else ScopeClass.OUT_OF_SCOPE
                        ),
                    )
                )
            observations = tuple(normalized_observations)
            values = tuple(observation.value for observation in observations)
        else:
            usable_values = tuple(value for value in values if value)
            had_unusable_values = had_unusable_values or len(usable_values) != len(values)
            values = usable_values
        route_values[route] = values
    has_values = any(route_values.values())
    if execution_error is not None or had_unusable_values:
        status = SourceStatus.PARTIAL if has_values else SourceStatus.FAILED
    else:
        status = SourceStatus.SUCCEEDED if has_values else SourceStatus.EMPTY
    logger.info(f'Source {spec.name} completed with status {status}')
    return CollectionResult(
        normalized_target,
        SourceOutcome(
            spec.name,
            status,
            process_succeeded,
            type(execution_error).__name__ if execution_error is not None else 'ValueError' if had_unusable_values else None,
        ),
        observations,
        route_values,
    )


def legacy_subdomains(result: CollectionResult) -> list[str]:
    """Return in-scope descendants for existing host-compatible consumers."""
    return sorted(
        {
            observation.value
            for observation in result.observations
            if observation.scope_class is ScopeClass.IN_SCOPE and observation.value != result.target
        }
    )

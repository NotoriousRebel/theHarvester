from __future__ import annotations

import pytest

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.source_catalog import ResultRoute
from theHarvester.lib.run import (
    ScopeClass,
    SourceStatus,
    execute_collection,
    legacy_subdomains,
)


class FakeHostnameSearch:
    def __init__(self, values: list[str]) -> None:
        self.values = values
        self.process_calls: list[bool] = []

    async def process(self, proxy: bool = False) -> None:
        self.process_calls.append(proxy)

    async def get_hostnames(self) -> list[str]:
        return self.values


class FailingHostnameSearch:
    async def process(self, proxy: bool = False) -> None:
        raise RuntimeError('provider unavailable')

    async def get_hostnames(self) -> list[str]:
        return []


class FakeMultiRouteSearch:
    def __init__(
        self,
        values: dict[ResultRoute, list[str]] | None = None,
        process_error: Exception | None = None,
    ) -> None:
        self.calls: list[str] = []
        self.process_error = process_error
        self.values = (
            values
            if values is not None
            else {
                ResultRoute.SUBDOMAINS: ['API.Example.COM.', 'BÜCHER.Example.COM.'],
                ResultRoute.EMAILS: ['ops@example.com'],
                ResultRoute.IPS: ['192.0.2.10'],
                ResultRoute.ASNS: ['AS64500'],
                ResultRoute.INTERESTING_URLS: ['https://example.com/login'],
            }
        )

    async def process(self, proxy: bool = False) -> None:
        self.calls.append(f'process:{proxy}')
        if self.process_error is not None:
            raise self.process_error

    async def get_hostnames(self) -> list[str]:
        self.calls.append('subdomains')
        return self.values.get(ResultRoute.SUBDOMAINS, [])

    async def get_emails(self) -> list[str]:
        self.calls.append('emails')
        return self.values.get(ResultRoute.EMAILS, [])

    async def get_ips(self) -> list[str]:
        self.calls.append('ips')
        return self.values.get(ResultRoute.IPS, [])

    async def get_asns(self) -> list[str]:
        self.calls.append('asns')
        return self.values.get(ResultRoute.ASNS, [])

    async def get_interestingurls(self) -> list[str]:
        self.calls.append('interesting_urls')
        return self.values.get(ResultRoute.INTERESTING_URLS, [])


@pytest.mark.asyncio
async def test_collection_constructs_processes_and_harvests_declared_routes_once() -> None:
    constructed: list[FakeMultiRouteSearch] = []

    def factory() -> FakeMultiRouteSearch:
        search = FakeMultiRouteSearch()
        constructed.append(search)
        return search

    result = await execute_collection('example.com', 'zoomeye', factory, proxy=True)

    assert len(constructed) == 1
    assert constructed[0].calls == [
        'process:True',
        'subdomains',
        'emails',
        'ips',
        'asns',
        'interesting_urls',
    ]
    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values == {
        ResultRoute.SUBDOMAINS: ('api.example.com', 'xn--bcher-kva.example.com'),
        ResultRoute.EMAILS: ('ops@example.com',),
        ResultRoute.IPS: ('192.0.2.10',),
        ResultRoute.ASNS: ('AS64500',),
        ResultRoute.INTERESTING_URLS: ('https://example.com/login',),
    }


@pytest.mark.asyncio
async def test_collection_retains_usable_routes_when_a_complete_response_is_mixed() -> None:
    search = FakeMultiRouteSearch(
        {
            ResultRoute.SUBDOMAINS: ['bad host'],
            ResultRoute.EMAILS: ['', 'ops@example.com'],
            ResultRoute.IPS: ['192.0.2.10'],
            ResultRoute.ASNS: ['AS64500'],
            ResultRoute.INTERESTING_URLS: ['https://example.com/login'],
        }
    )

    result = await execute_collection('example.com', 'zoomeye', lambda: search)

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.process_succeeded is True
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ()
    assert result.route_values[ResultRoute.EMAILS] == ('ops@example.com',)
    assert search.calls == [
        'process:False',
        'subdomains',
        'emails',
        'ips',
        'asns',
        'interesting_urls',
    ]


@pytest.mark.asyncio
async def test_collection_harvests_retained_routes_after_process_failure() -> None:
    search = FakeMultiRouteSearch(process_error=RuntimeError('later page failed'))

    result = await execute_collection('example.com', 'zoomeye', lambda: search)

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.process_succeeded is False
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com', 'xn--bcher-kva.example.com')
    assert result.route_values[ResultRoute.EMAILS] == ('ops@example.com',)
    assert search.calls == [
        'process:False',
        'subdomains',
        'emails',
        'ips',
        'asns',
        'interesting_urls',
    ]


@pytest.mark.asyncio
async def test_collection_skips_a_source_with_a_missing_precondition() -> None:
    factory_calls = 0

    def factory() -> FakeMultiRouteSearch:
        nonlocal factory_calls
        factory_calls += 1
        raise MissingKey('fixture')

    result = await execute_collection('example.com', 'zoomeye', factory)

    assert factory_calls == 1
    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.process_succeeded is False
    assert result.outcome.error_type == 'MissingKeyError'
    assert result.route_values == {}


@pytest.mark.asyncio
async def test_collection_records_a_complete_empty_multi_route_source() -> None:
    search = FakeMultiRouteSearch(values={})

    result = await execute_collection('example.com', 'zoomeye', lambda: search)

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.outcome.process_succeeded is True
    assert result.outcome.error_type is None
    assert all(values == () for values in result.route_values.values())


@pytest.mark.asyncio
async def test_collection_fails_a_complete_nonempty_unusable_multi_route_source() -> None:
    search = FakeMultiRouteSearch(values={ResultRoute.SUBDOMAINS: ['bad host']})

    result = await execute_collection('example.com', 'zoomeye', lambda: search)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.process_succeeded is True
    assert result.outcome.error_type == 'ValueError'
    assert all(values == () for values in result.route_values.values())


@pytest.mark.asyncio
async def test_collection_records_unexpected_construction_failure() -> None:
    def factory() -> FakeMultiRouteSearch:
        raise RuntimeError('constructor failed')

    result = await execute_collection('example.com', 'zoomeye', factory)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.process_succeeded is False
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values == {}


@pytest.mark.asyncio
async def test_collection_normalizes_scope_and_preserves_www_target_behavior() -> None:
    search = FakeHostnameSearch(
        [
            'API.Example.COM.',
            'BÜCHER.Example.COM.',
            'example.com',
            'example.com.attacker.test',
            '',
        ]
    )

    result = await execute_collection(
        'WWW.Example.COM.',
        'crtsh',
        lambda: search,
        proxy=True,
    )

    assert result.target == 'example.com'
    assert search.process_calls == [True]
    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.process_succeeded is True
    assert result.outcome.error_type == 'ValueError'
    assert [(observation.value, observation.scope_class) for observation in result.observations] == [
        ('api.example.com', ScopeClass.IN_SCOPE),
        ('xn--bcher-kva.example.com', ScopeClass.IN_SCOPE),
        ('example.com', ScopeClass.IN_SCOPE),
        ('example.com.attacker.test', ScopeClass.OUT_OF_SCOPE),
    ]
    assert legacy_subdomains(result) == ['api.example.com', 'xn--bcher-kva.example.com']


@pytest.mark.asyncio
async def test_collection_records_a_valid_empty_source() -> None:
    result = await execute_collection(
        'example.com',
        'crtsh',
        lambda: FakeHostnameSearch([]),
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.outcome.process_succeeded is True
    assert result.outcome.error_type is None
    assert result.observations == ()


@pytest.mark.asyncio
async def test_collection_reports_nonempty_unusable_results_as_failure() -> None:
    result = await execute_collection(
        'example.com',
        'crtsh',
        lambda: FakeHostnameSearch(['', '...', 'bad host', 'https://api.example.com']),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.process_succeeded is True
    assert result.outcome.error_type == 'ValueError'
    assert result.observations == ()


@pytest.mark.asyncio
async def test_collection_records_source_failures_without_results() -> None:
    result = await execute_collection(
        'example.com',
        'crtsh',
        FailingHostnameSearch,
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.process_succeeded is False
    assert result.outcome.error_type == 'RuntimeError'
    assert result.observations == ()

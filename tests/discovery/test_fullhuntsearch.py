import pytest

from theHarvester.discovery import fullhuntsearch
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute


@pytest.mark.asyncio
async def test_primary_endpoint_reports_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')
    requests: list[str] = []

    async def fake_fetch(**kwargs):
        requests.append(kwargs['url'])
        assert kwargs['json'] is True
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        assert kwargs['raise_on_error'] is True
        return {'hosts': [{'host': 'API.Example.COM.'}]}

    async def reject_legacy_fetch(*_args, **_kwargs):
        raise AssertionError('legacy fetch_all called')

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch_all', reject_legacy_fetch)

    result = await execute_collection(
        'example.com',
        'fullhunt',
        lambda: fullhuntsearch.SearchFullHunt('example.com'),
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert requests == ['https://fullhunt.io/api/v1/domain/example.com/details']


@pytest.mark.asyncio
async def test_malformed_fallback_payload_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')
    requests: list[str] = []

    async def fake_fetch(**kwargs):
        requests.append(kwargs['url'])
        if kwargs['url'].endswith('/details'):
            return {'hosts': []}
        return {}

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    result = await execute_collection(
        'example.com',
        'fullhunt',
        lambda: fullhuntsearch.SearchFullHunt('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert requests == [
        'https://fullhunt.io/api/v1/domain/example.com/details',
        'https://fullhunt.io/api/v1/domain/example.com/subdomains',
    ]


@pytest.mark.asyncio
async def test_malformed_advanced_payload_reports_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')
    requests: list[str] = []

    async def fake_fetch(**kwargs):
        requests.append(kwargs['url'])
        if kwargs['url'].endswith('/details'):
            return {'hosts': [{'host': 'api.example.com'}]}
        return {}

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    def factory() -> fullhuntsearch.SearchFullHunt:
        search = fullhuntsearch.SearchFullHunt('example.com')
        search.add_filter('tech', 'nginx')
        return search

    result = await execute_collection('example.com', 'fullhunt', factory)

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)
    assert len(requests) == 2
    assert requests[1].startswith('https://fullhunt.io/api/v1/search?query=')


@pytest.mark.asyncio
async def test_malformed_primary_payload_fails_without_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')
    requests: list[str] = []

    async def fake_fetch(**kwargs):
        requests.append(kwargs['url'])
        return {}

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    result = await execute_collection(
        'example.com',
        'fullhunt',
        lambda: fullhuntsearch.SearchFullHunt('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert requests == ['https://fullhunt.io/api/v1/domain/example.com/details']


@pytest.mark.asyncio
async def test_valid_empty_response_uses_fallback_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')
    requests: list[str] = []

    async def fake_fetch(**kwargs):
        requests.append(kwargs['url'])
        return {'hosts': []}

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    result = await execute_collection(
        'example.com',
        'fullhunt',
        lambda: fullhuntsearch.SearchFullHunt('example.com'),
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert requests == [
        'https://fullhunt.io/api/v1/domain/example.com/details',
        'https://fullhunt.io/api/v1/domain/example.com/subdomains',
    ]


@pytest.mark.asyncio
async def test_missing_credentials_skip_before_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: None)
    requests: list[str] = []

    async def fake_fetch(**kwargs):
        requests.append(kwargs['url'])
        return {'hosts': []}

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    result = await execute_collection(
        'example.com',
        'fullhunt',
        lambda: fullhuntsearch.SearchFullHunt('example.com'),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'
    assert requests == []


@pytest.mark.asyncio
async def test_first_endpoint_failure_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')
    requests: list[str] = []

    async def fake_fetch(**kwargs):
        requests.append(kwargs['url'])
        raise RuntimeError('HTTP 401')

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    result = await execute_collection(
        'example.com',
        'fullhunt',
        lambda: fullhuntsearch.SearchFullHunt('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert requests == ['https://fullhunt.io/api/v1/domain/example.com/details']


@pytest.mark.asyncio
async def test_timeout_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')

    async def fake_fetch(**_kwargs):
        raise TimeoutError('provider timed out')

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    result = await execute_collection(
        'example.com',
        'fullhunt',
        lambda: fullhuntsearch.SearchFullHunt('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'TimeoutError'


@pytest.mark.asyncio
async def test_fallback_failure_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')
    requests: list[str] = []

    async def fake_fetch(**kwargs):
        requests.append(kwargs['url'])
        if kwargs['url'].endswith('/details'):
            return {'hosts': []}
        raise RuntimeError('HTTP 429')

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    result = await execute_collection(
        'example.com',
        'fullhunt',
        lambda: fullhuntsearch.SearchFullHunt('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_later_endpoint_failure_retains_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')

    async def fake_fetch(**kwargs):
        if kwargs['url'].endswith('/details'):
            return {'hosts': [{'host': 'api.example.com'}]}
        raise RuntimeError('HTTP 503')

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    def factory() -> fullhuntsearch.SearchFullHunt:
        search = fullhuntsearch.SearchFullHunt('example.com')
        search.add_filter('tech', 'nginx')
        return search

    result = await execute_collection('example.com', 'fullhunt', factory)

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)


@pytest.mark.asyncio
async def test_malformed_primary_host_fails_without_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')
    requests: list[str] = []

    async def fake_fetch(**kwargs):
        requests.append(kwargs['url'])
        if kwargs['url'].endswith('/details'):
            return {'hosts': [{}]}
        return {'hosts': []}

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    result = await execute_collection(
        'example.com',
        'fullhunt',
        lambda: fullhuntsearch.SearchFullHunt('example.com'),
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert requests == ['https://fullhunt.io/api/v1/domain/example.com/details']


@pytest.mark.asyncio
async def test_malformed_advanced_host_retains_primary_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fullhuntsearch.Core, 'fullhunt_key', lambda: 'dummy-key')

    async def fake_fetch(**kwargs):
        if kwargs['url'].endswith('/details'):
            return {'hosts': [{'host': 'api.example.com'}]}
        return {'hosts': [{}]}

    monkeypatch.setattr(fullhuntsearch.AsyncFetcher, 'fetch', fake_fetch)

    def factory() -> fullhuntsearch.SearchFullHunt:
        search = fullhuntsearch.SearchFullHunt('example.com')
        search.add_filter('tech', 'nginx')
        return search

    result = await execute_collection('example.com', 'fullhunt', factory)

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.SUBDOMAINS] == ('api.example.com',)

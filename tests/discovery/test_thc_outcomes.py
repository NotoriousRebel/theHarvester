from types import TracebackType
from typing import Any, Self

import pytest

from theHarvester.discovery import thc
from theHarvester.lib.run import ScopeClass, SourceStatus, execute_collection, legacy_subdomains
from theHarvester.lib.source_catalog import ResultRoute

type ResponseOutcome = tuple[int, str, dict[str, str]] | Exception


async def _collect(monkeypatch: pytest.MonkeyPatch, outcomes: list[ResponseOutcome]):
    pending = list(outcomes)
    requests: list[str] = []
    sleeps: list[int] = []

    class FakeResponse:
        def __init__(self, status: int, text: str, headers: dict[str, str]) -> None:
            self.status = status
            self._text = text
            self.headers = headers

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(
            self,
            _exc_type: type[BaseException] | None,
            _exc: BaseException | None,
            _tb: TracebackType | None,
        ) -> bool:
            return False

        async def text(self) -> str:
            return self._text

    class FakeSession:
        def __init__(self, **kwargs: Any) -> None:
            assert kwargs['timeout'].total == 60

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(
            self,
            _exc_type: type[BaseException] | None,
            _exc: BaseException | None,
            _tb: TracebackType | None,
        ) -> bool:
            return False

        def get(self, url: str) -> FakeResponse:
            requests.append(url)
            if not pending:
                pytest.fail('THC made an unexpected request')
            outcome = pending.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return FakeResponse(*outcome)

    async def no_sleep(delay: int) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(thc.aiohttp, 'ClientSession', FakeSession)
    monkeypatch.setattr(thc.asyncio, 'sleep', no_sleep)
    result = await execute_collection('example.com', 'thc', lambda: thc.SearchThc('example.com'))
    assert not pending
    return result, requests, sleeps


@pytest.mark.asyncio
async def test_non_success_http_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, requests, sleeps = await _collect(monkeypatch, [(503, 'service unavailable', {})])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}
    assert len(requests) == 1
    assert sleeps == []


@pytest.mark.asyncio
async def test_exhausted_rate_limit_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    rate_limit = (429, 'rate limited', {'x-ratelimit-remaining': '0'})
    result, requests, sleeps = await _collect(monkeypatch, [rate_limit, rate_limit, rate_limit])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}
    assert len(requests) == 3
    assert sleeps == [2, 4]


@pytest.mark.asyncio
async def test_malformed_text_response_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, requests, sleeps = await _collect(monkeypatch, [(200, '<html>provider error</html>', {})])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}
    assert len(requests) == 1
    assert sleeps == []


@pytest.mark.asyncio
async def test_mixed_usable_and_malformed_lines_report_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _requests, _sleeps = await _collect(monkeypatch, [(200, 'API.EXAMPLE.COM\nnot a hostname\n', {})])

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ('api.example.com',)}


@pytest.mark.asyncio
@pytest.mark.parametrize('body', ['', ' \n'])
async def test_http_200_blank_text_reports_empty(monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    result, requests, sleeps = await _collect(monkeypatch, [(200, body, {})])

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}
    assert len(requests) == 1
    assert sleeps == []


@pytest.mark.asyncio
async def test_rate_limit_retry_can_recover_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, requests, sleeps = await _collect(
        monkeypatch,
        [(429, 'rate limited', {'x-ratelimit-remaining': '0'}), (200, '', {})],
    )

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}
    assert len(requests) == 2
    assert sleeps == [2]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('error', 'error_type'),
    [
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
    ],
)
async def test_request_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    error_type: str,
) -> None:
    result, requests, sleeps = await _collect(monkeypatch, [error])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}
    assert len(requests) == 1
    assert sleeps == []


@pytest.mark.asyncio
async def test_success_preserves_public_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _requests, _sleeps = await _collect(
        monkeypatch,
        [(200, 'WWW.EXAMPLE.COM\napi.example.com\napi.example.com\n', {})],
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {'www.example.com', 'api.example.com'}


@pytest.mark.asyncio
async def test_success_routes_valid_hostnames_through_central_scope_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _requests, _sleeps = await _collect(
        monkeypatch,
        [(200, 'api.example.com\nnotexample.com\nexample.com.evil\noutside.test\n', {})],
    )

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.SUBDOMAINS]) == {
        'api.example.com',
        'notexample.com',
        'example.com.evil',
        'outside.test',
    }
    assert {(observation.value, observation.scope_class) for observation in result.observations} == {
        ('api.example.com', ScopeClass.IN_SCOPE),
        ('notexample.com', ScopeClass.OUT_OF_SCOPE),
        ('example.com.evil', ScopeClass.OUT_OF_SCOPE),
        ('outside.test', ScopeClass.OUT_OF_SCOPE),
    }
    assert legacy_subdomains(result) == ['api.example.com']

from types import TracebackType
from typing import Any, Self

import pytest

from theHarvester.discovery import venacussearch
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute

type ResponseOutcome = tuple[int, object] | Exception


def _record(index: int) -> dict[str, object]:
    return {
        'tokens': [
            {'type': 'email', 'value': f'user{index}@example.com'},
            {'type': 'ip_address', 'value': f'192.0.2.{index}'},
            {'type': 'url', 'value': f'https://example.com/profile/{index}'},
            {'type': 'firstname', 'value': 'Ada'},
            {'type': 'lastname', 'value': f'Lovelace{index}'},
        ]
    }


def _page(
    *records: object,
    offset_doc: int = 0,
    offset_in_doc: int = 0,
    more: bool = False,
) -> dict[str, object]:
    return {
        'data': list(records),
        'offset_doc': offset_doc,
        'offset_in_doc': offset_in_doc,
        'more': more,
    }


async def _collect(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: list[ResponseOutcome],
    *,
    limit: int = 1000,
    offset_doc: int = 0,
):
    pending = list(outcomes)
    calls: list[dict[str, Any]] = []

    class FakeResponse:
        def __init__(self, status: int, payload: object) -> None:
            self.status = status
            self.payload = payload

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(
            self,
            _exc_type: type[BaseException] | None,
            _exc: BaseException | None,
            _tb: TracebackType | None,
        ) -> bool:
            return False

        async def json(self) -> object:
            if isinstance(self.payload, Exception):
                raise self.payload
            return self.payload

    class FakeSession:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(
            self,
            _exc_type: type[BaseException] | None,
            _exc: BaseException | None,
            _tb: TracebackType | None,
        ) -> bool:
            return False

        def get(self, url: str, **kwargs: Any) -> FakeResponse:
            calls.append({'url': url, **kwargs})
            if not pending:
                pytest.fail('Venacus made an unexpected request')
            outcome = pending.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return FakeResponse(*outcome)

    monkeypatch.setattr(venacussearch.Core, 'venacus_key', lambda: 'test-key')
    monkeypatch.setattr(venacussearch.aiohttp, 'ClientSession', FakeSession)
    result = await execute_collection(
        'example.com',
        'venacus',
        lambda: venacussearch.SearchVenacus('example.com', limit=limit, offset_doc=offset_doc),
    )
    assert not pending
    return result, calls


@pytest.mark.asyncio
@pytest.mark.parametrize('key', ['', ' '])
async def test_blank_key_reports_skipped_without_request(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    monkeypatch.setattr(venacussearch.Core, 'venacus_key', lambda: key)

    def unexpected_session():
        pytest.fail('Venacus request must not run without a key')

    monkeypatch.setattr(venacussearch.aiohttp, 'ClientSession', unexpected_session)
    result = await execute_collection(
        'example.com',
        'venacus',
        lambda: venacussearch.SearchVenacus('example.com'),
    )

    assert result.outcome.status is SourceStatus.SKIPPED
    assert result.outcome.error_type == 'MissingKeyError'


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [401, 503])
async def test_non_success_http_reports_failed(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    result, calls = await _collect(monkeypatch, [(status, _page())])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_provider_error_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(monkeypatch, [(200, {'error': 'invalid API key'})])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'payload',
    [
        pytest.param([], id='non-object'),
        pytest.param(ValueError('invalid JSON'), id='invalid-json'),
        pytest.param({'more': False}, id='missing-data'),
        pytest.param({'data': [], 'more': True}, id='empty-with-more'),
    ],
)
async def test_malformed_response_reports_failed(monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
    result, _calls = await _collect(monkeypatch, [(200, payload)])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'


@pytest.mark.asyncio
async def test_valid_empty_response_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(monkeypatch, [(200, _page())])

    assert len(calls) == 1
    assert result.outcome.status is SourceStatus.EMPTY
    assert all(values == () for values in result.route_values.values())


@pytest.mark.asyncio
async def test_terminal_page_without_offsets_reports_succeeded(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _collect(monkeypatch, [(200, {'data': [_record(1)], 'more': False})])

    assert len(calls) == 1
    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values[ResultRoute.EMAILS] == ('user1@example.com',)


@pytest.mark.asyncio
async def test_mixed_malformed_and_usable_records_report_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _page({'tokens': None}, _record(2), offset_doc=1)
    result, _calls = await _collect(monkeypatch, [(200, page)])

    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.EMAILS] == ('user2@example.com',)


@pytest.mark.asyncio
@pytest.mark.parametrize('invalid_value', [1, ' '], ids=['non-string', 'blank'])
async def test_invalid_route_values_report_malformed(
    monkeypatch: pytest.MonkeyPatch,
    invalid_value: object,
) -> None:
    malformed_record = {
        'tokens': [
            {'type': 'email', 'value': invalid_value},
            {'type': 'ip_address', 'value': invalid_value},
            {'type': 'url', 'value': invalid_value},
            {'type': 'firstname', 'value': invalid_value},
        ]
    }
    result, _calls = await _collect(monkeypatch, [(200, _page(malformed_record))])

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert all(values == () for values in result.route_values.values())


@pytest.mark.asyncio
async def test_later_offset_timeout_retains_completed_records(monkeypatch: pytest.MonkeyPatch) -> None:
    first_page = _page(_record(1), offset_doc=1, more=True)
    result, calls = await _collect(monkeypatch, [(200, first_page), TimeoutError('provider timed out')])

    assert len(calls) == 2
    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'TimeoutError'
    assert result.route_values[ResultRoute.EMAILS] == ('user1@example.com',)
    assert result.route_values[ResultRoute.IPS] == ('192.0.2.1',)
    assert result.route_values[ResultRoute.INTERESTING_URLS] == ('https://example.com/profile/1',)
    assert result.route_values[ResultRoute.PEOPLE] == (
        {'email': 'user1@example.com', 'firstname': 'Ada', 'lastname': 'Lovelace1'},
    )


@pytest.mark.asyncio
async def test_later_offset_malformed_record_retains_completed_records(monkeypatch: pytest.MonkeyPatch) -> None:
    first_page = _page(_record(1), offset_doc=1, more=True)
    malformed_page = _page({'tokens': None}, offset_doc=2)
    result, calls = await _collect(monkeypatch, [(200, first_page), (200, malformed_page)])

    assert len(calls) == 2
    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.EMAILS] == ('user1@example.com',)


@pytest.mark.asyncio
async def test_stalled_offset_reports_partial_without_repeating_request(monkeypatch: pytest.MonkeyPatch) -> None:
    stalled_page = _page(_record(1), more=True)
    result, calls = await _collect(monkeypatch, [(200, stalled_page)])

    assert len(calls) == 1
    assert result.outcome.status is SourceStatus.PARTIAL
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values[ResultRoute.EMAILS] == ('user1@example.com',)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('error', 'error_type'),
    [
        pytest.param(TimeoutError('provider timed out'), 'TimeoutError', id='timeout'),
        pytest.param(ConnectionError('transport failed'), 'ConnectionError', id='transport'),
    ],
)
async def test_first_request_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    error_type: str,
) -> None:
    result, calls = await _collect(monkeypatch, [error])

    assert len(calls) == 1
    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert all(values == () for values in result.route_values.values())


@pytest.mark.asyncio
async def test_success_preserves_routes_and_advances_offsets(monkeypatch: pytest.MonkeyPatch) -> None:
    first_page = _page(_record(1), offset_doc=7, offset_in_doc=3, more=True)
    final_page = _page(_record(2), offset_doc=8)
    result, calls = await _collect(
        monkeypatch,
        [(200, first_page), (200, final_page)],
        offset_doc=5,
    )

    assert len(calls) == 2
    assert calls[0]['url'] == 'https://api.venacus.com/v1/search/'
    assert calls[0]['headers']['Authorization'] == 'Bearer test-key'
    assert calls[0]['params'] == {
        'q': 'example.com',
        'offset_doc': 5,
        'offset_in_doc': 0,
        'limit': 100,
        'ai': 'false',
    }
    assert calls[1]['params']['offset_doc'] == 7
    assert calls[1]['params']['offset_in_doc'] == 3
    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert set(result.route_values[ResultRoute.EMAILS]) == {'user1@example.com', 'user2@example.com'}
    assert set(result.route_values[ResultRoute.IPS]) == {'192.0.2.1', '192.0.2.2'}
    assert set(result.route_values[ResultRoute.INTERESTING_URLS]) == {
        'https://example.com/profile/1',
        'https://example.com/profile/2',
    }
    assert len(result.route_values[ResultRoute.PEOPLE]) == 2

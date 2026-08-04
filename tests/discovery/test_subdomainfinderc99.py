import json
from typing import Any

import pytest

from theHarvester.discovery import subdomainfinderc99
from theHarvester.lib.run import SourceStatus, execute_collection
from theHarvester.lib.source_catalog import ResultRoute

_SERVER = 'https://subdomainfinder.c99.nl/'
_CSRF_FIELD = 'CSRF9843433218797932'
_CSRF_PAGE = f'<html><div class="input-group"><input name="{_CSRF_FIELD}" value="token"></div></html>'
_CSRF_ERROR = 'CSRF token invalid or expired'
_EMPTY_RESULT_PAGE = '<html><table id="result_table"></table></html>'


async def _collect(
    monkeypatch: pytest.MonkeyPatch,
    csrf_response: object,
    result_response: object = _EMPTY_RESULT_PAGE,
):
    requests: list[tuple[str, dict[str, Any]]] = []

    async def fake_fetch(**kwargs: Any) -> object:
        requests.append(('get', kwargs))
        if isinstance(csrf_response, Exception):
            raise csrf_response
        return csrf_response

    async def reject_fetch_all(*_args: Any, **_kwargs: Any) -> object:
        pytest.fail('SubdomainFinderC99 must use a strict GET request')

    async def fake_post_fetch(url: str, **kwargs: Any) -> object:
        requests.append(('post', {'url': url, **kwargs}))
        if isinstance(result_response, Exception):
            raise result_response
        return result_response

    async def no_sleep(_delay: object) -> None:
        return None

    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch_all', reject_fetch_all)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(subdomainfinderc99.asyncio, 'sleep', no_sleep)

    result = await execute_collection(
        'example.com',
        'subdomainfinderc99',
        lambda: subdomainfinderc99.SearchSubdomainfinderc99('example.com'),
    )
    return result, requests


@pytest.mark.asyncio
async def test_missing_csrf_fields_report_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _requests = await _collect(monkeypatch, '<html></html>')

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'csrf_page',
    [
        pytest.param('<div class="input-group"><input name="csrf-token" value=""></div>', id='blank-value'),
        pytest.param('<div class="input-group"><input name="CSRF123" value="   "></div>', id='whitespace-value'),
        pytest.param('<div class="input-group"><input name="" value="token"></div>', id='blank-name'),
    ],
)
async def test_unusable_csrf_fields_report_failed(monkeypatch: pytest.MonkeyPatch, csrf_page: str) -> None:
    result, _requests = await _collect(monkeypatch, csrf_page)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


@pytest.mark.asyncio
async def test_unrelated_form_field_does_not_satisfy_csrf_requirement(monkeypatch: pytest.MonkeyPatch) -> None:
    csrf_page = '<div class="input-group"><input name="unrelated" value="present"></div>'
    result, _requests = await _collect(monkeypatch, csrf_page)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


@pytest.mark.asyncio
async def test_valid_empty_result_page_reports_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    result, requests = await _collect(monkeypatch, _CSRF_PAGE)

    assert result.outcome.status is SourceStatus.EMPTY
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}
    assert [method for method, _kwargs in requests] == ['get', 'post']

    get_request = requests[0][1]
    assert get_request['url'] == _SERVER
    assert get_request['proxy'] is False
    assert get_request['request_timeout'] == 60
    assert get_request['fail_on_http_error'] is True
    assert get_request['raise_on_error'] is True

    post_request = requests[1][1]
    assert post_request['url'] == _SERVER
    assert post_request['proxy'] is False
    assert post_request['fail_on_http_error'] is True
    assert post_request['raise_on_error'] is True
    assert json.loads(post_request['data']) == {
        _CSRF_FIELD: 'token',
        'scan_subdomains': '',
        'domain': 'example.com',
        'privatequery': 'on',
    }


@pytest.mark.asyncio
async def test_provider_error_page_reports_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _requests = await _collect(
        monkeypatch,
        _CSRF_PAGE,
        f'<html><div>{_CSRF_ERROR}</div><table id="result_table"></table></html>',
    )

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'RuntimeError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('csrf_response', 'result_response', 'error_type'),
    [
        pytest.param(RuntimeError('HTTP 503'), _EMPTY_RESULT_PAGE, 'RuntimeError', id='csrf-http'),
        pytest.param(TimeoutError('csrf timed out'), _EMPTY_RESULT_PAGE, 'TimeoutError', id='csrf-timeout'),
        pytest.param(_CSRF_PAGE, RuntimeError('HTTP 429'), 'RuntimeError', id='result-http'),
        pytest.param(_CSRF_PAGE, ConnectionError('result transport failed'), 'ConnectionError', id='result-transport'),
    ],
)
async def test_request_failure_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    csrf_response: object,
    result_response: object,
    error_type: str,
) -> None:
    result, _requests = await _collect(monkeypatch, csrf_response, result_response)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == error_type
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('csrf_response', 'result_response'),
    [
        pytest.param([], _EMPTY_RESULT_PAGE, id='csrf-non-string'),
        pytest.param(_CSRF_PAGE, [], id='result-non-string'),
        pytest.param(_CSRF_PAGE, '<div id="result_table"></div>', id='wrong-result-element'),
    ],
)
async def test_malformed_page_reports_failed(
    monkeypatch: pytest.MonkeyPatch,
    csrf_response: object,
    result_response: object,
) -> None:
    result, _requests = await _collect(monkeypatch, csrf_response, result_response)

    assert result.outcome.status is SourceStatus.FAILED
    assert result.outcome.error_type == 'ValueError'
    assert result.route_values == {ResultRoute.SUBDOMAINS: ()}


@pytest.mark.asyncio
async def test_success_preserves_public_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    result_page = '<html><table id="result_table"><tr><td><a>api.example.com</a></td></tr></table></html>'
    result, _requests = await _collect(monkeypatch, _CSRF_PAGE, result_page)

    assert result.outcome.status is SourceStatus.SUCCEEDED
    assert result.route_values == {ResultRoute.SUBDOMAINS: ('api.example.com',)}

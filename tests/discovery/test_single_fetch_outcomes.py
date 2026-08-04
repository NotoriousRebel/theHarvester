import json

import pytest

from theHarvester.discovery import builtwith, securityscorecard
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.lib.run import SourceStatus, execute_collection


def _builtwith_response(value):
    return value if isinstance(value, Exception) else json.dumps(value)


def _securityscorecard_response(value):
    return value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('source', 'key_getter', 'adapter_type', 'prepare_response'),
    [
        pytest.param(
            'builtwith',
            'builtwith_key',
            builtwith.SearchBuiltWith,
            _builtwith_response,
            id='builtwith',
        ),
        pytest.param(
            'securityscorecard',
            'securityscorecard_key',
            securityscorecard.SearchSecurityScorecard,
            _securityscorecard_response,
            id='securityscorecard',
        ),
    ],
)
@pytest.mark.parametrize(
    ('key', 'response', 'expected_status', 'expected_error'),
    [
        pytest.param('   ', AssertionError('transport called'), SourceStatus.SKIPPED, 'MissingKeyError', id='blank-key'),
        pytest.param('dummy-key', {'domains': []}, SourceStatus.EMPTY, None, id='valid-empty'),
        pytest.param(
            'dummy-key',
            {'error': 'unauthorized'},
            SourceStatus.FAILED,
            'ValueError',
            id='provider-error',
        ),
        pytest.param('dummy-key', [], SourceStatus.FAILED, 'ValueError', id='malformed'),
        pytest.param('dummy-key', RuntimeError('HTTP 503'), SourceStatus.FAILED, 'RuntimeError', id='http-error'),
        pytest.param(
            'dummy-key',
            TimeoutError('provider timed out'),
            SourceStatus.FAILED,
            'TimeoutError',
            id='transport-timeout',
        ),
    ],
)
async def test_single_fetch_outcomes_are_truthful(
    monkeypatch,
    source,
    key_getter,
    adapter_type,
    prepare_response,
    key,
    response,
    expected_status,
    expected_error,
) -> None:
    monkeypatch.setattr(Core, key_getter, lambda: key)
    prepared_response = prepare_response(response)

    async def fake_fetch(**kwargs):
        if isinstance(prepared_response, TimeoutError):
            if kwargs.get('raise_on_error', False):
                raise prepared_response
            return ''
        if isinstance(prepared_response, Exception):
            raise prepared_response
        return prepared_response

    monkeypatch.setattr(AsyncFetcher, 'fetch', fake_fetch)

    result = await execute_collection(
        'example.com',
        source,
        lambda: adapter_type('example.com'),
    )

    assert result.outcome.status is expected_status
    assert result.outcome.error_type == expected_error

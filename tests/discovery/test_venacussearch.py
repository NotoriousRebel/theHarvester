from typing import Any

import aiohttp
import pytest

from theHarvester.discovery import venacussearch


@pytest.mark.asyncio
async def test_process_preserves_paginated_results_through_shared_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, Any]] = []

    async def fail_direct_session(*_args: object, **_kwargs: object) -> None:
        raise AssertionError('Venacus must not create a direct aiohttp session')

    async def fetch(**kwargs: Any) -> dict[str, Any]:
        requests.append(kwargs)
        if kwargs['params']['offset_doc'] == 0:
            return {
                'data': [{'tokens': [{'type': 'email', 'value': 'first@example.com'}]}],
                'offset_doc': 1,
                'offset_in_doc': 25,
                'more': True,
            }
        return {
            'data': [{'tokens': [{'type': 'email', 'value': 'second@example.com'}]}],
            'offset_doc': 2,
            'offset_in_doc': 0,
            'more': False,
        }

    monkeypatch.setattr(aiohttp, 'ClientSession', fail_direct_session)
    monkeypatch.setattr(venacussearch.Core, 'venacus_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(venacussearch.Core, 'get_user_agent', staticmethod(lambda: 'test-agent'))
    monkeypatch.setattr(venacussearch.AsyncFetcher, 'fetch', fetch)

    search = venacussearch.SearchVenacus('example.com')
    await search.process()

    assert await search.get_emails() == {'first@example.com', 'second@example.com'}
    assert requests == [
        {
            'url': 'https://api.venacus.com/v1/search/',
            'headers': {'Authorization': 'Bearer test-key', 'User-Agent': 'test-agent-theHarvester'},
            'params': {
                'q': 'example.com',
                'offset_doc': 0,
                'offset_in_doc': 0,
                'limit': 100,
                'ai': 'false',
            },
            'json': True,
            'response_delay': 0,
            'use_system_ssl': True,
        },
        {
            'url': 'https://api.venacus.com/v1/search/',
            'headers': {'Authorization': 'Bearer test-key', 'User-Agent': 'test-agent-theHarvester'},
            'params': {
                'q': 'example.com',
                'offset_doc': 1,
                'offset_in_doc': 25,
                'limit': 100,
                'ai': 'false',
            },
            'json': True,
            'response_delay': 0,
            'use_system_ssl': True,
        },
    ]

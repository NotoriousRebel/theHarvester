from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp
import pytest
from aiohttp import web

from theHarvester.lib import core as core_module
from theHarvester.lib.core import AsyncFetcher

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

FIXTURES_DIR = Path(__file__).parents[1] / 'fixtures'


@asynccontextmanager
async def running_app(
    app: web.Application,
    port: int,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> AsyncIterator[str]:
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', port, ssl_context=ssl_context)
    await site.start()
    scheme = 'https' if ssl_context else 'http'
    try:
        yield f'{scheme}://127.0.0.1:{port}'
    finally:
        await runner.cleanup()


@asynccontextmanager
async def running_raw_server(
    handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
) -> AsyncIterator[tuple[str, int]]:
    server = await asyncio.start_server(handler, '127.0.0.1', 0)
    address = server.sockets[0].getsockname()
    try:
        yield str(address[0]), int(address[1])
    finally:
        server.close()
        await server.wait_closed()


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
        await writer.wait_closed()


def http_response(body: str) -> bytes:
    encoded = body.encode()
    return (
        b'HTTP/1.1 200 OK\r\n'
        + f'Content-Length: {len(encoded)}\r\n'.encode()
        + b'Content-Type: text/plain\r\nConnection: close\r\n\r\n'
        + encoded
    )


@pytest.mark.asyncio
async def test_fetch_sends_get_params_and_decodes_json(unused_tcp_port: int) -> None:
    async def echo_request(request: web.Request) -> web.Response:
        return web.json_response(
            {
                'method': request.method,
                'path': request.path,
                'query': dict(request.query),
            }
        )

    app = web.Application()
    app.router.add_get('/search', echo_request)

    async with running_app(app, unused_tcp_port) as base_url:
        result = await AsyncFetcher.fetch(
            url=f'{base_url}/search',
            params={'domain': 'example.test'},
            json=True,
        )

    assert result == {
        'method': 'GET',
        'path': '/search',
        'query': {'domain': 'example.test'},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('request_kwargs', 'expected_content_type', 'expected_body'),
    [
        ({'json_body': {'domain': 'example.test'}}, 'application/json', {'domain': 'example.test'}),
        ({'data': {'domain': 'example.test'}}, 'application/x-www-form-urlencoded', {'domain': 'example.test'}),
        ({'data': 'domain=example.test'}, 'text/plain', 'domain=example.test'),
    ],
    ids=('json', 'form', 'raw'),
)
async def test_post_fetch_sends_body_formats(
    unused_tcp_port: int,
    request_kwargs: dict[str, Any],
    expected_content_type: str,
    expected_body: Any,
) -> None:
    async def echo_body(request: web.Request) -> web.Response:
        if request.content_type == 'application/json':
            body: Any = await request.json()
        elif request.content_type == 'application/x-www-form-urlencoded':
            body = dict(await request.post())
        else:
            body = await request.text()
        return web.json_response(
            {
                'method': request.method,
                'query': dict(request.query),
                'content_type': request.content_type,
                'body': body,
            }
        )

    app = web.Application()
    app.router.add_post('/submit', echo_body)

    async with running_app(app, unused_tcp_port) as base_url:
        result = await AsyncFetcher.post_fetch(
            f'{base_url}/submit',
            params={'page': '2'},
            json=True,
            **request_kwargs,
        )

    assert result == {
        'method': 'POST',
        'query': {'page': '2'},
        'content_type': expected_content_type,
        'body': expected_body,
    }


@pytest.mark.asyncio
async def test_post_fetch_preserves_default_delay_and_allows_no_delay(
    monkeypatch: pytest.MonkeyPatch,
    unused_tcp_port: int,
) -> None:
    delays: list[int] = []

    async def record_delay(delay: int) -> None:
        delays.append(delay)

    async def response(_request: web.Request) -> web.Response:
        return web.Response(text='ok')

    monkeypatch.setattr(core_module.asyncio, 'sleep', record_delay)
    app = web.Application()
    app.router.add_post('/', response)

    async with running_app(app, unused_tcp_port) as base_url:
        default_result = await AsyncFetcher.post_fetch(base_url)
        no_delay_result = await AsyncFetcher.post_fetch(base_url, response_delay=0)
        observed_delays = delays.copy()

    assert (default_result, no_delay_result, observed_delays) == ('ok', 'ok', [3, 0])


@pytest.mark.asyncio
async def test_post_fetch_preserves_proxy_delay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delays: list[int] = []

    async def record_delay(delay: int) -> None:
        delays.append(delay)

    async def proxy_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b'\r\n\r\n')
            writer.write(http_response('ok'))
            await writer.drain()
        finally:
            await close_writer(writer)

    monkeypatch.setattr(core_module.asyncio, 'sleep', record_delay)

    async with running_raw_server(proxy_handler) as (host, port):
        proxy_url = f'http://{host}:{port}'
        monkeypatch.setattr(AsyncFetcher, '_get_random_proxy', staticmethod(lambda _proxies: (proxy_url, 'http')))
        monkeypatch.setattr(AsyncFetcher, 'proxy_list', {'http': [proxy_url]})
        default_result = await AsyncFetcher.post_fetch('http://example.test/', proxy=True)
        no_delay_result = await AsyncFetcher.post_fetch(
            'http://example.test/',
            proxy=True,
            response_delay=0,
        )
        observed_delays = delays.copy()

    assert (default_result, no_delay_result, observed_delays) == ('ok', 'ok', [5, 0])


@pytest.mark.asyncio
async def test_fetch_decodes_text_and_json_responses(unused_tcp_port: int) -> None:
    async def text_response(_request: web.Request) -> web.Response:
        return web.Response(text='plain response')

    async def json_response(_request: web.Request) -> web.Response:
        return web.json_response({'result': 'structured'})

    app = web.Application()
    app.router.add_get('/text', text_response)
    app.router.add_get('/json', json_response)

    async with running_app(app, unused_tcp_port) as base_url:
        text_result = await AsyncFetcher.fetch(url=f'{base_url}/text')
        json_result = await AsyncFetcher.fetch(url=f'{base_url}/json', json=True)

    assert (text_result, json_result) == ('plain response', {'result': 'structured'})


@pytest.mark.asyncio
async def test_fetch_preserves_default_delay_and_allows_no_delay(
    monkeypatch: pytest.MonkeyPatch,
    unused_tcp_port: int,
) -> None:
    delays: list[int] = []

    async def record_delay(delay: int) -> None:
        delays.append(delay)

    async def response(_request: web.Request) -> web.Response:
        return web.Response(text='ok')

    monkeypatch.setattr(core_module.asyncio, 'sleep', record_delay)
    app = web.Application()
    app.router.add_get('/', response)

    async with running_app(app, unused_tcp_port) as base_url:
        default_result = await AsyncFetcher.fetch(url=base_url)
        no_delay_result = await AsyncFetcher.fetch(url=base_url, response_delay=0)
        observed_delays = delays.copy()

    assert (default_result, no_delay_result, observed_delays) == ('ok', 'ok', [5, 0])


@pytest.mark.asyncio
async def test_fetch_returns_empty_string_for_empty_response(unused_tcp_port: int) -> None:
    async def empty_response(_request: web.Request) -> web.Response:
        return web.Response(status=204)

    app = web.Application()
    app.router.add_get('/', empty_response)

    async with running_app(app, unused_tcp_port) as base_url:
        result = await AsyncFetcher.fetch(url=base_url)

    assert result == ''


@pytest.mark.asyncio
async def test_fetch_returns_empty_string_for_malformed_json(unused_tcp_port: int) -> None:
    async def malformed_response(_request: web.Request) -> web.Response:
        return web.Response(text='{not-json', content_type='application/json')

    app = web.Application()
    app.router.add_get('/', malformed_response)

    async with running_app(app, unused_tcp_port) as base_url:
        result = await AsyncFetcher.fetch(url=base_url, json=True)

    assert result == ''


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('status', 'body'),
    [(401, 'authentication required'), (429, 'rate limited')],
    ids=('authentication', 'rate-limit'),
)
async def test_fetch_returns_error_response_body(unused_tcp_port: int, status: int, body: str) -> None:
    async def error_response(_request: web.Request) -> web.Response:
        return web.Response(status=status, text=body)

    app = web.Application()
    app.router.add_get('/', error_response)

    async with running_app(app, unused_tcp_port) as base_url:
        result = await AsyncFetcher.fetch(url=base_url)

    assert result == body


@pytest.mark.asyncio
async def test_fetch_returns_empty_string_on_request_timeout(unused_tcp_port: int) -> None:
    release_response = asyncio.Event()

    async def wait_forever(_request: web.Request) -> web.Response:
        await release_response.wait()
        return web.Response(text='too late')

    app = web.Application()
    app.router.add_get('/', wait_forever)

    async with running_app(app, unused_tcp_port) as base_url:
        result = await AsyncFetcher.fetch(url=base_url, request_timeout=0.01)
        release_response.set()

    assert result == ''


@pytest.mark.asyncio
async def test_fetch_returns_empty_string_on_transport_failure(unused_tcp_port: int) -> None:
    result = await AsyncFetcher.fetch(url=f'http://127.0.0.1:{unused_tcp_port}')

    assert result == ''


@pytest.mark.asyncio
async def test_fetch_closes_only_the_session_it_creates(unused_tcp_port: int) -> None:
    transports: list[asyncio.Transport] = []

    async def record_transport(request: web.Request) -> web.Response:
        assert request.transport is not None
        transports.append(request.transport)
        return web.Response(text='ok')

    app = web.Application()
    app.router.add_get('/', record_transport)

    async with running_app(app, unused_tcp_port) as base_url:
        async with aiohttp.ClientSession() as caller_session:
            caller_result = await AsyncFetcher.fetch(session=caller_session, url=base_url)
            caller_session_open = not caller_session.closed and not transports[0].is_closing()

        owned_result = await AsyncFetcher.fetch(url=base_url)
        await asyncio.sleep(0)
        owned_transport_closed = transports[1].is_closing()

    assert (caller_result, caller_session_open, owned_result, owned_transport_closed) == ('ok', True, 'ok', True)


@pytest.mark.asyncio
async def test_fetch_applies_tls_verification_option(unused_tcp_port: int) -> None:
    async def secure_response(_request: web.Request) -> web.Response:
        return web.Response(text='secure response')

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(
        FIXTURES_DIR / 'localhost-cert.pem',
        FIXTURES_DIR / 'localhost-key.pem',
    )
    app = web.Application()
    app.router.add_get('/', secure_response)

    async with running_app(app, unused_tcp_port, ssl_context=server_context) as base_url:
        verified_result = await AsyncFetcher.fetch(url=base_url)
        unverified_result = await AsyncFetcher.fetch(url=base_url, verify=False)

    assert (verified_result, unverified_result) == ('', 'secure response')


@pytest.mark.asyncio
async def test_fetch_allows_aiohttp_default_tls_trust(unused_tcp_port: int) -> None:
    async def secure_response(_request: web.Request) -> web.Response:
        return web.Response(text='secure response')

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(
        FIXTURES_DIR / 'localhost-cert.pem',
        FIXTURES_DIR / 'localhost-key.pem',
    )
    aiohttp_default_context = ssl.create_default_context(cafile=FIXTURES_DIR / 'localhost-cert.pem')
    app = web.Application()
    app.router.add_get('/', secure_response)

    async with running_app(app, unused_tcp_port, ssl_context=server_context) as base_url:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=aiohttp_default_context)) as session:
            certifi_result = await AsyncFetcher.fetch(
                session=session,
                url=base_url,
                response_delay=0,
            )
            aiohttp_default_result = await AsyncFetcher.fetch(
                session=session,
                url=base_url,
                use_system_ssl=True,
                response_delay=0,
            )

    assert (certifi_result, aiohttp_default_result) == ('', 'secure response')


@pytest.mark.asyncio
async def test_fetch_rejects_conflicting_tls_controls(unused_tcp_port: int) -> None:
    request_count = 0

    async def response(_request: web.Request) -> web.Response:
        nonlocal request_count
        request_count += 1
        return web.Response(text='unexpected')

    app = web.Application()
    app.router.add_get('/', response)

    async with running_app(app, unused_tcp_port) as base_url:
        with pytest.raises(ValueError, match='use_system_ssl cannot be combined with verify=False'):
            await AsyncFetcher.fetch(
                url=base_url,
                verify=False,
                use_system_ssl=True,
                response_delay=0,
            )

    assert request_count == 0


@pytest.mark.asyncio
async def test_fetch_routes_http_proxy_requests_through_proxy() -> None:
    request_lines: list[str] = []

    async def proxy_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await reader.readuntil(b'\r\n\r\n')
            request_lines.append(request.split(b'\r\n', 1)[0].decode())
            writer.write(http_response('http proxy response'))
            await writer.drain()
        finally:
            await close_writer(writer)

    async with running_raw_server(proxy_handler) as (host, port):
        result = await AsyncFetcher.fetch(
            url='http://example.test/resource?query=value',
            proxy=f'http://{host}:{port}',
        )

    assert (result, request_lines) == (
        'http proxy response',
        ['GET http://example.test/resource?query=value HTTP/1.1'],
    )


@pytest.mark.asyncio
async def test_fetch_routes_socks_proxy_requests_through_proxy() -> None:
    observed: dict[str, Any] = {}

    async def socks_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            version, method_count = await reader.readexactly(2)
            methods = await reader.readexactly(method_count)
            observed['greeting'] = (version, methods)
            writer.write(b'\x05\x00')
            await writer.drain()

            version, command, _reserved, address_type = await reader.readexactly(4)
            if address_type == 3:
                host_length = (await reader.readexactly(1))[0]
                destination_host = (await reader.readexactly(host_length)).decode()
            elif address_type == 1:
                destination_host = socket.inet_ntoa(await reader.readexactly(4))
            else:
                raise AssertionError(f'Unexpected SOCKS address type: {address_type}')
            destination_port = int.from_bytes(await reader.readexactly(2), 'big')
            observed['connect'] = (version, command, destination_host, destination_port)

            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            await writer.drain()
            request = await reader.readuntil(b'\r\n\r\n')
            observed['request_line'] = request.split(b'\r\n', 1)[0].decode()
            writer.write(http_response('socks proxy response'))
            await writer.drain()
        finally:
            await close_writer(writer)

    async with running_raw_server(socks_handler) as (host, port):
        result = await AsyncFetcher.fetch(
            url='http://example.test:8080/resource',
            proxy=f'socks5://{host}:{port}',
        )

    assert (result, observed) == (
        'socks proxy response',
        {
            'greeting': (5, b'\x00'),
            'connect': (5, 1, 'example.test', 8080),
            'request_line': 'GET /resource HTTP/1.1',
        },
    )

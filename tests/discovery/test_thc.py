#!/usr/bin/env python3
# coding=utf-8
"""
Tests for THC (ip.thc.org) discovery module.

THC provides multiple endpoints:
- Subdomain enumeration
- CNAME lookup
- Reverse DNS lookup

API Documentation: https://ip.thc.org/docs/
"""

from types import TracebackType
from typing import Any, Self
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from theHarvester.discovery import thc
from theHarvester.lib.core import Core


class FakeResponse:
    def __init__(self, text: str, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self._text = text
        self.status = status
        self.headers = headers or {}

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
    def __init__(self, **_kwargs: Any) -> None:
        pass

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
        domain = parse_qs(urlparse(url).query).get('domain', ['example.com'])[0]
        return FakeResponse(f'WWW.{domain}\napi.{domain}\napi.{domain}\nnot{domain}\n')


@pytest.fixture(autouse=True)
def fake_thc_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(thc.aiohttp, 'ClientSession', FakeSession)


# =============================================================================
# 1. Direct API Tests (Endpoint Validation)
# =============================================================================
@pytest.mark.live_network
class TestThcApi:
    """Tests to validate that the THC API responds correctly."""

    def test_api_subdomains_download_endpoint_responds(self) -> None:
        """Verify that the subdomain download endpoint responds."""
        url = 'https://ip.thc.org/api/v1/subdomains/download?domain=example.com&limit=10&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        assert response.status_code == 200

    def test_api_subdomains_returns_text_format(self) -> None:
        """Verify that the response is plain text."""
        url = 'https://ip.thc.org/api/v1/subdomains/download?domain=example.com&limit=5&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        content_type = response.headers.get('content-type', '')
        assert 'text' in content_type or 'octet-stream' in content_type

    def test_api_cli_subdomain_endpoint(self) -> None:
        """Verify CLI endpoint /sb/{domain}."""
        url = 'https://ip.thc.org/sb/example.com?l=5&noheader'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        assert response.status_code == 200

    def test_api_returns_rate_limit_headers(self) -> None:
        """Verify that the API returns rate limit headers."""
        url = 'https://ip.thc.org/api/v1/subdomains/download?domain=example.com&limit=1&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        assert 'x-ratelimit-limit' in response.headers
        assert 'x-ratelimit-remaining' in response.headers


# =============================================================================
# 2. Subdomain Search Tests (Main Functionality)
# =============================================================================
class TestThcSubdomainSearch:
    """Tests for subdomain search functionality."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @staticmethod
    def small_domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_search_returns_set(self) -> None:
        """Verify that get_hostnames() returns a set."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_finds_subdomains(self) -> None:
        """Verify that it finds subdomains for a known domain."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        assert result == {'www.example.com', 'api.example.com'}

    @pytest.mark.asyncio
    async def test_search_results_contain_target_domain(self) -> None:
        """Verify that all results contain the target domain."""
        search = thc.SearchThc(self.small_domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert self.small_domain() in hostname, f'{hostname} should contain {self.small_domain()}'

    @pytest.mark.asyncio
    async def test_search_no_duplicates(self) -> None:
        """Verify that there are no duplicates in the results."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        result_list = list(result)
        assert len(result_list) == len(set(result_list))

    @pytest.mark.asyncio
    async def test_request_uses_declared_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        requested_urls: list[str] = []

        class CaptureSession(FakeSession):
            def get(self, url: str) -> FakeResponse:
                requested_urls.append(url)
                return FakeResponse('')

        monkeypatch.setattr(thc.aiohttp, 'ClientSession', CaptureSession)
        search = thc.SearchThc(self.domain())
        await search.process()

        assert requested_urls == [
            'https://ip.thc.org/api/v1/subdomains/download?domain=example.com&limit=10000&hide_header=true'
        ]

    @pytest.mark.asyncio
    async def test_rate_limit_is_attributed_and_retried(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        responses = iter(
            [
                FakeResponse('', status=429, headers={'x-ratelimit-remaining': '0'}),
                FakeResponse('api.example.com\n'),
            ]
        )

        class RateLimitSession(FakeSession):
            def get(self, _url: str) -> FakeResponse:
                return next(responses)

        delays: list[int] = []

        async def fake_sleep(seconds: int) -> None:
            delays.append(seconds)

        monkeypatch.setattr(thc.aiohttp, 'ClientSession', RateLimitSession)
        monkeypatch.setattr(thc.asyncio, 'sleep', fake_sleep)
        search = thc.SearchThc(self.domain())
        await search.process()

        assert await search.get_hostnames() == {'api.example.com'}
        assert delays == [2]
        assert 'THC rate limit hit' in capsys.readouterr().out

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ('response', 'message'),
        [
            (FakeResponse('outside.test\nnotexample.com\n'), ''),
            (FakeResponse('', status=503), 'THC returned status 503'),
        ],
    )
    async def test_empty_and_error_responses_return_no_hostnames(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        response: FakeResponse,
        message: str,
    ) -> None:
        class ResponseSession(FakeSession):
            def get(self, _url: str) -> FakeResponse:
                return response

        monkeypatch.setattr(thc.aiohttp, 'ClientSession', ResponseSession)
        search = thc.SearchThc(self.domain())
        await search.process()

        assert await search.get_hostnames() == set()
        if message:
            assert message in capsys.readouterr().out


# =============================================================================
# 3. Edge Case Tests
# =============================================================================
class TestThcEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_search_nonexistent_domain(self) -> None:
        """Verify behavior with non-existent domain."""
        search = thc.SearchThc('this-domain-definitely-does-not-exist-12345.com')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_empty_domain(self) -> None:
        """Verify behavior with empty domain."""
        search = thc.SearchThc('')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_special_characters_domain(self) -> None:
        """Verify behavior with special characters."""
        search = thc.SearchThc('example.com; DROP TABLE domains;--')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_unicode_domain(self) -> None:
        """Verify behavior with IDN/unicode domain."""
        search = thc.SearchThc('xn--mnchen-3ya.de')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_subdomain_as_input(self) -> None:
        """Verify behavior when a subdomain is passed as input."""
        search = thc.SearchThc('www.example.com')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)


# =============================================================================
# 4. Proxy Tests
# =============================================================================
class TestThcProxy:
    """Tests for proxy functionality."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_process_accepts_proxy_parameter(self) -> None:
        """Verify that process() accepts proxy parameter."""
        search = thc.SearchThc(self.domain())
        await search.process(proxy=False)
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_proxy_attribute_is_set(self) -> None:
        """Verify that the proxy attribute is set correctly."""
        search = thc.SearchThc(self.domain())
        assert search.proxy is False


# =============================================================================
# 5. Initialization and Attributes Tests
# =============================================================================
class TestThcInitialization:
    """Tests for class initialization and structure."""

    def test_init_sets_word(self) -> None:
        """Verify that __init__ sets the domain."""
        domain = 'test.com'
        search = thc.SearchThc(domain)
        assert search.word == domain

    def test_init_creates_empty_results(self) -> None:
        """Verify that results is initialized empty."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'results')
        assert len(search.results) == 0

    def test_init_proxy_default_false(self) -> None:
        """Verify that proxy is False by default."""
        search = thc.SearchThc('test.com')
        assert search.proxy is False

    def test_init_has_rate_limit_settings(self) -> None:
        """Verify that rate limit settings are initialized."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'max_retries')
        assert hasattr(search, 'base_delay')
        assert search.max_retries == 3
        assert search.base_delay == 2

    def test_class_has_required_methods(self) -> None:
        """Verify that the class has the required methods."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'do_search')
        assert hasattr(search, 'get_hostnames')
        assert hasattr(search, 'process')
        assert callable(search.do_search)
        assert callable(search.get_hostnames)
        assert callable(search.process)


# =============================================================================
# 6. Response Format Tests
# =============================================================================
class TestThcResponseFormat:
    """Tests to verify response format."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_hostnames_are_strings(self) -> None:
        """Verify that all hostnames are strings."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert isinstance(hostname, str)

    @pytest.mark.asyncio
    async def test_hostnames_are_valid_format(self) -> None:
        """Verify that hostnames have valid format."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert ' ' not in hostname
            assert '\n' not in hostname
            assert '\t' not in hostname

    @pytest.mark.asyncio
    async def test_hostnames_are_lowercase(self) -> None:
        """Verify that hostnames are lowercase."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert hostname == hostname.lower()


# =============================================================================
# 7. Integration Tests with theHarvester
# =============================================================================
class TestThcIntegration:
    """Integration tests with theHarvester framework."""

    @pytest.mark.asyncio
    async def test_module_can_be_imported(self) -> None:
        """Verify that the module can be imported."""
        from theHarvester.discovery import thc as thc_module

        assert thc_module is not None

    @pytest.mark.asyncio
    async def test_search_class_exists(self) -> None:
        """Verify that SearchThc class exists."""
        from theHarvester.discovery import thc as thc_module

        assert hasattr(thc_module, 'SearchThc')

    @pytest.mark.asyncio
    async def test_compatible_with_store_function(self) -> None:
        """Verify compatibility with store function from __main__.py."""
        search = thc.SearchThc('example.com')
        assert hasattr(search, 'process')
        assert hasattr(search, 'get_hostnames')


if __name__ == '__main__':
    pytest.main()

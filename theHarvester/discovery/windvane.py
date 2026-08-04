import json as _stdlib_json
import logging
from types import ModuleType
from typing import Any

from theHarvester.lib.core import AsyncFetcher, Core

logger = logging.getLogger(__name__)

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError:
    pass
except Exception:
    pass


class SearchWindvane:
    """Class uses the Windvane API to gather subdomains and domain intelligence
    API Documentation: https://windvane.lichoin.com

    The API provides several endpoints:
    - /ListSubDomain - Subdomain enumeration
    - /ListDNS - DNS history analysis
    - /ListDomainWhois - Historical whois lookup
    - /ListEmail - Domain name email query

    Note: This API requires authentication for full access.
    - With API key: Full access to all endpoints with pagination
    - Without API key: Limited unauthenticated endpoint access

    Set API key via:
    - Environment variable: export WINDVANE_API_KEY="your-key"
    - Or call search.set_api_key("your-key")
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.totalemails: set = set()
        self.proxy = False
        self.hostname = 'https://windvane.lichoin.com/trpc.backendhub.public.WindvaneService'
        self.api_key = self._get_api_key()

    def _get_api_key(self) -> str | None:
        try:
            api_key = Core.windvane_key()
        except (KeyError, TypeError):
            return None
        if api_key is None:
            return None
        if not isinstance(api_key, str):
            raise ValueError('Windvane API key must be a string')
        return api_key.strip() or None

    @staticmethod
    def _parse_json(payload: object) -> dict[str, object]:
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, str):
            try:
                parsed = json.loads(payload)
            except (TypeError, ValueError) as error:
                raise ValueError('Windvane returned invalid JSON') from error
            if isinstance(parsed, dict):
                return parsed
        raise ValueError('Windvane returned an invalid response')

    @staticmethod
    def _nonblank_string(value: object) -> str | None:
        if isinstance(value, str) and (stripped := value.strip()):
            return stripped
        return None

    @classmethod
    def _parse_items(cls, payload: object) -> tuple[list[dict[str, Any]], bool]:
        response_data = cls._parse_json(payload)
        code = response_data.get('code')
        if type(code) is not int:
            raise ValueError('Windvane response is missing a valid code')
        if code != 0:
            raise RuntimeError(f'Windvane API returned code {code}')
        data_section = response_data.get('data')
        if not isinstance(data_section, dict):
            raise ValueError('Windvane response has invalid data')
        items = data_section.get('list')
        if not isinstance(items, list):
            raise ValueError('Windvane response has invalid results')
        valid_items = [item for item in items if isinstance(item, dict)]
        return valid_items, len(valid_items) != len(items)

    async def do_search(self) -> None:
        """Main search function that queries multiple Windvane API endpoints"""
        headers = {'User-agent': Core.get_user_agent(), 'Content-Type': 'application/json', 'Accept': 'application/json'}

        if self.api_key:
            headers['X-Api-Key'] = self.api_key
            execution_error: Exception | None = None
            for search in (self._search_subdomains, self._search_dns_history, self._search_emails):
                try:
                    await search(headers)
                except Exception as error:
                    logger.info(f'Windvane API error: {error}')
                    if execution_error is None:
                        execution_error = error
            if execution_error is not None:
                raise execution_error
        else:
            logger.info('[*] Windvane API key not found. Using limited unauthenticated access.')
            await self._search_subdomains_limited(headers)

    async def _search_subdomains(self, headers: dict) -> None:
        """Search for subdomains using /ListSubDomain endpoint"""
        url = f'{self.hostname}/ListSubDomain'
        for page in range(1, 4):
            data = {'domain': self.word, 'page_request': {'page': page, 'count': 30}}
            response = await AsyncFetcher.post_fetch(
                url,
                headers=headers,
                data=json.dumps(data),
                proxy=self.proxy,
                fail_on_http_error=True,
                raise_on_error=True,
            )
            subdomains, malformed_row = self._parse_items(response)
            for item in subdomains:
                domain = self._nonblank_string(item.get('domain'))
                if domain is None:
                    malformed_row = True
                    continue
                if domain and domain.endswith(self.word):
                    self.totalhosts.add(domain.lower())
            if malformed_row:
                raise ValueError('Windvane returned malformed subdomain data')
            if not subdomains:
                return
        raise RuntimeError('Windvane subdomain page limit reached')

    async def _search_dns_history(self, headers: dict) -> None:
        """Search DNS history using /ListDNS endpoint for additional subdomains and IPs"""
        url = f'{self.hostname}/ListDNS'
        for page in range(1, 3):
            data = {'domain': self.word, 'page_request': {'page': page, 'count': 30}}
            response = await AsyncFetcher.post_fetch(
                url,
                headers=headers,
                data=json.dumps(data),
                proxy=self.proxy,
                fail_on_http_error=True,
                raise_on_error=True,
            )
            dns_records, malformed_row = self._parse_items(response)
            for record in dns_records:
                domain = self._nonblank_string(record.get('domain'))
                answer = self._nonblank_string(record.get('answer'))
                answer_type = self._nonblank_string(record.get('answer_type'))
                if domain is None or answer is None or answer_type is None:
                    malformed_row = True
                    continue
                if domain.endswith(self.word):
                    self.totalhosts.add(domain.lower())
                if answer_type == 'A' and self._is_valid_ip(answer):
                    self.totalips.add(answer)
            if malformed_row:
                raise ValueError('Windvane returned malformed DNS history data')
            if not dns_records:
                return
        raise RuntimeError('Windvane DNS history page limit reached')

    async def _search_emails(self, headers: dict) -> None:
        """Search for emails using /ListEmail endpoint"""
        url = f'{self.hostname}/ListEmail'
        data = {'email': self.word, 'page_request': {'page': 1, 'count': 50}}
        response = await AsyncFetcher.post_fetch(
            url,
            headers=headers,
            data=json.dumps(data),
            proxy=self.proxy,
            fail_on_http_error=True,
            raise_on_error=True,
        )
        email_results, malformed_row = self._parse_items(response)
        for item in email_results:
            email = self._nonblank_string(item.get('email'))
            domain_value = item.get('domain')
            domain = self._nonblank_string(domain_value)
            if email is None or (domain_value not in (None, '') and domain is None):
                malformed_row = True
                continue
            if self.word in email:
                self.totalemails.add(email.lower())
            if domain and domain.endswith(self.word):
                self.totalhosts.add(domain.lower())
        if malformed_row:
            raise ValueError('Windvane returned malformed email data')

    async def _search_subdomains_limited(self, headers: dict) -> None:
        """Limited subdomain search without API key - tries simpler approaches"""
        url = f'{self.hostname}/ListSubDomain'
        data = {'domain': self.word, 'page_request': {'page': 1, 'count': 10}}
        response = await AsyncFetcher.post_fetch(
            url,
            headers=headers,
            data=json.dumps(data),
            proxy=self.proxy,
            fail_on_http_error=True,
            raise_on_error=True,
        )
        subdomains, malformed_row = self._parse_items(response)

        for item in subdomains:
            domain = self._nonblank_string(item.get('domain'))
            if domain is None:
                malformed_row = True
                continue
            if domain and domain.endswith(self.word):
                self.totalhosts.add(domain.lower())

        if malformed_row:
            raise ValueError('Windvane returned malformed subdomain data')

        logger.info(f'[*] Found {len(subdomains)} subdomains with limited access')

    def set_api_key(self, api_key: str) -> None:
        """Set the API key for authenticated requests

        Args:
            api_key: Windvane API key for authenticated access

        """
        self.api_key = api_key.strip() or None

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate if string is a valid IP address"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, TypeError):
            return False

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def get_emails(self) -> set:
        return self.totalemails

    async def process(self, proxy: bool = False) -> None:
        """Process the search with optional proxy and API key configuration

        Args:
            proxy: Whether to use proxy for requests

        """
        self.proxy = proxy

        # API key is already set via _get_api_key() method

        await self.do_search()

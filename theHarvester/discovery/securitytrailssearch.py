import asyncio

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import securitytrailsparser


class SearchSecuritytrail:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.security_trails_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('Securitytrail')
        self.api = 'https://api.securitytrails.com/v1/'
        self.info: tuple[set, set] = (set(), set())
        self.proxy = False
        # Hold structured responses for robust parsing
        self.domain_data: dict = {}
        self.subdomains_data: dict = {}

    async def authenticate(self) -> None:
        # Method to authenticate API key before sending requests.
        headers = {'APIKEY': self.key}
        url = f'{self.api}ping'
        auth_response = await AsyncFetcher.fetch(
            url=url,
            headers=headers,
            proxy=self.proxy,
            request_timeout=60,
            fail_on_http_error=True,
            raise_on_error=True,
        )
        if not isinstance(auth_response, str) or not auth_response.strip():
            raise ValueError('SecurityTrails returned an invalid authentication response')
        if 'False' in auth_response or 'Invalid authentication' in auth_response:
            raise RuntimeError('SecurityTrails authentication failed')
        await asyncio.sleep(5)

    async def do_search(self) -> None:
        # https://api.securitytrails.com/v1/domain/domain.com
        domain_url = f'{self.api}domain/{self.word}'
        headers = {'APIKEY': self.key, 'Accept': 'application/json'}
        domain_response = await AsyncFetcher.fetch(
            url=domain_url,
            headers=headers,
            json=True,
            proxy=self.proxy,
            request_timeout=60,
            fail_on_http_error=True,
            raise_on_error=True,
        )
        await asyncio.sleep(5)  # 2+ seconds is required due to rate limit.
        if not isinstance(domain_response, dict):
            raise ValueError('SecurityTrails returned an invalid domain response')
        if any(domain_response.get(key) for key in ('error', 'message', 'detail')):
            raise RuntimeError('SecurityTrails returned a provider error')
        self.domain_data = domain_response
        self.info = await securitytrailsparser.Parser(word=self.word, text=domain_response).parse_text()

        # Get subdomains now.
        subdomains_url = f'{domain_url}/subdomains'
        subdomain_response = await AsyncFetcher.fetch(
            url=subdomains_url,
            headers=headers,
            json=True,
            proxy=self.proxy,
            request_timeout=60,
            fail_on_http_error=True,
            raise_on_error=True,
        )
        await asyncio.sleep(5)
        if not isinstance(subdomain_response, dict):
            raise ValueError('SecurityTrails returned an invalid subdomain response')
        if any(subdomain_response.get(key) for key in ('error', 'message', 'detail')):
            raise RuntimeError('SecurityTrails returned a provider error')
        subdomains = subdomain_response.get('subdomains')
        if not isinstance(subdomains, list) or any(
            not isinstance(subdomain, str) or not subdomain.strip() for subdomain in subdomains
        ):
            raise ValueError('SecurityTrails returned invalid subdomains')
        self.subdomains_data = subdomain_response

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.authenticate()
        await self.do_search()
        parser = securitytrailsparser.Parser(
            word=self.word,
            text={'domain': self.domain_data, 'subdomains': self.subdomains_data},
        )
        self.info = await parser.parse_text()

    async def get_ips(self) -> set:
        return self.info[0]

    async def get_hostnames(self) -> set:
        return self.info[1]

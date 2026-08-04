import json as _stdlib_json
from types import ModuleType

from theHarvester.lib.core import AsyncFetcher, Core

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError:
    pass
except Exception:
    pass


class SearchThreatcrowd:
    """Class uses ThreatCrowd API to gather domain intelligence and subdomains"""

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False
        self.hostname = 'http://ci-www.threatcrowd.org'

    @staticmethod
    def _parse_json(payload: object) -> dict:
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception as error:
                raise ValueError('ThreatCrowd returned an invalid payload') from error
        if not isinstance(payload, dict):
            raise ValueError('ThreatCrowd returned an invalid payload')
        return payload

    async def do_search(self) -> None:
        headers = {'User-agent': Core.get_user_agent()}
        url = f'{self.hostname}/searchApi/v2/domain/report/?domain={self.word}'
        response = await AsyncFetcher.fetch(
            url=url,
            headers=headers,
            proxy=self.proxy,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        data = self._parse_json(response)
        response_code = data.get('response_code')
        if response_code not in (1, '1'):
            raise ValueError(f'ThreatCrowd API returned error code: {response_code}')

        subdomains = data.get('subdomains')
        resolutions = data.get('resolutions')
        if not isinstance(subdomains, list) or not isinstance(resolutions, list):
            raise ValueError('ThreatCrowd returned invalid result collections')
        for subdomain in subdomains:
            if isinstance(subdomain, str) and subdomain.strip():
                clean_subdomain = subdomain.strip().lower()
                if clean_subdomain.endswith(f'.{self.word}') or clean_subdomain == self.word:
                    self.totalhosts.add(clean_subdomain)

        for resolution in resolutions:
            if isinstance(resolution, dict):
                ip = resolution.get('ip_address', '')
                if ip and ip.strip():
                    self.totalips.add(ip.strip())
            elif isinstance(resolution, str) and resolution.strip():
                self.totalips.add(resolution.strip())

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchChaos:
    """Class uses ProjectDiscovery Chaos subdomain enumeration API"""

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.proxy = False
        self.hostname = 'https://dns.projectdiscovery.io'
        self.key = self._get_api_key()

    def _get_api_key(self) -> str:
        """Get Chaos API key"""
        try:
            key = Core.projectdiscovery_key()
        except KeyError as error:
            raise MissingKey('Chaos (ProjectDiscovery)') from error
        if not key:
            raise MissingKey('Chaos (ProjectDiscovery)')
        return key

    async def do_search(self) -> None:
        headers = {'User-agent': Core.get_user_agent(), 'Authorization': f'Bearer {self.key}'}
        url = f'{self.hostname}/dns/{self.word}/subdomains'
        data = await AsyncFetcher.fetch(
            url=url,
            headers=headers,
            proxy=self.proxy,
            json=True,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if isinstance(data, dict):
            if 'error' in data:
                message = data.get('message', data['error'])
                if 'unauthorized' in str(message).lower():
                    raise PermissionError('Chaos rejected the configured credentials')
                raise RuntimeError(f'Chaos returned an error: {message}')
            result_found = False
            subdomains = []
            for key in ('subdomains', 'data', 'results'):
                if key not in data:
                    continue
                result_found = True
                subdomains = data[key]
                if subdomains:
                    break
            if not result_found:
                raise ValueError('Chaos returned an invalid payload')
        elif isinstance(data, list):
            subdomains = data
        else:
            raise ValueError('Chaos returned an invalid payload')

        if not isinstance(subdomains, list):
            raise ValueError('Chaos returned invalid subdomains')
        for subdomain in subdomains:
            if isinstance(subdomain, str):
                label = subdomain
            elif isinstance(subdomain, dict):
                label = subdomain.get('subdomain', '') or subdomain.get('name', '')
                if not isinstance(label, str) or not label:
                    raise ValueError('Chaos returned an invalid subdomain')
            else:
                raise ValueError('Chaos returned an invalid subdomain')
            full_domain = f'{label}.{self.word}' if label else self.word
            self.totalhosts.add(full_domain.lower())

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchDiscovery:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.projectdiscovery_key()
        if not self.key or not self.key.strip():
            raise MissingKey('ProjectDiscovery')
        self.total_results: list[str] = []
        self.proxy: bool = False

    async def do_search(self):
        url = f'https://dns.projectdiscovery.io/dns/{self.word}/subdomains'
        response = await AsyncFetcher.fetch(
            url=url,
            json=True,
            headers={'User-Agent': Core.get_user_agent(), 'Authorization': self.key},
            proxy=self.proxy,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if not isinstance(response, dict) or not isinstance(response.get('subdomains'), list):
            raise ValueError('ProjectDiscovery returned an invalid payload')
        self.total_results = [f'{domain}.{self.word}' for domain in response['subdomains']]

    async def get_hostnames(self):
        return self.total_results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

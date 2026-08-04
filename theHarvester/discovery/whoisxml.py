from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchWhoisXML:
    def __init__(self, word) -> None:
        self.word = word
        self.key = Core.whoisxml_key()
        if not self.key or not self.key.strip():
            raise MissingKey('whoisxml')
        self.total_results: list[str] = []
        self.proxy: bool = False

    async def do_search(self):
        # https://subdomains.whoisxmlapi.com/api/documentation/making-requests
        url = 'https://subdomains.whoisxmlapi.com/api/v1'
        params = {'apiKey': self.key, 'domainName': self.word}
        response = await AsyncFetcher.fetch(
            url=url,
            json=True,
            params=params,
            headers={'User-Agent': Core.get_user_agent()},
            proxy=self.proxy,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if not isinstance(response, dict):
            raise ValueError('WhoisXML returned an invalid payload')
        result = response.get('result')
        if not isinstance(result, dict) or not isinstance(result.get('records'), list):
            raise ValueError('WhoisXML returned an invalid payload')
        self.total_results = [record['domain'] for record in result['records']]

    async def get_hostnames(self):
        return self.total_results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

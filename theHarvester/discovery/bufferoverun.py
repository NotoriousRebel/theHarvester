import re

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchBufferover:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.key = Core.bufferoverun_key()
        if not self.key:
            raise MissingKey('bufferoverun')
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://tls.bufferover.run/dns?q={self.word}'
        response = await AsyncFetcher.fetch(
            url=url,
            json=True,
            headers={'User-Agent': Core.get_user_agent(), 'x-api-key': f'{self.key}'},
            proxy=self.proxy,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if not isinstance(response, dict) or not isinstance(response.get('Results'), list):
            raise ValueError('BufferOverrun returned an invalid payload')
        results = response['Results']
        if results:
            self.totalhosts = {
                (
                    host.split(',')
                    if ',' in host and self.word.replace('www.', '') in host.split(',')[0] in host
                    else host.split(',')[4]
                )
                for host in results
            }

        self.totalips = {
            ip.split(',')[0] for ip in results if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip.split(',')[0])
        }

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

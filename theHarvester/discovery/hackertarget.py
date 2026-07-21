# theHarvester/discovery/hackertarget.py
import ipaddress

from theHarvester.lib.core import AsyncFetcher, Core


class SearchHackerTarget:
    """Class uses the HackerTarget API to gather subdomains and IPs.

    Provider APIs:
    https://hackertarget.com/hostsearch/
    https://hackertarget.com/reverse-dns-lookup/
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.totalips: set[str] = set()
        self.hostname = 'https://api.hackertarget.com'
        self.proxy = False
        self.results = None
        self.key = Core.hackertarget_key()

    async def do_search(self) -> None:
        headers = {'User-agent': Core.get_user_agent()}

        # base URLs used by the original implementation
        base_urls = [
            f'{self.hostname}/hostsearch/?q={self.word}',
            f'{self.hostname}/reversedns/?q={self.word}',
        ]

        # if user supplied an API key in api-keys.yml (or repo loader), append it
        if self.key:
            request_urls = [f'{u}&apikey={self.key}' for u in base_urls]
        else:
            request_urls = base_urls

        # fetch all using existing AsyncFetcher helper
        responses = await AsyncFetcher.fetch_all(request_urls, headers=headers, proxy=self.proxy)

        for index, response in enumerate(responses[:2]):
            if not isinstance(response, str):
                continue
            for line in response.splitlines():
                fields = [field.strip() for field in line.split(',', 1)]
                if len(fields) != 2:
                    continue
                hostname, address = fields if index == 0 else fields[::-1]
                if not hostname:
                    continue
                try:
                    ipaddress.ip_address(address)
                except ValueError:
                    continue
                self.totalhosts.add(hostname)
                self.totalips.add(address)

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_ips(self) -> set[str]:
        return self.totalips

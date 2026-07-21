import csv
import ipaddress

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchBufferover:
    """Query BufferOver's documented TLS DNS API.

    Provider API: https://tls.bufferover.run/
    Result rows: IP, certificate SHA-256, certificate organization, CN/SNI.
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.totalips: set[str] = set()
        self.key = Core.bufferoverun_key()
        if self.key is None:
            raise MissingKey('bufferoverun')
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://tls.bufferover.run/dns?q={self.word}'
        response = await AsyncFetcher.fetch_all(
            [url],
            json=True,
            headers={'User-Agent': Core.get_user_agent(), 'x-api-key': f'{self.key}'},
            proxy=self.proxy,
        )
        for row in csv.reader(response[0].get('Results') or []):
            if len(row) != 4:
                continue
            address, _certificate_hash, _organization, hostname = (value.strip() for value in row)
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            self.totalips.add(address)
            if hostname:
                self.totalhosts.add(hostname)

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_ips(self) -> set[str]:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

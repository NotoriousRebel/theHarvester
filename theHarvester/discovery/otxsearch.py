from ipaddress import ip_address
from typing import Any

from theHarvester.lib.core import AsyncFetcher
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchOtx:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.word}/passive_dns'
        try:
            response_list = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
        except (OSError, RuntimeError, ValueError):
            self.totalhosts = set()
            self.totalips = set()
            return

        # Expect a list with one JSON-decoded dict
        dct: Any = response_list[0] if response_list else {}
        if not isinstance(dct, dict):
            self.totalhosts = set()
            self.totalips = set()
            return

        passive = dct.get('passive_dns')
        if not isinstance(passive, list):
            self.totalhosts = set()
            self.totalips = set()
            return

        try:
            for record in passive:
                if not isinstance(record, dict):
                    continue
                hostname = record.get('hostname')
                normalized_hostname = normalize_scoped_hostname(hostname, self.word)
                if normalized_hostname:
                    self.totalhosts.add(normalized_hostname)
                address = record.get('address')
                if normalized_hostname and isinstance(address, str):
                    try:
                        self.totalips.add(str(ip_address(address.strip())))
                    except ValueError:
                        continue
        except (KeyError, TypeError, ValueError):
            self.totalhosts = set()
            self.totalips = set()

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

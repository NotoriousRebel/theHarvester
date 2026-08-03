import re

from theHarvester.lib.core import AsyncFetcher


class SearchOtx:
    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False

    async def do_search(self) -> None:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.word}/passive_dns'
        dct = await AsyncFetcher.fetch(
            url=url,
            json=True,
            proxy=self.proxy,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if not isinstance(dct, dict):
            raise ValueError('OTX returned an invalid payload')
        if dct.get('error'):
            raise RuntimeError('OTX returned a provider error')

        passive = dct.get('passive_dns')
        if not isinstance(passive, list):
            raise ValueError('OTX returned invalid passive DNS results')

        self.totalhosts = {host['hostname'] for host in passive if isinstance(host, dict) and 'hostname' in host}
        # filter out ips that are just called NXDOMAIN and ensure they look like IPv4
        self.totalips = {
            ip['address']
            for ip in passive
            if isinstance(ip, dict)
            and (addr := ip.get('address'))
            and isinstance(addr, str)
            and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', addr)
        }

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

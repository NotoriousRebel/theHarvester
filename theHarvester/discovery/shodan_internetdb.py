import asyncio
import logging
import socket

from theHarvester.lib.core import AsyncFetcher

logger = logging.getLogger(__name__)


class SearchShodanInternetDB:
    """Search Shodan InternetDB for IP intelligence data.

    Shodan InternetDB (https://internetdb.shodan.io/) is a free API that
    provides basic information about IP addresses including open ports,
    hostnames, vulnerabilities (CVEs), tags, and CPEs. No API key is required.

    This module first resolves the target domain to its IP addresses, then
    queries InternetDB for each IP to gather associated hostnames and other
    intelligence.
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.ports: set = set()
        self.vulns: set = set()
        self.tags: set = set()
        self.cpes: set = set()
        self.proxy = False

    async def do_search(self) -> None:
        # Resolve the domain to IP addresses first
        addr_infos = await asyncio.to_thread(socket.getaddrinfo, self.word, None, socket.AF_UNSPEC, socket.SOCK_STREAM)

        # Deduplicate IPs from the resolution results
        resolved_ips: set[str] = set()
        for _family, _type, _proto, _canonname, sockaddr in addr_infos:
            ip = sockaddr[0]
            if isinstance(ip, str):
                resolved_ips.add(ip)

        if not resolved_ips:
            logger.info(f'Shodan InternetDB: No IPs resolved for {self.word}')
            return

        # Query InternetDB for each resolved IP
        requested_ips = sorted(resolved_ips)
        urls = [f'https://internetdb.shodan.io/{ip}' for ip in requested_ips]
        responses = await asyncio.gather(
            *(
                AsyncFetcher.fetch(
                    url=url,
                    json=True,
                    proxy=self.proxy,
                    request_timeout=60,
                    fail_on_http_error=True,
                    raise_on_error=True,
                )
                for url in urls
            ),
            return_exceptions=True,
        )

        batch_error: Exception | None = None
        for requested_ip, response in zip(requested_ips, responses, strict=True):
            if isinstance(response, Exception):
                if isinstance(response, RuntimeError) and str(response) == 'HTTP 404':
                    continue
                batch_error = batch_error or response
                continue
            if not isinstance(response, dict):
                batch_error = batch_error or ValueError('Shodan InternetDB returned an invalid response')
                continue

            # A successful no-data response uses a "detail" value.
            if 'detail' in response:
                detail = response['detail']
                if isinstance(detail, str) and detail.strip() == 'No information available':
                    continue
                if isinstance(detail, str) and detail.strip():
                    batch_error = batch_error or RuntimeError('Shodan InternetDB returned a provider error')
                    continue
                batch_error = batch_error or ValueError('Shodan InternetDB returned an invalid response')
                continue
            if any(response.get(key) for key in ('error', 'message')):
                batch_error = batch_error or RuntimeError('Shodan InternetDB returned a provider error')
                continue
            if response.get('ip') != requested_ip:
                batch_error = batch_error or ValueError('Shodan InternetDB returned an invalid response')
                continue

            has_data = False
            hostnames = response.get('hostnames')
            if not isinstance(hostnames, list):
                batch_error = batch_error or ValueError('Shodan InternetDB returned an invalid response')
            else:
                for hostname in hostnames:
                    if type(hostname) is not str:
                        batch_error = batch_error or ValueError('Shodan InternetDB returned an invalid response')
                        continue
                    has_data = True
                    if hostname == self.word or hostname.endswith('.' + self.word):
                        self.totalhosts.add(hostname)

            for key, item_type, destination in (
                ('ports', int, self.ports),
                ('vulns', str, self.vulns),
                ('tags', str, self.tags),
                ('cpes', str, self.cpes),
            ):
                values = response.get(key)
                if not isinstance(values, list):
                    batch_error = batch_error or ValueError('Shodan InternetDB returned an invalid response')
                    continue
                for item in values:
                    if type(item) is not item_type:
                        batch_error = batch_error or ValueError('Shodan InternetDB returned an invalid response')
                        continue
                    has_data = True
                    destination.add(item)

            if has_data:
                self.totalips.add(requested_ip)

        if batch_error is not None:
            raise batch_error

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def get_ports(self) -> set:
        return self.ports

    async def get_vulns(self) -> set:
        return self.vulns

    async def get_tags(self) -> set:
        return self.tags

    async def get_cpes(self) -> set:
        return self.cpes

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

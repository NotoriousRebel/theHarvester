import json as _stdlib_json
import logging
from types import ModuleType

from theHarvester.lib.core import AsyncFetcher, Core

logger = logging.getLogger(__name__)

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError as e:
    logger.info(f"'ujson' not available. Falling back to standard 'json' module. Reason: {e}")
except (AttributeError, OSError, RuntimeError, SystemError, ValueError) as e:
    logger.info(f"Unexpected error while importing 'ujson'. Falling back to standard 'json'. Reason: {e}")


class SearchRobtex:
    """Class uses the Robtex passive DNS API to gather subdomains"""

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalips: set = set()
        self.proxy = False
        self.hostname = 'https://freeapi.robtex.com'

    async def do_search(self) -> None:
        headers = {'User-agent': Core.get_user_agent()}

        # Use passive DNS forward lookup to get subdomains
        url = f'{self.hostname}/pdns/forward/{self.word}'
        response = await AsyncFetcher.fetch(
            url=url,
            headers=headers,
            proxy=self.proxy,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if not isinstance(response, str):
            raise ValueError('Robtex returned an invalid response')

        # Extract subdomains from DNS records
        for line in response.splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except (TypeError, ValueError) as error:
                raise ValueError('Robtex returned malformed JSONL') from error
            if not isinstance(record, dict):
                raise ValueError('Robtex returned malformed JSONL')
            if 'error' in record:
                raise RuntimeError('Robtex returned a provider error')
            if not all(isinstance(record.get(field), str) for field in ('rrname', 'rrtype', 'rrdata')):
                raise ValueError('Robtex returned a malformed record')
            # Get the hostname from rrdata field for different record types
            rrdata = record.get('rrdata', '')
            rrtype = record.get('rrtype', '')
            rrname = record.get('rrname', '')

            # Add the original domain name
            if rrname and rrname.endswith(self.word):
                self.totalhosts.add(rrname)

            # For CNAME records, the rrdata contains hostnames
            if rrtype == 'CNAME' and rrdata:
                if rrdata.endswith(self.word) or f'.{self.word}' in rrdata:
                    self.totalhosts.add(rrdata.rstrip('.'))

            # For A records, we can get IPs
            if rrtype == 'A' and rrdata:
                try:
                    # Validate it's an IP
                    parts = rrdata.split('.')
                    if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                        self.totalips.add(rrdata)
                except (ValueError, TypeError):
                    pass

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

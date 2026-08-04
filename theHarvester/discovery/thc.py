import asyncio
import logging

import aiohttp

from theHarvester.lib.core import Core
from theHarvester.lib.hostnames import normalize_hostname

logger = logging.getLogger(__name__)


class SearchThc:
    """Class to search for subdomains using THC (ip.thc.org)."""

    def __init__(self, word: str) -> None:
        self.word = word
        self.results: set = set()
        self.proxy = False
        self.max_retries = 3
        self.base_delay = 2

    async def do_search(self) -> None:
        url = f'https://ip.thc.org/api/v1/subdomains/download?domain={self.word}&limit=10000&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}

        for attempt in range(self.max_retries):
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status == 429:
                        if attempt == self.max_retries - 1:
                            raise RuntimeError('THC rate limit retry limit exhausted')
                        rate_remaining = response.headers.get('x-ratelimit-remaining', '0')
                        wait_time = self.base_delay * (attempt + 1)
                        logger.info(f'THC rate limit hit (remaining: {rate_remaining}). Waiting {wait_time}s before retry...')
                        await asyncio.sleep(wait_time)
                        continue

                    if response.status != 200:
                        raise RuntimeError(f'THC returned HTTP {response.status}')

                    text = await response.text()
                    if not text.strip():
                        return
                    if normalize_hostname(self.word) is None:
                        return
                    malformed = False
                    for line in text.splitlines():
                        if not line.strip():
                            continue
                        hostname = normalize_hostname(line)
                        if hostname is None:
                            malformed = True
                            continue
                        self.results.add(hostname)
                    if malformed:
                        raise ValueError('THC returned an invalid response')
                    return

    async def get_hostnames(self) -> set:
        return self.results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

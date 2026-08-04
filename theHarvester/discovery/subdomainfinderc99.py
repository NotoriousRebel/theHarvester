import asyncio

import ujson
from bs4 import BeautifulSoup
from bs4.element import Tag

from theHarvester.discovery.constants import get_delay
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser


class SearchSubdomainfinderc99:
    def __init__(self, word) -> None:
        self.word = word
        self.total_results: set = set()
        self.proxy = False
        # TODO add api support
        self.server = 'https://subdomainfinder.c99.nl/'
        self.totalresults = ''

    async def do_search(self) -> None:
        # Based on https://gist.github.com/th3gundy/bc83580cbe04031e9164362b33600962
        headers = {'User-Agent': Core.get_user_agent()}
        response = await AsyncFetcher.fetch(
            url=self.server,
            headers=headers,
            proxy=self.proxy,
            request_timeout=60,
            fail_on_http_error=True,
            raise_on_error=True,
        )
        if not isinstance(response, str) or not response.strip():
            raise ValueError('SubdomainFinderC99 returned an invalid CSRF page')
        data = await self.get_csrf_params(response)
        if not any(name.casefold().startswith('csrf') and value.strip() for name, value in data.items()):
            raise ValueError('SubdomainFinderC99 returned an invalid CSRF page')

        data['scan_subdomains'] = ''
        data['domain'] = self.word
        data['privatequery'] = 'on'
        await asyncio.sleep(get_delay())
        second_resp = await AsyncFetcher.post_fetch(
            self.server,
            headers=headers,
            proxy=self.proxy,
            data=ujson.dumps(data),
            fail_on_http_error=True,
            raise_on_error=True,
        )
        if not isinstance(second_resp, str) or not second_resp.strip():
            raise ValueError('SubdomainFinderC99 returned an invalid result page')
        if 'CSRF token invalid or expired' in second_resp:
            raise RuntimeError('SubdomainFinderC99 rejected the CSRF token')
        result_table = BeautifulSoup(second_resp, 'html.parser').find('table', {'id': 'result_table'})
        if not isinstance(result_table, Tag):
            raise ValueError('SubdomainFinderC99 returned an invalid result page')

        self.totalresults += second_resp

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    @staticmethod
    async def get_csrf_params(data):
        csrf_params: dict[str, str] = {}
        html = BeautifulSoup(data, 'html.parser').find('div', {'class': 'input-group'})
        if not isinstance(html, Tag):
            return csrf_params
        for c in html.find_all('input'):
            try:
                if not isinstance(c, Tag):
                    continue
                name = c.get('name')
                value = c.get('value')
                if isinstance(name, str) and name and value is not None:
                    csrf_params[name] = str(value)
            except Exception:
                continue

        return csrf_params

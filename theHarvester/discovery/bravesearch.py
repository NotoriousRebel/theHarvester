import asyncio
from typing import Any
from urllib.parse import quote

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.configuration import CredentialAdapter, FileSystemCredentialAdapter
from theHarvester.lib.core import AsyncFetcher
from theHarvester.parsers import myparser


class SearchBrave:
    """Search Brave while allowing credentials to be supplied without file access.

    Provider API:
    https://api-dashboard.search.brave.com/app/documentation/web-search/query

    Filesystem credentials remain the production default; injection keeps tests and
    embedded use independent of operator configuration files.
    """

    def __init__(self, word: str, limit: int, credential_adapter: CredentialAdapter | None = None) -> None:
        self.word = word
        self.results: list[dict[str, Any]] = []
        self.totalresults = ''
        credentials = credential_adapter if credential_adapter is not None else FileSystemCredentialAdapter()
        self.api_key = credentials.get('brave')
        if self.api_key is None or self.api_key == '':
            raise MissingKey('Brave Search')
        self.server = 'https://api.search.brave.com/res/v1/web/search'
        self.limit = limit
        self.proxy = False

    async def do_search(self) -> None:
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'gzip', 'X-Subscription-Token': self.api_key}

        # Search queries: exact match and site-specific
        queries = [f'"{self.word}"', f'site:{self.word}']

        for query in queries:
            if len(self.results) >= self.limit:
                break
            for offset in range(10):
                remaining = self.limit - len(self.results)
                if remaining <= 0:
                    break
                params = {
                    'q': query,
                    'count': min(20, remaining),
                    'offset': offset,
                    'safesearch': 'off',
                    'freshness': 'all',
                    'extra_snippets': 'true',
                    'text_decorations': 'true',
                    'spellcheck': 'true',
                }
                param_string = '&'.join([f'{key}={quote(str(value))}' for key, value in params.items()])
                url = f'{self.server}?{param_string}'
                resp = await AsyncFetcher.fetch(
                    url=url,
                    headers=headers,
                    proxy=self.proxy,
                    json=True,
                    fail_on_http_error=True,
                    follow_redirects=False,
                    raise_on_error=True,
                )
                if not isinstance(resp, dict):
                    raise ValueError('Brave Search returned an invalid payload')
                if 'error' in resp:
                    error = resp['error']
                    if not isinstance(error, dict):
                        raise ValueError('Brave Search returned an invalid error payload')
                    message = error.get('message', 'Unknown API error')
                    code = error.get('code', 'unknown')
                    raise RuntimeError(f'Brave Search returned {code}: {message}')

                web = resp.get('web')
                if not isinstance(web, dict) or not isinstance(web.get('results'), list):
                    raise ValueError('Brave Search returned an invalid results payload')
                results = web['results'][:remaining]
                query_data = resp.get('query')
                more_results_available = query_data.get('more_results_available') if isinstance(query_data, dict) else None
                if not results:
                    if not isinstance(more_results_available, bool):
                        raise ValueError('Brave Search returned an invalid pagination payload')
                    break

                for result in results:
                    if not isinstance(result, dict):
                        raise ValueError('Brave Search returned an invalid result')
                    result_text = f'{result.get("title", "")} {result.get("description", "")}'
                    for snippet in result.get('extra_snippets', []):
                        result_text += f' {snippet}'
                    result_text += f' {result.get("url", "")}'
                    self.totalresults += result_text + '\n'

                self.results.extend(results)
                if len(self.results) >= self.limit:
                    break
                if not isinstance(more_results_available, bool):
                    raise ValueError('Brave Search returned an invalid pagination payload')
                if not more_results_available:
                    break
                await asyncio.sleep(get_delay())

    async def get_emails(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.totalresults, self.word)
        return await rawres.hostnames()

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()

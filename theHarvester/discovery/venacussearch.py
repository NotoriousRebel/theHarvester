from typing import Any

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import Core
from theHarvester.parsers import venacusparser


class SearchVenacus:
    def __init__(self, word: str, limit=1000, offset_doc=0) -> None:
        self.word = word
        self.key = Core.venacus_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('Venacus')
        self.base_url = 'https://api.venacus.com'
        self.results: list[dict[str, Any]] = []
        self.parsed: dict[str, Any] = {}
        self.proxy = False
        self.offset_doc = offset_doc
        self.offset_in_doc = 0
        self.ai = False
        self.more = True
        self.limit = limit

    async def do_search(self) -> None:
        result_count = 0
        headers = {
            'Authorization': f'Bearer {self.key}',
            'User-Agent': f'{Core.get_user_agent()}-theHarvester',
        }

        async with aiohttp.ClientSession() as session:
            while self.more and result_count < self.limit:
                query = {
                    'q': self.word,
                    'offset_doc': self.offset_doc,
                    'offset_in_doc': self.offset_in_doc,
                    'limit': 100,
                    'ai': 'true' if self.ai else 'false',
                }

                async with session.get(f'{self.base_url}/v1/search/', headers=headers, params=query) as total_resp:
                    if total_resp.status != 200:
                        raise RuntimeError(f'Venacus returned HTTP {total_resp.status}')
                    search_data = await total_resp.json()
                    if not isinstance(search_data, dict):
                        raise ValueError('Venacus returned an invalid response')
                    if search_data.get('error'):
                        raise RuntimeError('Venacus returned a provider error')
                    current_results = search_data.get('data')
                    if not isinstance(current_results, list):
                        raise ValueError('Venacus returned invalid data')
                    more = search_data.get('more')
                    if not isinstance(more, bool):
                        raise ValueError('Venacus returned invalid pagination')

                    if not current_results:
                        if more:
                            raise ValueError('Venacus returned invalid pagination')
                        break

                    malformed = False
                    for record in current_results:
                        parser = venacusparser.Parser()
                        try:
                            record_values = await parser.parse_text_tokens([record])
                        except (KeyError, TypeError):
                            malformed = True
                            continue
                        if not any(record_values.values()):
                            malformed = True
                            continue
                        invalid_values = False
                        for route, values in record_values.items():
                            if route == 'people':
                                invalid_values = any(
                                    not isinstance(person, dict)
                                    or any(not isinstance(value, str) or not value.strip() for value in person.values())
                                    for person in values
                                )
                            else:
                                invalid_values = any(not isinstance(value, str) or not value.strip() for value in values)
                            if invalid_values:
                                break
                        if invalid_values:
                            malformed = True
                            continue
                        for route, values in record_values.items():
                            if route == 'people':
                                self.parsed.setdefault(route, []).extend(values)
                            else:
                                self.parsed.setdefault(route, set()).update(values)
                        self.results.append(record)
                    if malformed:
                        raise ValueError('Venacus returned malformed data')
                    result_count += len(current_results)

                    if more:
                        next_offset_doc = search_data.get('offset_doc')
                        next_offset_in_doc = search_data.get('offset_in_doc')
                        if (
                            not isinstance(next_offset_doc, int)
                            or isinstance(next_offset_doc, bool)
                            or not isinstance(next_offset_in_doc, int)
                            or isinstance(next_offset_in_doc, bool)
                        ):
                            raise ValueError('Venacus returned invalid pagination')
                        if (next_offset_doc, next_offset_in_doc) == (self.offset_doc, self.offset_in_doc):
                            raise ValueError('Venacus pagination did not advance')
                        self.offset_doc = next_offset_doc
                        self.offset_in_doc = next_offset_in_doc
                    self.more = more

    async def process(self, proxy: bool = False):
        self.proxy = proxy
        await self.do_search()

    async def get_people(self) -> list[dict[str, str]]:
        if 'people' not in self.parsed:
            return []
        return self.parsed['people']

    async def get_emails(self) -> set[str]:
        if 'emails' not in self.parsed:
            return set()
        return self.parsed['emails']

    async def get_ips(self) -> set[str]:
        if 'ips' not in self.parsed:
            return set()
        return self.parsed['ips']

    async def get_interestingurls(self) -> set[str]:
        if 'urls' not in self.parsed:
            return set()
        return self.parsed['urls']

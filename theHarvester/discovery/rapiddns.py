from bs4 import BeautifulSoup
from bs4.element import Tag

from theHarvester.lib.core import AsyncFetcher, Core


class SearchRapidDns:
    def __init__(self, word) -> None:
        self.word = word
        self.total_results: list = []
        self.proxy = False

    async def do_search(self):
        headers = {'User-agent': Core.get_user_agent()}
        url = f'https://rapiddns.io/subdomain/{self.word}?full=1#result'
        response = await AsyncFetcher.fetch(
            url=url,
            headers=headers,
            proxy=self.proxy,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if not isinstance(response, str) or not response.strip():
            raise ValueError('RapidDNS returned an invalid response')
        soup = BeautifulSoup(response, 'html.parser')
        table_el = soup.find('table')
        if not isinstance(table_el, Tag):
            raise ValueError('RapidDNS returned an invalid result table')
        tbody_el = table_el.find('tbody')
        if not isinstance(tbody_el, Tag):
            raise ValueError('RapidDNS returned an invalid result table')
        results: list[str] = []
        for row in tbody_el.find_all('tr'):
            if not isinstance(row, Tag):
                continue
            cells = row.find_all('td')
            if len(cells) < 3:
                raise ValueError('RapidDNS returned an invalid result row')
            subdomain = str(cells[0].get_text())
            if cells[-1].get_text() == 'CNAME':
                results.append(subdomain)
            else:
                results.append(f'{subdomain}:{str(cells[1].get_text()).strip()}')
        self.total_results.extend(results)
        self.total_results = list(set(self.total_results))

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_hostnames(self):
        return self.total_results

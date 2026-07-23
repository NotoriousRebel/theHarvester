from theHarvester.lib.core import AsyncFetcher
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchCrtsh:
    def __init__(self, word) -> None:
        self.word = word
        self.data: list = []
        self.proxy = False

    async def do_search(self) -> list:
        data: set[str] = set()
        try:
            url = f'https://crt.sh/?q=%25.{self.word}&exclude=expired&deduplicate=Y&output=json'
            response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
            response = response[0]
            if isinstance(response, list):
                for record in response:
                    if not isinstance(record, dict) or not isinstance(record.get('name_value'), str):
                        continue
                    for value in record['name_value'].split():
                        hostname = normalize_scoped_hostname(value.removeprefix('*.'), self.word)
                        if hostname and not hostname.startswith('*'):
                            data.add(hostname)
        except IndexError:
            print('No response from crt.sh or malformed list.')
        except KeyError as ke:
            print(f'Missing expected key in response: {ke}')
        except Exception as e:
            print(f'Unexpected error: {e}')
        return sorted(data)

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        data = await self.do_search()
        self.data = data

    async def get_hostnames(self) -> list:
        return self.data

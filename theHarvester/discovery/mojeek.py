from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser


class SearchMojeek:
    def __init__(self, word, limit) -> None:
        self.word = word
        self.limit = limit
        self.total_results = ''
        self.proxy = False
        self.server = 'www.mojeek.com'
        self.api_server = 'api.mojeek.com'

        try:
            self.api_key = Core.mojeek_key()
        except Exception:
            self.api_key = ''

        if self.api_key:
            print('[*] Mojeek: API key detected.')
        else:
            print('[*] Mojeek: No API key found, using default scraping mode.')

    async def do_search(self) -> None:
        headers = {'User-Agent': Core.get_user_agent()}

        if self.api_key:
            urls = [
                f'https://{self.api_server}/search?api_key={self.api_key}&q={self.word}&fmt=json&s={num}'
                for num in range(1, self.limit, 10)
            ]

            responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy, json=True)

            api_success = False
            api_unusable = False
            for response in responses:
                if not isinstance(response, dict):
                    api_unusable = True
                    continue

                data = response.get('response', response)
                if not isinstance(data, dict):
                    api_unusable = True
                    continue

                results = data.get('results')
                if isinstance(results, list):
                    for result in results:
                        if not isinstance(result, dict):
                            api_unusable = True
                            continue
                        url_value = result.get('url')
                        title_value = result.get('title')
                        description_value = result.get('desc')
                        url = url_value.replace('\\/', '/') if isinstance(url_value, str) else ''
                        title = title_value if isinstance(title_value, str) else ''
                        description = description_value if isinstance(description_value, str) else ''
                        if not any((url, title, description)):
                            api_unusable = True
                            continue
                        api_success = True
                        self.total_results += f' {url} {title} {description} '
                elif 'results' in data:
                    api_unusable = True

                status = data.get('status')
                if isinstance(status, str) and 'denied' in status.lower():
                    api_unusable = True
                    print(f'[!] Mojeek API: Access denied ({status}).')
                    break
                if 'status' in data and not isinstance(status, str):
                    api_unusable = True
                if 'results' not in data and 'status' not in data:
                    api_unusable = True

            if api_success and not api_unusable:
                print('[*] Mojeek: API search completed successfully.')
                return
            else:
                print('[*] Mojeek: API returned no results, falling back to scraping...')

        urls = [f'https://{self.server}/search?q={self.word}&s={num}' for num in range(0, self.limit, 10)]

        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
        for response in responses:
            self.total_results += str(response)

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()

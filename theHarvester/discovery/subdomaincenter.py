from theHarvester.lib.core import AsyncFetcher, Core


class SubdomainCenter:
    def __init__(self, word):
        self.word = word
        self.results = set()
        self.server = 'https://api.subdomain.center/?domain='
        self.proxy = False

    async def do_search(self):
        headers = {'User-Agent': Core.get_user_agent()}
        current_url = f'{self.server}{self.word}'
        response = await AsyncFetcher.fetch(
            url=current_url,
            headers=headers,
            proxy=self.proxy,
            json=True,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if not isinstance(response, list):
            raise ValueError('Subdomain Center returned an invalid payload')
        self.results = {sub[4:] if sub[:4] == 'www.' and sub[4:] else sub for sub in response}

    async def get_hostnames(self):
        return self.results

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()

import base64

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchFofa:
    """Class uses Fofa API to search for domain and host intelligence
    Fofa is a Chinese search engine for network-connected devices
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.totalips: set[str] = set()
        self.proxy = False
        self.hostname = 'https://fofa.info'
        self.api_key, self.email = self._get_api_credentials()

    def _get_api_credentials(self) -> tuple[str, str]:
        """Get Fofa API credentials"""
        try:
            credentials = Core.fofa_key()
        except KeyError as error:
            raise MissingKey('Fofa API (key and email required)') from error
        if (
            not isinstance(credentials, tuple)
            or len(credentials) != 2
            or not all(isinstance(value, str) and value for value in credentials)
        ):
            raise MissingKey('Fofa API (key and email required)')
        return credentials

    async def do_search(self) -> None:
        headers = {'User-agent': Core.get_user_agent()}
        query = f'domain="{self.word}"'
        query_encoded = base64.b64encode(query.encode()).decode()
        url = f'{self.hostname}/api/v1/search/all'
        params = {
            'email': self.email,
            'key': self.api_key,
            'qbase64': query_encoded,
            'fields': 'host,ip,port,protocol,title',
            'size': 100,
        }
        param_string = '&'.join([f'{key}={value}' for key, value in params.items()])
        data = await AsyncFetcher.fetch(
            url=f'{url}?{param_string}',
            headers=headers,
            proxy=self.proxy,
            json=True,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if not isinstance(data, dict):
            raise ValueError('Fofa returned an invalid payload')
        if data.get('error', False):
            message = data.get('errmsg', 'Unknown error')
            if '账号无效' in str(message) or 'invalid' in str(message).lower():
                raise PermissionError('Fofa rejected the configured credentials')
            raise RuntimeError(f'Fofa returned an error: {message}')

        results = data.get('results')
        if not isinstance(results, list):
            raise ValueError('Fofa returned invalid results')
        for result in results:
            if not isinstance(result, list) or len(result) < 2:
                raise ValueError('Fofa returned an invalid result')
            host, ip = result[:2]
            if not isinstance(host, str) or not isinstance(ip, str):
                raise ValueError('Fofa returned an invalid result')
            clean_host = host.lower().replace('http://', '').replace('https://', '').split(':')[0]
            if clean_host.endswith(f'.{self.word}') or clean_host == self.word:
                self.totalhosts.add(clean_host)
            if ip:
                self.totalips.add(ip)

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

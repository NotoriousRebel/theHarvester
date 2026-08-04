import asyncio
from urllib.parse import urlencode

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core


class SearchVirustotal:
    def __init__(self, word) -> None:
        self.key = Core.virustotal_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('virustotal')
        self.word = word
        self.proxy = False
        self.hostnames: list = []

    async def do_search(self) -> None:
        # TODO determine if more endpoints can yield useful info given a domain
        # based on: https://developers.virustotal.com/reference/domains-relationships
        # base_url = "https://www.virustotal.com/api/v3/domains/domain/subdomains?limit=40"
        headers = {
            'User-Agent': Core.get_user_agent(),
            'Accept': 'application/json',
            'x-apikey': self.key,
        }
        base_url = f'https://www.virustotal.com/api/v3/domains/{self.word}/subdomains?limit=40'
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            # rate limit is 4 per minute
            # TODO add timer logic if proven to be needed
            # in the meantime sleeping 16 seconds should eliminate hitting the rate limit
            send_url = f'{base_url}&{urlencode({"cursor": cursor})}' if cursor is not None else base_url
            jdata = await AsyncFetcher.fetch(
                url=send_url,
                headers=headers,
                proxy=self.proxy,
                json=True,
                request_timeout=60,
                fail_on_http_error=True,
                follow_redirects=False,
                raise_on_error=True,
            )
            if not isinstance(jdata, dict):
                raise ValueError('VirusTotal returned an invalid response')
            if jdata.get('error'):
                raise RuntimeError('VirusTotal returned a provider error')
            data = jdata.get('data')
            meta = jdata.get('meta')
            links = jdata.get('links')
            if not isinstance(data, list):
                raise ValueError('VirusTotal returned invalid data')
            if not isinstance(meta, dict) or not isinstance(links, dict):
                raise ValueError('VirusTotal returned invalid pagination')
            page_count = meta.get('count')
            if not isinstance(page_count, int) or isinstance(page_count, bool) or page_count < 0:
                raise ValueError('VirusTotal returned an invalid count')
            malformed = False
            for record in data:
                try:
                    self.hostnames.extend(await self.parse_hostnames([record], self.word))
                except (AttributeError, KeyError, TypeError, ValueError):
                    malformed = True
            self.hostnames = list(sorted(set(self.hostnames)))
            # verify domains such as x.x.com.multicdn.x.com are parsed properly
            self.hostnames = [
                host
                for host in self.hostnames
                if ((len(host.split('.')) >= 3) and host.split('.')[-2] == self.word.split('.')[-2])
            ]
            if malformed:
                raise ValueError('VirusTotal returned malformed data')

            next_link = links.get('next')
            if next_link is None:
                break
            if not isinstance(next_link, str) or not next_link.strip():
                raise ValueError('VirusTotal returned invalid pagination')
            if not data:
                raise ValueError('VirusTotal returned invalid pagination')
            next_cursor = meta.get('cursor')
            if not isinstance(next_cursor, str) or not next_cursor.strip():
                raise ValueError('VirusTotal returned invalid pagination')
            if next_cursor in seen_cursors:
                raise ValueError('VirusTotal pagination did not advance')
            seen_cursors.add(next_cursor)
            cursor = next_cursor
            await asyncio.sleep(16)

    async def get_hostnames(self) -> list:
        return self.hostnames

    @staticmethod
    async def parse_hostnames(data, word):
        total_subdomains: set[str] = set()
        for attribute in data:
            identifier = attribute.get('id') if isinstance(attribute, dict) else None
            if not isinstance(identifier, str) or not identifier.strip():
                raise ValueError('VirusTotal returned malformed data')
            total_subdomains.add(identifier.replace('"', '').replace('www.', ''))
            attributes = attribute['attributes']
            total_subdomains.update(
                {
                    value['value'].replace('"', '').replace('www.', '')
                    for value in attributes['last_dns_records']
                    if word in value['value']
                }
            )
            if 'last_https_certificate' in attributes:
                total_subdomains.update(
                    {
                        value.replace('"', '').replace('www.', '')
                        for value in attributes['last_https_certificate']['extensions']['subject_alternative_name']
                        if word in value
                    }
                )
        # Convert to list for further processing without changing variable type mid-function
        subdomains_list: list[str] = list(sorted(total_subdomains))
        # Other false positives may occur over time and yes there are other ways to parse this, feel free to implement
        # them and submit a PR or raise an issue if you run into this filtering not being enough
        # TODO determine if parsing 'v=spf1 include:_spf-x.acme.com include:_spf-x.acme.com' is worth parsing
        subdomains_list = [
            x
            for x in subdomains_list
            if 'edgekey.net' not in str(x) and 'akadns.net' not in str(x) and 'include:_spf' not in str(x)
        ]
        subdomains_list.sort()
        return subdomains_list

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

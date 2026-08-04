import asyncio

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.core import AsyncFetcher, Core


class SearchRocketReach:
    def __init__(self, word, limit) -> None:
        self.ips: set = set()
        self.word = word
        self.key = Core.rocketreach_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('RocketReach')
        self.hosts: set = set()
        self.proxy = False
        self.baseurl = 'https://api.rocketreach.co/api/v2/person/search'
        self.links: set = set()
        self.emails: set = set()
        self.limit = limit

    async def do_search(self) -> None:
        if self.limit <= 0:
            return

        headers = {
            'Api-Key': self.key,
            'Content-Type': 'application/json',
            'User-Agent': Core.get_user_agent(),
        }

        start = 0
        remaining = self.limit
        while remaining > 0:
            page_size = min(100, remaining)
            data = {
                'query': {'current_employer_domain': [self.word]},
                'start': start,
                'page_size': page_size,
            }
            result = await AsyncFetcher.post_fetch(
                self.baseurl,
                headers=headers,
                data=data,
                json=True,
                fail_on_http_error=True,
                raise_on_error=True,
            )
            if not isinstance(result, dict):
                raise ValueError('RocketReach returned an invalid response')

            detail = result.get('detail', '')
            if detail and 'Subscribe to a plan to access' in str(detail):
                raise RuntimeError('RocketReach subscription required')
            if detail and 'Request was throttled.' in str(detail):
                raise RuntimeError('RocketReach request throttled')
            if detail:
                raise RuntimeError('RocketReach returned a provider error')

            profiles = result.get('profiles')
            if not isinstance(profiles, list):
                raise ValueError('RocketReach returned invalid profiles')
            pagination = result.get('pagination', {})
            if not isinstance(pagination, dict):
                raise ValueError('RocketReach returned invalid pagination')
            if not profiles:
                break

            page_links: set[str] = set()
            page_emails: set[str] = set()
            for profile in profiles:
                if not isinstance(profile, dict):
                    raise ValueError('RocketReach returned an invalid profile')
                if 'linkedin_url' in profile:
                    link = profile['linkedin_url']
                    if not isinstance(link, str):
                        raise ValueError('RocketReach returned an invalid profile')
                    if link:
                        page_links.add(link)
                profile_emails = profile.get('emails')
                if profile_emails:
                    if not isinstance(profile_emails, list):
                        raise ValueError('RocketReach returned invalid profile emails')
                    for email in profile_emails:
                        if not isinstance(email, dict):
                            raise ValueError('RocketReach returned invalid profile emails')
                        address = email.get('email')
                        if address:
                            if not isinstance(address, str):
                                raise ValueError('RocketReach returned invalid profile emails')
                            page_emails.add(address)
            self.links.update(page_links)
            self.emails.update(page_emails)

            found = len(profiles)
            remaining -= found
            start += found

            total = pagination.get('total')
            if isinstance(total, int) and start >= total:
                break
            if found < page_size:
                break

        await asyncio.sleep(get_delay() + 5)

    async def get_links(self):
        return self.links

    async def get_emails(self):
        return self.emails

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

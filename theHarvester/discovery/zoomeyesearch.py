import asyncio
import math
import re
from collections.abc import Iterable
from typing import Any

from theHarvester.discovery.constants import MissingKey, get_delay
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser


class SearchZoomEye:
    def __init__(self, word, limit) -> None:
        self.word = word
        self.limit = limit
        self.key = Core.zoomeye_key()
        # NOTE for ZoomEye you get a system recharge on the 1st of every month
        # Which resets your balance to 10000 requests
        # If you wish to extract as many subdomains as possible visit the fetch_subdomains
        # To see how
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('zoomeye')
        self.key = self.key.strip()
        # API v2 base
        self.baseurl = 'https://api.zoomeye.ai/host/search'
        self.domain_url = 'https://api.zoomeye.ai/domain/search'
        self.proxy = False
        self.totalasns: list = list()
        self.totalhosts: list = list()
        self.interestingurls: list = list()
        self.totalips: list = list()
        self.totalemails: list = list()
        # Regex used is directly from: https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py#L29
        # Maybe one day it will be a pip package
        # Regardless LinkFinder is an amazing tool!
        regex_str = r"""
          (?:"|')                               # Start newline delimiter
          (
            ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
            [^"'/]{1,}\.                        # Match a domainname (any character + dot)
            [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
            |
            ((?:/|\.\./|\./)                    # Start with /,../,./
            [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
            [^"'><,;|()]{1,})                   # Rest of the characters can't be
            |
            ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
            [a-zA-Z0-9_\-/]{1,}                 # Resource name
            \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
            [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-]{1,}                 # filename
            \.(?:php|asp|aspx|jsp|json|
                 action|html|js|txt|xml)        # . + extension
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
          )
          (?:"|')                               # End newline delimiter
        """
        self.iurl_regex = re.compile(regex_str, re.VERBOSE)

    def _build_headers(self) -> dict[str, str]:
        # API v2 uses API-KEY header
        return {'API-KEY': self.key, 'User-Agent': Core.get_user_agent()}

    async def _fetch_page(self, url: str, params: tuple[tuple[str, str], ...]) -> dict[str, Any]:
        response = await AsyncFetcher.fetch(
            url=url,
            json=True,
            proxy=self.proxy,
            headers=self._build_headers(),
            params=params,
            request_timeout=60,
            fail_on_http_error=True,
            follow_redirects=False,
            raise_on_error=True,
        )
        if not isinstance(response, dict):
            raise ValueError('ZoomEye returned an invalid response')
        if not self._is_success(response):
            raise RuntimeError('ZoomEye returned a provider error')
        payload = self._unwrap_data(response)
        if not isinstance(payload, dict):
            raise ValueError('ZoomEye returned invalid data')
        return payload

    @staticmethod
    def _page_items(payload: dict[str, Any], *keys: str) -> list[Any]:
        for key in keys:
            if key in payload:
                items = payload[key]
                if not isinstance(items, list):
                    raise ValueError('ZoomEye returned an invalid page container')
                return items
        raise ValueError('ZoomEye returned a missing page container')

    @staticmethod
    def _domain_names(items: list[Any]) -> tuple[list[str], bool]:
        names = []
        malformed = False
        for item in items:
            value = item.get('name') or item.get('domain') or item.get('host') if isinstance(item, dict) else None
            if not isinstance(value, str) or not value.strip():
                malformed = True
                continue
            names.append(value)
        return names, malformed

    @staticmethod
    def _is_success(resp: dict[str, Any]) -> bool:
        if 'code' in resp:
            code = resp['code']
            if type(code) is not int:
                raise ValueError('ZoomEye returned an invalid success code')
            return code in (0, 200, 60000)
        if 'status' in resp:
            status = resp['status']
            if type(status) is not int:
                raise ValueError('ZoomEye returned an invalid success status')
            return status in (0, 200)
        return True

    @staticmethod
    def _unwrap_data(resp: dict[str, Any]) -> dict[str, Any]:
        # Many v2 endpoints return {'code':0,'data':{...}}
        data = resp.get('data')
        return data if isinstance(data, dict) else resp

    @staticmethod
    def _page_total_from_payload(payload: dict[str, Any], page_size: int) -> int:
        if 'available' in payload:
            try:
                available = int(payload['available'])
            except (TypeError, ValueError) as error:
                raise ValueError('ZoomEye returned invalid pagination') from error
            if isinstance(payload['available'], bool) or available < 0:
                raise ValueError('ZoomEye returned invalid pagination')
            return max(1, available)

        total_key = next((key for key in ('total', 'count', 'total_count') if key in payload), None)
        if total_key is not None:
            total_results = payload[total_key]
            if not isinstance(total_results, int) or isinstance(total_results, bool) or total_results < 0:
                raise ValueError('ZoomEye returned invalid pagination')
            size = payload.get('size', page_size)
            try:
                size_int = int(size)
            except (TypeError, ValueError) as error:
                raise ValueError('ZoomEye returned invalid pagination') from error
            if isinstance(size, bool) or size_int <= 0:
                raise ValueError('ZoomEye returned invalid pagination')
            return max(1, math.ceil(total_results / size_int))
        return 1

    @staticmethod
    def _safe_add_hostname(container: set, value: str | None) -> bool:
        if not value or not isinstance(value, str):
            return False
        v = value.strip()
        if not v:
            return False
        v = v.removesuffix('.')
        container.add(v)
        return True

    async def fetch_subdomains(self) -> None:
        # type=0 for subdomain search per docs
        size = 30
        params = (('q', self.word), ('type', '0'), ('page', '1'), ('size', str(size)))
        payload = await self._fetch_page(self.domain_url, params)
        total_pages = self._page_total_from_payload(payload, size)
        # If user requested more pages than available, clamp to available
        page_limit = min(self.limit, total_pages) if total_pages >= 1 else self.limit

        # Parse first page
        first_list = self._page_items(payload, 'list', 'results')
        found_subdomains, malformed = self._domain_names(first_list)
        self.totalhosts.extend(found_subdomains)
        if malformed:
            raise ValueError('ZoomEye returned malformed domain data')

        # Iterate remaining pages
        for i in range(2, page_limit + 1):
            params = (('q', self.word), ('type', '0'), ('page', str(i)), ('size', str(size)))
            payload = await self._fetch_page(self.domain_url, params)
            page_list = self._page_items(payload, 'list', 'results')
            found_subdomains, malformed = self._domain_names(page_list)
            if malformed:
                self.totalhosts.extend(found_subdomains)
                raise ValueError('ZoomEye returned malformed domain data')
            if not found_subdomains:
                break
            self.totalhosts.extend(found_subdomains)
            if i % 10 == 0:
                await asyncio.sleep(get_delay() + 1)

    async def do_search(self) -> None:
        # Fetch subdomains first
        await self.fetch_subdomains()

        size = 20
        params = (('query', f'site:{self.word}'), ('page', '1'), ('size', str(size)))
        payload = await self._fetch_page(self.baseurl, params)
        total_pages = self._page_total_from_payload(payload, size)
        page_limit = min(self.limit, total_pages) if total_pages >= 1 else self.limit

        nomatches_counter = 0

        def extract_matches(p: dict[str, Any]) -> Iterable[dict]:
            return self._page_items(p, 'matches', 'list', 'results')

        matches = extract_matches(payload)
        if matches:
            await self._retain_matches(matches)
        if page_limit < 2:
            return

        for num in range(2, page_limit + 1):
            params = (('query', f'site:{self.word}'), ('page', str(num)), ('size', str(size)))
            payload = await self._fetch_page(self.baseurl, params)
            matches = extract_matches(payload)
            if not matches:
                nomatches_counter += 1
                if nomatches_counter >= 5:
                    break
                continue

            await self._retain_matches(matches)

            if num % 10 == 0:
                await asyncio.sleep(get_delay() + 1)

    async def _retain_matches(self, matches: Iterable[dict]) -> None:
        hostnames, emails, ips, asns, iurls, malformed = await self.parse_matches(matches)
        self.totalhosts.extend(hostnames)
        self.totalemails.extend(emails)
        self.totalips.extend(ips)
        self.totalasns.extend(asns)
        self.interestingurls.extend(iurls)
        if malformed:
            raise ValueError('ZoomEye returned malformed host data')

    async def parse_matches(self, matches):
        # Helper function to parse items from match json
        ips: set[str] = set()
        iurls: set[str] = set()
        hostnames: set[str] = set()
        asns: set[str] = set()
        emails: set[str] = set()
        malformed = False

        for match in matches:
            if not isinstance(match, dict):
                malformed = True
                continue
            record_usable = False
            try:
                # IPs
                for field in ('ip', 'ip_str', 'ip_str_v4', 'address'):
                    ip = match.get(field)
                    if ip is None:
                        continue
                    if not isinstance(ip, str) or not ip.strip():
                        malformed = True
                        continue
                    ips.add(ip)
                    record_usable = True
                    break

                # ASNs
                asn_val = None
                geoinfo = match.get('geoinfo')
                if isinstance(geoinfo, dict):
                    asn_val = geoinfo.get('asn')
                elif geoinfo is not None:
                    malformed = True
                asn_val = asn_val if asn_val is not None else match.get('asn')
                if asn_val is not None:
                    try:
                        if isinstance(asn_val, bool) or not isinstance(asn_val, int | str) or not str(asn_val).strip():
                            raise ValueError
                        asns.add(str(asn_val) if str(asn_val).startswith('AS') else f'AS{int(asn_val)}')
                        record_usable = True
                    except (TypeError, ValueError):
                        malformed = True

                # Reverse DNS and hostnames
                rdns_new = match.get('rdns_new')
                if rdns_new is not None:
                    if not isinstance(rdns_new, str) or not rdns_new.strip():
                        malformed = True
                    elif ',' in rdns_new:
                        parts = str(rdns_new).split(',')
                        primary = parts[0]
                        secondary = parts[1] if len(parts) == 2 else None
                        if primary:
                            record_usable = self._safe_add_hostname(hostnames, primary) or record_usable
                        if secondary:
                            record_usable = self._safe_add_hostname(hostnames, secondary) or record_usable
                    else:
                        record_usable = self._safe_add_hostname(hostnames, rdns_new) or record_usable

                rdns = match.get('rdns')
                if rdns is not None:
                    if not isinstance(rdns, str) or not rdns.strip():
                        malformed = True
                    else:
                        record_usable = self._safe_add_hostname(hostnames, rdns) or record_usable

                # Additional hostname-like fields
                for f in ('hostname', 'host', 'domain', 'site', 'fqdn'):
                    if f not in match or match[f] is None:
                        continue
                    if self._safe_add_hostname(hostnames, match[f]):
                        record_usable = True
                    else:
                        malformed = True
                for f in ('hostnames', 'domains', 'names'):
                    vals = match.get(f)
                    if vals is None:
                        continue
                    if not isinstance(vals, list):
                        malformed = True
                        continue
                    for value in vals:
                        if self._safe_add_hostname(hostnames, value):
                            record_usable = True
                        else:
                            malformed = True

                # Banner/content extraction for emails, hostnames, iurls
                banners = []

                portinfo = match.get('portinfo')
                if isinstance(portinfo, dict):
                    banner = portinfo.get('banner')
                    if isinstance(banner, str) and banner:
                        banners.append(banner)
                    elif banner is not None:
                        malformed = True
                elif portinfo is not None:
                    malformed = True

                service = match.get('service')
                if isinstance(service, dict):
                    for key in ('banner', 'data', 'raw'):
                        value = service.get(key)
                        if isinstance(value, str) and value:
                            banners.append(value)
                        elif value is not None:
                            malformed = True
                    http = service.get('http')
                    if isinstance(http, dict):
                        for key in ('title', 'html', 'body', 'server', 'raw'):
                            value = http.get(key)
                            if isinstance(value, str) and value:
                                banners.append(value)
                            elif value is not None:
                                malformed = True
                    elif http is not None:
                        malformed = True
                elif service is not None:
                    malformed = True

                content_blob = '\n'.join(banners)
                if content_blob:
                    temp_emails = set(await self.parse_emails(content_blob))
                    emails.update(temp_emails)
                    parsed_hostnames = set(await self.parse_hostnames(content_blob))
                    hostnames.update(parsed_hostnames)
                    found_urls = {
                        str(iurl.group(1)).replace('"', '')
                        for iurl in re.finditer(self.iurl_regex, content_blob)
                        if self.word in str(iurl.group(1))
                    }
                    iurls.update(found_urls)
                    record_usable = bool(temp_emails or parsed_hostnames or found_urls) or record_usable

            except Exception:
                malformed = True
            if not record_usable:
                malformed = True

        return hostnames, emails, ips, asns, iurls, malformed

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()  # Only need to do it once.

    async def parse_emails(self, content):
        rawres = myparser.Parser(content, self.word)
        return await rawres.emails()

    async def parse_hostnames(self, content):
        rawres = myparser.Parser(content, self.word)
        return await rawres.hostnames()

    async def get_hostnames(self):
        return set(self.totalhosts)

    async def get_emails(self):
        return set(self.totalemails)

    async def get_ips(self):
        return set(self.totalips)

    async def get_asns(self):
        return set(self.totalasns)

    async def get_interestingurls(self):
        return set(self.interestingurls)

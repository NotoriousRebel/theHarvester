import logging
from urllib.parse import urlencode

from theHarvester.lib.core import AsyncFetcher

logger = logging.getLogger(__name__)


class SearchCertspoter:
    # Bound one-shot enumeration if a provider keeps returning novel cursors forever;
    # exhausting the bound is reported as incomplete rather than silent success.
    MAX_PAGES = 1_000

    def __init__(self, target_domain: str) -> None:
        self.target_domain = target_domain.strip().lower().rstrip('.')
        self.totalhosts: set[str] = set()
        self.proxy = False

    def _normalize_hostname(self, hostname: object) -> str | None:
        if not isinstance(hostname, str):
            return None

        hostname = hostname.strip().lower().rstrip('.').removeprefix('*.')
        if not hostname or '*' in hostname or any(character.isspace() for character in hostname):
            return None
        if hostname == self.target_domain or hostname.endswith(f'.{self.target_domain}'):
            return hostname
        return None

    async def do_search(self) -> None:
        base_url = 'https://api.certspotter.com/v1/issuances'
        cursor = None
        seen_cursors: set[str] = set()
        try:
            for _ in range(self.MAX_PAGES):
                params = {
                    'domain': self.target_domain,
                    'include_subdomains': 'true',
                    'expand': 'dns_names',
                }
                if cursor is not None:
                    params['after'] = cursor

                responses = await AsyncFetcher.fetch_all([f'{base_url}?{urlencode(params)}'], json=True, proxy=self.proxy)
                if not responses or not isinstance(responses[0], list):
                    break

                page = responses[0]
                if not page:
                    break

                for issuance in page:
                    if not isinstance(issuance, dict):
                        continue
                    dns_names = issuance.get('dns_names')
                    if not isinstance(dns_names, list):
                        continue
                    for dns_name in dns_names:
                        if hostname := self._normalize_hostname(dns_name):
                            self.totalhosts.add(hostname)

                last_issuance = page[-1]
                next_cursor = last_issuance.get('id') if isinstance(last_issuance, dict) else None
                if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                    break
                seen_cursors.add(next_cursor)
                cursor = next_cursor
            else:
                logger.info(f'Cert Spotter stopped after {self.MAX_PAGES} pages; results may be incomplete.')
        except IndexError:
            logger.info('No data returned from Cert Spotter.')
        except ConnectionError:
            logger.info('Network connection failed.')
        except Exception as e:
            logger.info(f'Unexpected error occurred: {e}')

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
        logger.info('\tSearching results.')

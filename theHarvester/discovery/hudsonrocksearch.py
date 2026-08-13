from __future__ import annotations

import asyncio
import json
import re
from email.errors import HeaderParseError
from email.headerregistry import Address
from ipaddress import ip_address
from math import ceil
from time import monotonic
from urllib.parse import urlsplit, urlunsplit

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchHudsonRock:
    """Collect bounded, sanitized credential-exposure evidence from Hudson Rock v3."""

    DISCOVERY_URL = 'https://api.hudsonrock.com/json/v3/search-by-domain/discovery'
    SEARCH_URL = 'https://api.hudsonrock.com/json/v3/search-by-domain'
    MAX_REQUESTS = 20
    MAX_RESULTS = 500
    MAX_RUNTIME_SECONDS = 120
    REQUEST_DELAY_SECONDS = 0.25
    MAX_RETRIES = 2

    def __init__(self, word: str) -> None:
        self.word = word.strip().lower().rstrip('.')
        self.target_domain = self.word.rsplit('@', 1)[-1]
        key = Core.hudsonrock_key()
        if not isinstance(key, str) or not key.strip():
            raise MissingKey('hudsonrock')
        self.key = key.strip()
        self.totalhosts: set[str] = set()
        self.emails: set[str] = set()
        self.urls: set[str] = set()
        self.exposures: set[str] = set()
        self.proxy = False
        self.execution_status: str = 'completed'
        self.stop_reason: str | None = None
        self._requests = 0
        self._started_at = 0.0

    @property
    def _headers(self) -> dict[str, str]:
        return {'Accept': 'application/json', 'Content-Type': 'application/json', 'api-key': self.key}

    def _has_results(self) -> bool:
        return bool(self.totalhosts or self.emails or self.urls or self.exposures)

    def _stop(self, empty_status: str, reason: str) -> None:
        self.execution_status = 'partial' if self._has_results() else empty_status
        self.stop_reason = reason

    def _remaining_runtime(self) -> float:
        return self.MAX_RUNTIME_SECONDS - (monotonic() - self._started_at)

    async def _sleep(self, delay: float) -> bool:
        remaining = self._remaining_runtime()
        if remaining <= 0:
            self._stop('failed', 'runtime-limit')
            return False
        try:
            async with asyncio.timeout(remaining):
                await asyncio.sleep(delay)
        except TimeoutError:
            self._stop('failed', 'runtime-limit')
            return False
        return True

    async def _post(self, url: str, payload: dict[str, object]) -> dict[str, object] | None:
        for attempt in range(self.MAX_RETRIES + 1):
            if self._requests >= self.MAX_REQUESTS:
                self._stop('failed', 'request-limit')
                return None
            remaining = self._remaining_runtime()
            if remaining <= 0:
                self._stop('failed', 'runtime-limit')
                return None
            self._requests += 1
            try:
                async with asyncio.timeout(remaining):
                    response = await AsyncFetcher.fetch_json(
                        url,
                        headers=self._headers,
                        method='POST',
                        json_body=payload,
                        proxy=self.proxy,
                        request_timeout=max(1, ceil(remaining)),
                    )
            except TimeoutError:
                self._stop('failed', 'runtime-limit')
                return None
            except ResponseStreamError as error:
                if error.reason == 'response-limit':
                    self._stop('failed', 'response-limit')
                    return None
                if error.reason == 'invalid-response':
                    self._stop('failed', 'invalid-response')
                    return None
                response = None
            except Exception:
                response = None

            if not isinstance(response, FetcherResponse):
                if attempt == self.MAX_RETRIES or not await self._sleep(self.REQUEST_DELAY_SECONDS * (attempt + 1)):
                    self._stop('failed', 'transport-error')
                    return None
                continue
            if response.status in {401, 403}:
                self.totalhosts.clear()
                self.emails.clear()
                self.urls.clear()
                self.exposures.clear()
                self.execution_status = 'failed'
                self.stop_reason = 'access-denied'
                return None
            if response.status in {408, 429} or response.status >= 500:
                if attempt == self.MAX_RETRIES:
                    self._stop(
                        'rate-limited' if response.status == 429 else 'failed',
                        'rate-limit' if response.status == 429 else 'timeout' if response.status == 408 else 'server-failure',
                    )
                    return None
                retry_after = response.headers.get('retry-after', '')
                delay = float(retry_after) if retry_after.isdigit() else self.REQUEST_DELAY_SECONDS * (attempt + 1)
                if not await self._sleep(min(delay, 30)):
                    return None
                continue
            if not 200 <= response.status < 300 or not isinstance(response.body, dict):
                self._stop('failed', 'invalid-response')
                return None
            return response.body
        return None

    @staticmethod
    def _safe_label(value: object, *, limit: int = 100) -> str | None:
        if not isinstance(value, str):
            return None
        label = value.strip()
        if not label or len(label) > limit or not re.fullmatch(r'[\w .()+/&,:-]+', label):
            return None
        return label

    @classmethod
    def _safe_labels(cls, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        labels: set[str] = set()
        for entry in value:
            candidate = entry
            if isinstance(entry, dict):
                candidate = next((entry[field] for field in ('name', 'product', 'display_name') if field in entry), None)
            label = cls._safe_label(candidate)
            if label:
                labels.add(label)
            if len(labels) >= 50:
                break
        return sorted(labels)

    def _safe_url(self, value: object) -> tuple[str, str] | None:
        if not isinstance(value, str) or not value.startswith(('http://', 'https://')):
            return None
        try:
            parsed = urlsplit(value)
            if parsed.username is not None or parsed.password is not None:
                return None
            hostname = normalize_scoped_hostname(parsed.hostname, self.target_domain)
            if hostname is None:
                return None
            port = f':{parsed.port}' if parsed.port is not None else ''
        except ValueError:
            return None
        return urlunsplit((parsed.scheme.lower(), f'{hostname}{port}', '', '', '')), hostname

    def _add_url(self, value: object) -> str | None:
        safe = self._safe_url(value)
        if safe is None:
            return None
        url, hostname = safe
        if url not in self.urls and len(self.urls) >= self.MAX_RESULTS:
            return None
        self.totalhosts.add(hostname)
        self.urls.add(url)
        return url

    def _safe_email(self, value: object) -> str | None:
        if not isinstance(value, str) or value.count('@') != 1:
            return None
        candidate = value.strip().lower()
        try:
            address = Address(addr_spec=candidate)
        except (HeaderParseError, ValueError):
            return None
        domain = normalize_scoped_hostname(address.domain, self.target_domain)
        if address.username and domain and len(address.username.encode()) <= 64 and len(candidate.encode()) <= 254:
            return Address(username=address.username, domain=domain).addr_spec
        return None

    def _add_email(self, value: object) -> str | None:
        email = self._safe_email(value)
        if email is None or (email not in self.emails and len(self.emails) >= self.MAX_RESULTS):
            return None
        self.emails.add(email)
        return email

    def _endpoint_context(self, item: dict[str, object]) -> dict[str, object]:
        endpoint: dict[str, object] = {}
        address = next((item[field] for field in ('ip', 'ip_address') if field in item), None)
        if isinstance(address, str):
            try:
                endpoint['ip'] = str(ip_address(address))
            except ValueError:
                pass
        for output, fields in {
            'computer_name': ('computer_name', 'computer'),
            'operating_system': ('operating_system', 'os'),
        }.items():
            label = self._safe_label(next((item[field] for field in fields if field in item), None), limit=128)
            if label:
                endpoint[output] = label
        products = self._safe_labels(
            next((item[field] for field in ('antiviruses', 'antivirus_products') if field in item), None)
        )
        if products:
            endpoint['antivirus_products'] = products
        return endpoint

    @staticmethod
    def _safe_date(value: object) -> str | None:
        if not isinstance(value, str) or len(value) > 40:
            return None
        return value if re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})', value) else None

    def _record_exposures(self, item: dict[str, object]) -> None:
        credentials = item.get('credentials')
        if not isinstance(credentials, list):
            return
        scoped: list[tuple[str | None, str | None, str | None, str]] = []
        seen: set[tuple[str | None, str | None, str | None, str]] = set()
        credential_count = 0
        for credential in credentials:
            if not isinstance(credential, dict):
                continue
            safe = self._safe_url(credential.get('url'))
            safe_url = safe[0] if safe else None
            domain = normalize_scoped_hostname(credential.get('domain'), self.target_domain)
            if safe_url is None and domain is None:
                continue
            credential_type = self._safe_label(credential.get('type'), limit=32) or 'unknown'
            employee_email = self._safe_email(credential.get('username')) if credential_type == 'employee' else None
            credential_count = min(credential_count + 1, self.MAX_RESULTS)
            candidate = (safe_url, domain, employee_email, credential_type)
            if candidate not in seen and len(scoped) < self.MAX_RESULTS:
                seen.add(candidate)
                scoped.append(candidate)
        if not scoped:
            return

        endpoint = self._endpoint_context(item)
        applications = self._safe_labels(item.get('sensitive_applications'))
        stealer_family = self._safe_label(item.get('stealer_family'))
        record_id = item.get('_id')
        provider_record_id = (
            record_id.lower() if isinstance(record_id, str) and re.fullmatch(r'[0-9a-fA-F]{24}', record_id) else None
        )
        dates = {
            output: date
            for output, field in (('date_compromised', 'date_compromised'), ('date_uploaded', 'date_uploaded'))
            if (date := self._safe_date(item.get(field)))
        }
        for safe_url, domain, employee_email, credential_type in scoped:
            exposure_category = self._safe_label(item.get('type') or item.get('exposure_category'), limit=32) or credential_type
            evidence: dict[str, object] = {
                'provider': 'hudsonrock-v3',
                'exposure_category': exposure_category,
                'credential_count': credential_count,
                'credential_type': credential_type,
                **dates,
            }
            if provider_record_id:
                evidence['provider_record_id'] = provider_record_id
            if safe_url:
                evidence['url'] = safe_url
            if domain:
                evidence['domain'] = domain
            if employee_email:
                evidence['employee_email'] = employee_email
            if stealer_family:
                evidence['stealer_family'] = stealer_family
            if applications:
                evidence['sensitive_applications'] = applications
            if endpoint:
                evidence['compromised_endpoint'] = endpoint
            serialized = json.dumps(evidence, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
            if serialized in self.exposures:
                continue
            self.exposures.add(serialized)
            if safe_url:
                self._add_url(safe_url)
            if employee_email:
                self._add_email(employee_email)
            if len(self.exposures) >= self.MAX_RESULTS:
                return

    def _process_discovery_page(self, body: dict[str, object]) -> bool:
        data = body.get('data')
        if not isinstance(data, list):
            self._stop('failed', 'malformed-data')
            return False
        malformed = False
        for item in data:
            if isinstance(item, dict):
                if not isinstance(item.get('url'), str):
                    malformed = True
                    continue
                self._add_url(item.get('url'))
                if len(self.urls) >= self.MAX_RESULTS:
                    self._stop('failed', 'result-limit')
                    return False
            else:
                malformed = True
        if malformed:
            self._stop('failed', 'malformed-data')
            return False
        return True

    def _process_search_page(self, body: dict[str, object]) -> bool:
        data = body.get('data')
        if not isinstance(data, list):
            self._stop('failed', 'malformed-data')
            return False
        malformed = False
        for item in data:
            if isinstance(item, dict):
                if not isinstance(item.get('credentials'), list):
                    malformed = True
                    continue
                self._record_exposures(item)
                if len(self.exposures) >= self.MAX_RESULTS:
                    self._stop('failed', 'result-limit')
                    return False
            else:
                malformed = True
        if malformed:
            self._stop('failed', 'malformed-data')
            return False
        return True

    async def _collect_pages(self, url: str, payload: dict[str, object], *, discovery: bool) -> bool:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while self.execution_status == 'completed':
            request = dict(payload)
            if cursor:
                request['cursor'] = cursor
            page = await self._post(url, request)
            if page is None:
                return False
            process = self._process_discovery_page if discovery else self._process_search_page
            if not process(page):
                return False
            next_cursor = page.get('nextCursor')
            if next_cursor is None:
                return True
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                self._stop('failed', 'invalid-cursor')
                return False
            seen_cursors.add(next_cursor)
            cursor = next_cursor
            if not await self._sleep(self.REQUEST_DELAY_SECONDS):
                return False
        return False

    async def do_search(self) -> None:
        self._started_at = monotonic()
        payload: dict[str, object] = {'domains': [self.target_domain], 'types': ['employees', 'users']}
        if not await self._collect_pages(self.DISCOVERY_URL, payload, discovery=True):
            return
        if not await self._sleep(self.REQUEST_DELAY_SECONDS):
            return
        search_payload = {**payload, 'filter_credentials': True, 'additional_fields': ['sensitive_applications']}
        await self._collect_pages(self.SEARCH_URL, search_payload, discovery=False)
        if self.execution_status == 'completed' and not self._has_results():
            self.stop_reason = 'no-results'

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_emails(self) -> set[str]:
        return self.emails

    async def get_ips(self) -> set[str]:
        """Endpoint addresses are evidence context, never discovery results."""
        return set()

    async def get_urls(self) -> set[str]:
        return self.urls

    async def get_credential_exposures(self) -> list[dict[str, object]]:
        return [json.loads(exposure) for exposure in sorted(self.exposures)]

    async def get_infostealers(self) -> list[dict[str, object]]:
        """Project sanitized exposures into the legacy infostealer field names."""
        records: list[dict[str, object]] = []
        for exposure in await self.get_credential_exposures():
            endpoint = exposure.get('compromised_endpoint')
            record: dict[str, object] = {}
            if isinstance(endpoint, dict):
                for current, legacy in (
                    ('computer_name', 'computer_name'),
                    ('operating_system', 'operating_system'),
                    ('ip', 'ip'),
                    ('antivirus_products', 'antiviruses'),
                ):
                    if current in endpoint:
                        record[legacy] = endpoint[current]
            for current, legacy in (
                ('employee_email', 'email'),
                ('date_compromised', 'date_compromised'),
                ('sensitive_applications', 'top_corporate_services'),
            ):
                if current in exposure:
                    record[legacy] = exposure[current]
            if record:
                records.append(record)
        return records

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

from __future__ import annotations

import json
import re
from email.errors import HeaderParseError
from email.headerregistry import Address
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    from theHarvester.lib.evidence_types import ResultKind

MAX_ASN = 4_294_967_295
_DATE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})')
_LABEL = re.compile(r'[\w .()+/&,:-]+')


def _label(value: object, *, limit: int = 128) -> str:
    if not isinstance(value, str) or not (label := value.strip()) or len(label) > limit or not _LABEL.fullmatch(label):
        raise ValueError('structured result contains an invalid label')
    return label


def _labels(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > 50:
        raise ValueError('structured result labels must be a bounded array')
    return sorted({_label(label, limit=100) for label in value})


def _email(value: object) -> str:
    if not isinstance(value, str) or len(value.encode()) > 254:
        raise ValueError('structured result contains an invalid email')
    try:
        address = Address(addr_spec=value.strip().lower())
    except (HeaderParseError, ValueError) as error:
        raise ValueError('structured result contains an invalid email') from error
    if not address.username or not address.domain or len(address.username.encode()) > 64:
        raise ValueError('structured result contains an invalid email')
    return Address(username=address.username, domain=address.domain.lower()).addr_spec


def _origin(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError('credential exposure URL must be an origin')
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {'http', 'https'}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
        port = f':{parsed.port}' if parsed.port is not None else ''
    except ValueError as error:
        raise ValueError('credential exposure URL must be an origin') from error
    return urlunsplit((parsed.scheme, f'{parsed.hostname.lower()}{port}', '', '', ''))


def _structured_object(value: str, allowed: set[str]) -> dict[str, object]:
    try:
        record = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as error:
        raise ValueError('structured result must contain a JSON object') from error
    if not isinstance(record, dict) or not record or set(record) - allowed:
        raise ValueError('structured result contains unsupported fields')
    return record


def _normalize_credential_exposure(value: str) -> str:
    allowed = {
        'compromised_endpoint',
        'credential_count',
        'credential_type',
        'date_compromised',
        'date_uploaded',
        'domain',
        'employee_email',
        'exposure_category',
        'provider',
        'provider_record_id',
        'sensitive_applications',
        'stealer_family',
        'url',
    }
    record = _structured_object(value, allowed)
    if record.get('provider') != 'hudsonrock-v3':
        raise ValueError('credential exposure must identify hudsonrock-v3')
    normalized: dict[str, object] = {'provider': 'hudsonrock-v3'}
    for field in ('credential_type', 'exposure_category', 'stealer_family'):
        if field in record:
            normalized[field] = _label(record[field])
    for field in ('date_compromised', 'date_uploaded'):
        if field in record:
            date = record[field]
            if not isinstance(date, str) or len(date) > 40 or not _DATE.fullmatch(date):
                raise ValueError('credential exposure contains an invalid date')
            normalized[field] = date
    if 'credential_count' in record:
        count = record['credential_count']
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 500:
            raise ValueError('credential exposure contains an invalid count')
        normalized['credential_count'] = count
    if 'provider_record_id' in record:
        identifier = record['provider_record_id']
        if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{24}', identifier):
            raise ValueError('credential exposure contains an invalid provider identifier')
        normalized['provider_record_id'] = identifier
    if 'url' in record:
        normalized['url'] = _origin(record['url'])
    if 'domain' in record:
        normalized['domain'] = _label(record['domain'], limit=253).lower()
    if 'employee_email' in record:
        normalized['employee_email'] = _email(record['employee_email'])
    if 'sensitive_applications' in record:
        normalized['sensitive_applications'] = _labels(record['sensitive_applications'])
    if 'compromised_endpoint' in record:
        endpoint = record['compromised_endpoint']
        if (
            not isinstance(endpoint, dict)
            or not endpoint
            or set(endpoint)
            - {
                'antivirus_products',
                'computer_name',
                'ip',
                'operating_system',
            }
        ):
            raise ValueError('credential exposure contains invalid endpoint context')
        normalized_endpoint: dict[str, object] = {}
        if 'ip' in endpoint:
            if not isinstance(endpoint['ip'], str):
                raise ValueError('credential exposure contains invalid endpoint context')
            normalized_endpoint['ip'] = str(ip_address(endpoint['ip']))
        for field in ('computer_name', 'operating_system'):
            if field in endpoint:
                normalized_endpoint[field] = _label(endpoint[field])
        if 'antivirus_products' in endpoint:
            normalized_endpoint['antivirus_products'] = _labels(endpoint['antivirus_products'])
        normalized['compromised_endpoint'] = normalized_endpoint
    return json.dumps(normalized, ensure_ascii=False, separators=(',', ':'), sort_keys=True)


def normalize_asn(value: str | int) -> str:
    if isinstance(value, bool) or not isinstance(value, str | int):
        raise ValueError('ASN must be an integer or AS-prefixed integer')
    text = str(value).strip()
    if text[:2].casefold() == 'as':
        text = text[2:]
    if not text.isascii() or not text.isdecimal():
        raise ValueError('ASN must be an integer or AS-prefixed integer')
    number = int(text)
    if not 0 <= number <= MAX_ASN:
        raise ValueError(f'ASN must be between 0 and {MAX_ASN}')
    return f'AS{number}'


def normalize_prefix(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('network prefix must be a non-empty string')
    if '%' in value:
        raise ValueError('network prefix must not contain an IPv6 scope identifier')
    try:
        return str(ip_network(value.strip(), strict=False))
    except ValueError as error:
        raise ValueError('network prefix must be valid IPv4 or IPv6 CIDR') from error


def normalize_result_value(kind: ResultKind | str, value: str) -> str:
    normalized = value.strip()
    if kind == 'asn':
        return normalize_asn(normalized)
    if kind == 'prefix':
        return normalize_prefix(normalized)
    if kind == 'credential-exposure':
        return _normalize_credential_exposure(normalized)
    return normalized

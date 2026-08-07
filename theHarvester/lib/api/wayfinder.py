from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import os
import shlex
import signal
import subprocess
import sys
from argparse import ArgumentParser
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any
from uuid import uuid4
from weakref import WeakKeyDictionary

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field, ValidationError, field_validator

from theHarvester import __version__
from theHarvester.lib.api.auth import API_KEY_COOKIE_NAME, _configured_api_key, get_api_key, wayfinder_session_token
from theHarvester.lib.api.rate_limit import API_RATE_LIMIT, limiter
from theHarvester.lib.enumeration import (
    DEFAULT_DNS_RECURSIVE_QUERY_LIMIT,
    DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
    DEFAULT_RESULT_START,
    EnumerationOptions,
)
from theHarvester.lib.public_egress import PublicResolver
from theHarvester.lib.source_catalog import (
    ACTION_ACTIVITIES,
    SOURCE_SPECS,
    ActivityClass,
    SourceSpec,
    get_source_spec,
    resolve_sources,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

router = APIRouter(prefix='/api/wayfinder', tags=['Wayfinder'])
ui_router = APIRouter()
MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_RUN_REQUEST_BYTES = 64 * 1024
WORKER_LEASE_TIMEOUT_SECONDS = 30
DEFAULT_DNS_RESOLVERS = '1.1.1.1,8.8.8.8,9.9.9.9'
LEGACY_RESULT_ROUTES = {
    'hosts': 'subdomain',
    'ips': 'ip',
    'emails': 'email',
    'asns': 'asn',
    'interesting_urls': 'interesting-url',
    'trello_urls': 'url',
    'twitter_people': 'person',
    'linkedin_people': 'person',
    'linkedin_links': 'person-link',
    'people': 'person',
}
_worker_task: asyncio.Task[None] | None = None
_worker_stop: asyncio.Event | None = None
_worker_wakeup: asyncio.Event | None = None
_worker_owner: str | None = None
_process_groups: WeakKeyDictionary[asyncio.subprocess.Process, int] = WeakKeyDictionary()


def _worker_enabled() -> bool:
    return os.getenv('THEHARVESTER_WAYFINDER_WORKER', 'enabled').casefold() != 'disabled'


def _docker_gateway() -> ipaddress.IPv4Address | None:
    try:
        for line in Path('/proc/net/route').read_text(encoding='ascii').splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 3 and fields[1] == '00000000':
                return ipaddress.IPv4Address(bytes.fromhex(fields[2])[::-1])
    except (OSError, ValueError):
        pass
    return None


@ui_router.get('/', include_in_schema=False)
async def wayfinder_app(request: Request) -> HTMLResponse:
    try:
        client_address = ipaddress.ip_address(request.client.host) if request.client is not None else None
        trusted_gateway = (
            _docker_gateway() if os.getenv('THEHARVESTER_WAYFINDER_LOCAL_PROXY', '').casefold() == 'enabled' else None
        )
        is_local_client = client_address is not None and (client_address.is_loopback or client_address == trusted_gateway)
    except ValueError:
        is_local_client = False
    try:
        hostname = request.url.hostname
        is_loopback_host = hostname == 'localhost' or (hostname is not None and ipaddress.ip_address(hostname).is_loopback)
    except ValueError:
        is_loopback_host = False
    if not is_local_client or not is_loopback_host:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Wayfinder is available only on localhost')
    static_dir = Path(__file__).parent / 'static' / 'wayfinder'
    template = (static_dir / 'index.html').read_text(encoding='utf-8')
    asset_version = max((static_dir / name).stat().st_mtime_ns for name in ('app.css', 'app.js'))
    response = HTMLResponse(template.replace('{{VERSION}}', __version__).replace('{{ASSET_VERSION}}', str(asset_version)))
    if configured_api_key := _configured_api_key():
        response.delete_cookie(API_KEY_COOKIE_NAME, path='/')
        response.set_cookie(
            API_KEY_COOKIE_NAME,
            wayfinder_session_token(configured_api_key),
            httponly=True,
            samesite='strict',
            path='/api/wayfinder',
        )
    return response


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_target(value: str) -> str:
    target = value.strip().rstrip('.').lower()
    if not target or len(target) > 253 or any(character in target for character in '/?#@'):
        raise ValueError('Target must be a hostname or IP address')
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        try:
            target = target.encode('idna').decode('ascii')
        except UnicodeError as error:
            raise ValueError('Target must be a valid hostname') from error
        labels = target.split('.')
        if any(
            not label
            or len(label) > 63
            or label.startswith('-')
            or label.endswith('-')
            or not all(character.isalnum() or character == '-' for character in label)
            for label in labels
        ):
            raise ValueError('Target must be a valid hostname')
        return target


async def is_public_target(target: str) -> bool:
    resolver = PublicResolver()
    try:
        await resolver.resolve(target)
        return True
    except OSError:
        return False
    finally:
        await resolver.close()


class RunRequest(BaseModel):
    target: str
    sources: list[str] = Field(min_length=1, max_length=len(SOURCE_SPECS))
    limit: int = Field(default=500, ge=1, le=10_000)
    start: int = Field(default=DEFAULT_RESULT_START, ge=0)
    deadline_seconds: int = Field(default=1800, ge=30, le=86_400)
    proxies: bool = False
    dns_brute: bool = False
    dns_lookup: bool = False
    dns_resolve: bool = False
    dns_resolvers: list[str] = Field(
        default_factory=lambda: DEFAULT_DNS_RESOLVERS.split(','),
        min_length=3,
        max_length=3,
    )
    dns_recursive_depth: int = Field(default=0, ge=0)
    dns_recursive_query_limit: int = Field(default=DEFAULT_DNS_RECURSIVE_QUERY_LIMIT, gt=0)
    dns_recursive_runtime_seconds: float = Field(
        default=DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS,
        gt=0,
        allow_inf_nan=False,
    )
    shodan: bool = False
    screenshot: bool = False
    take_over: bool = False
    api_scan: bool = False

    @field_validator('target')
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return _normalize_target(value)

    @field_validator('sources')
    @classmethod
    def validate_sources(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError('Sources must not contain duplicates')
        return values

    @field_validator('dns_resolvers')
    @classmethod
    def validate_dns_resolvers(cls, values: list[str]) -> list[str]:
        normalized = [str(ipaddress.ip_address(value.strip())) for value in values]
        if len(set(normalized)) != 3:
            raise ValueError('DNS resolution requires exactly three distinct resolver IPs')
        return normalized


class WayfinderStore:
    def __init__(self, database: str | Path | None = None) -> None:
        configured = database or os.getenv('THEHARVESTER_WAYFINDER_DB')
        self.database = Path(configured) if configured else Path('~/.local/share/theHarvester/wayfinder.sqlite').expanduser()

    async def initialize(self) -> None:
        try:
            self.database.parent.mkdir(parents=True, mode=0o700)
        except FileExistsError:
            pass
        else:
            self.database.parent.chmod(0o700)
        self.database.touch(exist_ok=True, mode=0o600)
        self.database.chmod(0o600)
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                CREATE TABLE IF NOT EXISTS wayfinder_runs (
                    run_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    request_json TEXT NOT NULL,
                    evidence_json TEXT,
                    cancellation_requested_at TEXT,
                    error TEXT,
                    log TEXT NOT NULL DEFAULT ''
                )
                """
            )
            await database.execute(
                """
                CREATE TABLE IF NOT EXISTS wayfinder_worker_lease (
                    lease_name TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL
                )
                """
            )
            await database.commit()

    @staticmethod
    def _row(row: aiosqlite.Row, *, detail: bool = False) -> dict[str, Any]:
        result = {
            'run_id': row['run_id'],
            'target': row['target'],
            'status': row['status'],
            'origin': row['origin'],
            'created_at': row['created_at'],
            'started_at': row['started_at'],
            'completed_at': row['completed_at'],
            'cancellation_requested_at': row['cancellation_requested_at'],
            'error': row['error'],
        }
        request = json.loads(row['request_json'])
        evidence = json.loads(row['evidence_json']) if row['evidence_json'] else None
        result['sources'] = request.get('sources', [])
        result['activities'] = _activities(request)
        result['evidence_status'] = evidence.get('status') if evidence else None
        result['result_count'] = len(_results(evidence)) if evidence else 0
        if detail:
            result['request'] = request
            result['evidence'] = evidence
            result['results'] = _results(evidence)
            result['source_executions'] = _source_executions(evidence)
            result['screenshots'] = _screenshots(evidence, row['run_id'])
            result['log'] = row['log']
        return result

    async def create(self, request: RunRequest) -> dict[str, Any]:
        await self.initialize()
        run_id = str(uuid4())
        created_at = _now()
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                INSERT INTO wayfinder_runs
                    (run_id, target, status, origin, created_at, request_json)
                VALUES (?, ?, 'queued', 'local', ?, ?)
                """,
                (run_id, request.target, created_at, request.model_dump_json()),
            )
            await database.commit()
        run = await self.get(run_id)
        assert run is not None
        return run

    async def import_evidence(self, evidence: dict[str, Any], filename: str) -> dict[str, Any]:
        await self.initialize()
        run_id = str(uuid4())
        created_at = _now()
        target = _normalize_target(str(evidence['target']))
        source_executions = _source_executions(evidence)
        request = {
            'filename': filename,
            'sources': sorted(
                {
                    str(execution.get('source') or execution.get('name'))
                    for execution in source_executions
                    if execution.get('source') or execution.get('name')
                }
            ),
            'activities': _evidence_activities(source_executions),
        }
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                INSERT INTO wayfinder_runs
                    (run_id, target, status, origin, created_at, started_at, completed_at, request_json, evidence_json)
                VALUES (?, ?, 'completed', 'imported', ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    target,
                    created_at,
                    evidence.get('started_at'),
                    evidence.get('completed_at') or created_at,
                    json.dumps(request),
                    json.dumps(evidence),
                ),
            )
            await database.commit()
        run = await self.get(run_id)
        assert run is not None
        return run

    async def list_runs(self) -> list[dict[str, Any]]:
        await self.initialize()
        async with aiosqlite.connect(self.database) as database:
            database.row_factory = aiosqlite.Row
            cursor = await database.execute('SELECT * FROM wayfinder_runs ORDER BY created_at DESC')
            rows = await cursor.fetchall()
        return [self._row(row) for row in rows]

    async def get(self, run_id: str) -> dict[str, Any] | None:
        await self.initialize()
        async with aiosqlite.connect(self.database) as database:
            database.row_factory = aiosqlite.Row
            cursor = await database.execute('SELECT * FROM wayfinder_runs WHERE run_id = ?', (run_id,))
            row = await cursor.fetchone()
        return self._row(row, detail=True) if row else None

    async def cancel(self, run_id: str) -> dict[str, Any] | None:
        await self.initialize()
        requested_at = _now()
        async with aiosqlite.connect(self.database) as database:
            await database.execute('BEGIN IMMEDIATE')
            cursor = await database.execute('SELECT status FROM wayfinder_runs WHERE run_id = ?', (run_id,))
            row = await cursor.fetchone()
            if row is None:
                await database.rollback()
                return None
            current = row[0]
            if current == 'queued':
                await database.execute(
                    "UPDATE wayfinder_runs SET status = 'cancelled', cancellation_requested_at = ?, completed_at = ? "
                    "WHERE run_id = ? AND status = 'queued'",
                    (requested_at, requested_at, run_id),
                )
            elif current == 'running':
                await database.execute(
                    "UPDATE wayfinder_runs SET status = 'cancelling', cancellation_requested_at = ? "
                    "WHERE run_id = ? AND status = 'running'",
                    (requested_at, run_id),
                )
            elif current not in {'cancelling', 'cancelled'}:
                await database.rollback()
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f'Run is already {current}')
            await database.commit()
        return await self.get(run_id)

    async def recover_orphans(self) -> None:
        await self.initialize()
        recovered_at = _now()
        async with aiosqlite.connect(self.database) as database:
            cursor = await database.execute("SELECT run_id FROM wayfinder_runs WHERE status IN ('running', 'cancelling')")
            for (run_id,) in await cursor.fetchall():
                evidence, evidence_error = _read_child_evidence(_artifact_dir(run_id, database=self.database))
                error = 'Wayfinder restarted before child completion'
                if evidence_error:
                    error += f'; {evidence_error}'
                await database.execute(
                    """
                    UPDATE wayfinder_runs
                    SET status = 'failed', completed_at = ?, error = ?, evidence_json = COALESCE(?, evidence_json)
                    WHERE run_id = ? AND status IN ('running', 'cancelling')
                    """,
                    (recovered_at, error, json.dumps(evidence) if evidence else None, run_id),
                )
            await database.commit()

    async def acquire_worker_lease(self, owner_id: str) -> bool:
        await self.initialize()
        now = _now()
        async with aiosqlite.connect(self.database) as database:
            await database.execute('BEGIN IMMEDIATE')
            cursor = await database.execute(
                "SELECT owner_id, heartbeat_at FROM wayfinder_worker_lease WHERE lease_name = 'executor'"
            )
            row = await cursor.fetchone()
            stale = row is not None and datetime.fromisoformat(row[1]) < datetime.fromisoformat(now) - timedelta(
                seconds=WORKER_LEASE_TIMEOUT_SECONDS
            )
            if row is not None and row[0] != owner_id and not stale:
                await database.rollback()
                return False
            await database.execute(
                """
                INSERT INTO wayfinder_worker_lease (lease_name, owner_id, heartbeat_at)
                VALUES ('executor', ?, ?)
                ON CONFLICT(lease_name) DO UPDATE
                SET owner_id = excluded.owner_id, heartbeat_at = excluded.heartbeat_at
                """,
                (owner_id, now),
            )
            await database.commit()
        return True

    async def heartbeat_worker_lease(self, owner_id: str) -> bool:
        async with aiosqlite.connect(self.database) as database:
            cursor = await database.execute(
                "UPDATE wayfinder_worker_lease SET heartbeat_at = ? WHERE lease_name = 'executor' AND owner_id = ?",
                (_now(), owner_id),
            )
            await database.commit()
        return cursor.rowcount == 1

    async def release_worker_lease(self, owner_id: str) -> None:
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                "DELETE FROM wayfinder_worker_lease WHERE lease_name = 'executor' AND owner_id = ?",
                (owner_id,),
            )
            await database.commit()

    async def claim_next(self) -> dict[str, Any] | None:
        await self.initialize()
        async with aiosqlite.connect(self.database) as database:
            await database.execute('BEGIN IMMEDIATE')
            cursor = await database.execute(
                "SELECT run_id FROM wayfinder_runs WHERE status = 'queued' ORDER BY created_at LIMIT 1"
            )
            row = await cursor.fetchone()
            if row is None:
                await database.rollback()
                return None
            run_id = row[0]
            started_at = _now()
            cursor = await database.execute(
                "UPDATE wayfinder_runs SET status = 'running', started_at = ? WHERE run_id = ? AND status = 'queued'",
                (started_at, run_id),
            )
            if cursor.rowcount != 1:
                await database.rollback()
                return None
            await database.commit()
        return await self.get(run_id)

    async def finish(self, run_id: str, evidence: dict[str, Any] | None, log: str) -> None:
        completed_at = _now()
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                """
                UPDATE wayfinder_runs
                SET status = CASE status WHEN 'cancelling' THEN 'cancelled' ELSE 'completed' END,
                    completed_at = ?, evidence_json = COALESCE(?, evidence_json), log = ?
                WHERE run_id = ? AND status IN ('running', 'cancelling')
                """,
                (completed_at, json.dumps(evidence) if evidence else None, log[-200_000:], run_id),
            )
            await database.commit()

    async def fail(
        self,
        run_id: str,
        error: str,
        log: str,
        *,
        cancelled: bool = False,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        completed_at = _now()
        lifecycle_status = 'cancelled' if cancelled else 'failed'
        async with aiosqlite.connect(self.database) as database:
            await database.execute(
                'UPDATE wayfinder_runs SET status = ?, completed_at = ?, error = ?, log = ?, '
                'evidence_json = COALESCE(?, evidence_json) WHERE run_id = ?',
                (lifecycle_status, completed_at, error, log[-200_000:], json.dumps(evidence) if evidence else None, run_id),
            )
            await database.commit()


def _activities(request: dict[str, Any]) -> list[str]:
    if request.get('activities'):
        return list(request['activities'])
    activities = {'P0'}
    source_activities = {_source.activity for source in request.get('sources', []) if (_source := _source_spec(source))}
    if ActivityClass.DNS in source_activities:
        activities.add('P1')
    if ActivityClass.DIRECT in source_activities:
        activities.add('P2')
    if (
        request.get('dns_brute')
        or request.get('dns_lookup')
        or request.get('dns_resolve')
        or request.get('dns_recursive_depth', 0) > 0
    ):
        activities.add('P1')
    if request.get('screenshot') or request.get('take_over') or request.get('api_scan'):
        activities.add('P2')
    return [activity for activity in ('P0', 'P1', 'P2') if activity in activities]


def _has_direct_activity(request: dict[str, Any]) -> bool:
    return any(
        (_source := _source_spec(source)) is not None and _source.activity is ActivityClass.DIRECT
        for source in request.get('sources', [])
    ) or any(request.get(action) for action in ('screenshot', 'take_over', 'api_scan'))


def _source_spec(name: str) -> SourceSpec | None:
    try:
        return get_source_spec(name)
    except KeyError:
        return None


def _results(evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not evidence:
        return []
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(result_type: str, value: object, sources: object = (), dns_status: str | None = None) -> None:
        if value is None or value == '':
            return
        normalized_value = str(value)
        key = (result_type, normalized_value)
        if key in seen:
            return
        seen.add(key)
        normalized_sources = sorted({str(source) for source in sources}) if isinstance(sources, (list, tuple, set)) else []
        item: dict[str, Any] = {'type': result_type, 'value': normalized_value, 'sources': normalized_sources}
        if dns_status is not None:
            item['dns_status'] = dns_status
        results.append(item)

    for item in evidence.get('results') or []:
        if isinstance(item, dict) and item.get('type') != 'screenshot':
            add(str(item.get('type', 'other')), item.get('value'), item.get('sources', ()), item.get('dns_status'))

    for entity in evidence.get('entities') or []:
        if not isinstance(entity, dict):
            continue
        scope_classes = entity.get('scope_classes', [])
        result_type = 'subdomain'
        if 'scope-extension' in scope_classes:
            result_type = 'scope-extension'
        elif 'external-relationship' in scope_classes:
            result_type = 'external-relationship'
        provenance = entity.get('observations') or entity.get('provenance') or []
        sources = [item.get('source') for item in provenance if isinstance(item, dict) and item.get('source')]
        addressability = entity.get('addressability')
        dns_status = (
            {
                'currently-addressable': 'resolved',
                'not-currently-addressable': 'no-answer',
                'resolver-disputed': 'disputed',
                'wildcard-uncertain': 'uncertain',
                'unverified': 'not-captured',
            }.get(str(addressability))
            if addressability is not None
            else None
        )
        add(result_type, entity.get('value'), sources, dns_status)

    kind_map = {
        'hostname': 'subdomain',
        'ip-address': 'ip',
        'interesting-url': 'interesting-url',
        'api-endpoint': 'api-endpoint',
        'shodan-result': 'shodan',
    }
    for observation in evidence.get('selected_observations') or []:
        if not isinstance(observation, dict) or observation.get('kind') == 'screenshot':
            continue
        kind = str(observation.get('kind', 'other'))
        add(kind_map.get(kind, kind), observation.get('value'), [observation.get('source')] if observation.get('source') else [])

    legacy = evidence.get('_legacy', {})
    if not isinstance(legacy, dict):
        legacy = {}
    for key, result_type in LEGACY_RESULT_ROUTES.items():
        for value in legacy.get(key, []):
            add(result_type, json.dumps(value, sort_keys=True) if isinstance(value, dict) else value)
    return results


def _source_executions(evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not evidence:
        return []
    executions = evidence.get('source_executions') or evidence.get('executions') or []
    return [dict(execution) for execution in executions if isinstance(execution, dict)]


def _screenshots(_evidence: dict[str, Any] | None, run_id: str) -> list[dict[str, Any]]:
    screenshot_dir = _artifact_dir(run_id) / 'screenshots'
    if not screenshot_dir.is_dir():
        return []
    return [
        {
            'name': path.name,
            'target': path.stem,
            'url': f'/api/wayfinder/runs/{run_id}/screenshots/{path.name}',
        }
        for path in sorted(screenshot_dir.glob('*.png'))
        if path.is_file()
    ]


def _evidence_activities(executions: list[dict[str, Any]]) -> list[str]:
    activities: set[str] = set()
    source_activities = {source.name: source.activity.value for source in SOURCE_SPECS.values()}
    for execution in executions:
        source = str(execution.get('source') or execution.get('name') or '')
        activity = str(execution.get('activity') or '')
        declared = source_activities.get(source)
        if source.startswith('action:'):
            declared = ACTION_ACTIVITIES.get(source.removeprefix('action:'))
        if declared:
            activities.add(str(declared))
        elif activity in {'P0', 'P1', 'P2'}:
            activities.add(activity)
    if not activities:
        activities.add('P0')
    return [activity for activity in ('P0', 'P1', 'P2') if activity in activities]


def _legacy_target(payload: dict[str, Any]) -> str | None:
    command = payload.get('cmd')
    if not isinstance(command, str):
        return None
    try:
        arguments = shlex.split(command)
    except ValueError:
        return None
    for flag in ('-d', '--domain'):
        if flag in arguments and arguments.index(flag) + 1 < len(arguments):
            return arguments[arguments.index(flag) + 1]
    return None


def _parse_json_import(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Result file is not valid JSON') from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Result JSON must be an object')
    if isinstance(payload.get('evidence_run'), dict):
        evidence = dict(payload['evidence_run'])
        evidence['_legacy'] = {key: value for key, value in payload.items() if key != 'evidence_run'}
    elif isinstance(payload.get('run'), dict):
        evidence = dict(payload['run'])
        evidence['_legacy'] = {key: value for key, value in payload.items() if key != 'run'}
    else:
        evidence = dict(payload)
        if 'target' not in evidence:
            evidence = {
                'run_id': str(uuid4()),
                'target': _legacy_target(payload),
                'status': 'complete',
                'started_at': None,
                'completed_at': _now(),
                '_legacy': payload,
            }
    return _validate_evidence(evidence)


def _parse_jsonl_import(body: bytes) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    try:
        for line in body.decode('utf-8').splitlines():
            if line.strip():
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError
                records.append(record)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Result file is not valid JSONL') from error
    if not records or any(record.get('schema_version') != 'theharvester-evidence-v1' for record in records):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='JSONL must use theharvester-evidence-v1')
    run_records = [record.get('data') for record in records if record.get('record_type') == 'run']
    if len(run_records) != 1 or not isinstance(run_records[0], dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='JSONL must contain exactly one run record')
    evidence = dict(run_records[0])
    mapping = {
        'source_execution': 'source_executions',
        'discovery_observation': 'observations',
        'dns_validation_observation': 'dns_validations',
        'merged_result': 'entities',
        'selected_observation': 'selected_observations',
    }
    for record_type, key in mapping.items():
        evidence[key] = [
            record['data']
            for record in records
            if record.get('record_type') == record_type and isinstance(record.get('data'), dict)
        ]
    return _validate_evidence(evidence)


def _validate_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    if not evidence.get('target'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Result file does not identify a target')
    try:
        evidence['target'] = _normalize_target(str(evidence['target']))
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    if evidence.get('status') not in {'complete', 'partial', 'failed'}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Evidence status must be complete, partial, or failed',
        )
    for field in ('results', 'source_executions', 'executions', 'entities', 'selected_observations'):
        value = evidence.get(field)
        if value is None:
            evidence[field] = []
        elif not isinstance(value, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f'Evidence field {field} must be an array',
            )
    for entity in evidence['entities']:
        if not isinstance(entity, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Evidence entities must be objects')
        for field in ('scope_classes', 'observations', 'provenance'):
            if field in entity and not isinstance(entity[field], list):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f'Evidence entity field {field} must be an array',
                )
    legacy = evidence.get('_legacy')
    if legacy is not None:
        if not isinstance(legacy, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Evidence field _legacy must be an object')
        for field in LEGACY_RESULT_ROUTES:
            if field in legacy and not isinstance(legacy[field], list):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f'Legacy evidence field {field} must be an array',
                )
    evidence.setdefault('run_id', str(uuid4()))
    evidence.setdefault('completed_at', _now())
    return evidence


def _artifact_dir(run_id: str, *, database: Path | None = None) -> Path:
    configured = os.getenv('THEHARVESTER_WAYFINDER_ARTIFACTS')
    root = Path(configured) if configured else (database or WayfinderStore().database).parent / 'wayfinder-artifacts'
    return root / run_id


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise OSError(f'Refusing symlinked Wayfinder directory: {path}')
    path.chmod(0o700)


async def _default_process_factory(run_id: str, _artifact_dir_path: Path) -> asyncio.subprocess.Process:
    process_options = (
        {'creationflags': getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)} if os.name == 'nt' else {'start_new_session': True}
    )
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        '-m',
        'theHarvester.lib.api.wayfinder',
        '--execute',
        run_id,
        '--database',
        str(WayfinderStore().database),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **process_options,
    )
    if process.pid is not None:
        _process_groups[process] = process.pid
    return process


_process_factory: Callable[[str, Path], Awaitable[asyncio.subprocess.Process]] = _default_process_factory


async def _process_output(process: asyncio.subprocess.Process) -> str:
    async def read(stream: asyncio.StreamReader | None) -> bytes:
        return await stream.read() if stream is not None else b''

    stdout, stderr = await asyncio.gather(read(process.stdout), read(process.stderr))
    return '\n'.join(part.decode('utf-8', errors='replace').strip() for part in (stdout, stderr) if part).strip()


def _read_child_evidence(artifact_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    evidence_path = artifact_dir / 'evidence.json'
    if not evidence_path.is_file():
        return None, None
    try:
        return _validate_evidence(json.loads(evidence_path.read_text(encoding='utf-8'))), None
    except (OSError, json.JSONDecodeError, HTTPException) as error:
        return None, f'Child evidence is invalid: {error}'


def _write_child_evidence(artifact_dir: Path, evidence: Any, *, partial: bool) -> None:
    payload = evidence.evidence_dict()
    if partial:
        payload['status'] = 'partial'
    temporary = artifact_dir / 'evidence.json.tmp'
    temporary.write_text(json.dumps(payload), encoding='utf-8')
    temporary.chmod(0o600)
    evidence_path = artifact_dir / 'evidence.json'
    temporary.replace(evidence_path)
    evidence_path.chmod(0o600)


async def _signal_process_tree(process: asyncio.subprocess.Process, *, force: bool) -> None:
    process_group = _process_groups.get(process)
    if process_group is not None and os.name != 'nt':
        try:
            os.killpg(process_group, signal.SIGKILL if force else signal.SIGTERM)
        except ProcessLookupError:
            pass
        return
    if process_group is not None and os.name == 'nt':
        if force:
            killer = await asyncio.create_subprocess_exec(
                'taskkill',
                '/PID',
                str(process.pid),
                '/T',
                '/F',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
        else:
            try:
                process.send_signal(getattr(signal, 'CTRL_BREAK_EVENT', 1))
            except ProcessLookupError:
                pass
        return
    try:
        process.kill() if force else process.terminate()
    except ProcessLookupError:
        pass


async def _stop_process(process: asyncio.subprocess.Process, wait_task: asyncio.Task[int]) -> None:
    if process.returncode is None:
        await _signal_process_tree(process, force=False)
    try:
        await asyncio.wait_for(asyncio.shield(wait_task), timeout=2)
    except TimeoutError:
        if process.returncode is None:
            await _signal_process_tree(process, force=True)
        await wait_task


async def _execute_claimed(store: WayfinderStore, run: dict[str, Any], owner_id: str | None = None) -> None:
    run_id = run['run_id']
    if _has_direct_activity(run['request']) and not await is_public_target(run['target']):
        await store.fail(run_id, 'P2 target is no longer publicly routable', '')
        return
    artifact_dir = _artifact_dir(run_id)
    _ensure_private_directory(artifact_dir)
    try:
        process = await _process_factory(run_id, artifact_dir)
    except (OSError, RuntimeError) as error:
        await store.fail(run_id, f'Could not start child process: {error}', '')
        return
    wait_task = asyncio.create_task(process.wait())
    output_task = asyncio.create_task(_process_output(process))
    deadline = asyncio.get_running_loop().time() + int(run['request']['deadline_seconds'])
    next_heartbeat = 0.0
    while not wait_task.done():
        await asyncio.sleep(0.05)
        if owner_id is not None and asyncio.get_running_loop().time() >= next_heartbeat:
            if not await store.heartbeat_worker_lease(owner_id):
                await _stop_process(process, wait_task)
                await store.fail(run_id, 'Worker lost its execution lease', await output_task)
                return
            next_heartbeat = asyncio.get_running_loop().time() + 5
        current = await store.get(run_id)
        stopping = _worker_stop is not None and _worker_stop.is_set()
        if current is not None and current['status'] == 'cancelling':
            await _stop_process(process, wait_task)
            evidence, evidence_error = _read_child_evidence(artifact_dir)
            failure_message = 'Cancelled by operator' + (f'; {evidence_error}' if evidence_error else '')
            await store.fail(run_id, failure_message, await output_task, cancelled=True, evidence=evidence)
            return
        if stopping:
            await _stop_process(process, wait_task)
            evidence, evidence_error = _read_child_evidence(artifact_dir)
            failure_message = 'Wayfinder stopped before child completion' + (f'; {evidence_error}' if evidence_error else '')
            await store.fail(run_id, failure_message, await output_task, evidence=evidence)
            return
        if asyncio.get_running_loop().time() >= deadline:
            await _stop_process(process, wait_task)
            evidence, evidence_error = _read_child_evidence(artifact_dir)
            failure_message = f'Run exceeded its {run["request"]["deadline_seconds"]} second deadline'
            if evidence_error:
                failure_message += f'; {evidence_error}'
            await store.fail(
                run_id,
                failure_message,
                await output_task,
                evidence=evidence,
            )
            return
    log = await output_task
    current = await store.get(run_id)
    evidence, evidence_error = _read_child_evidence(artifact_dir)
    if evidence_error:
        await store.fail(
            run_id,
            evidence_error,
            log,
            cancelled=current is not None and current['status'] == 'cancelling',
        )
        return
    if current is not None and current['status'] == 'cancelling':
        await store.finish(run_id, evidence, log)
    elif process.returncode == 0 and evidence is not None:
        await store.finish(run_id, evidence, log)
    else:
        await store.fail(
            run_id, f'Child process exited with status {process.returncode} without terminal completion', log, evidence=evidence
        )


async def _worker_loop(store: WayfinderStore, owner_id: str) -> None:
    assert _worker_stop is not None
    assert _worker_wakeup is not None
    while not _worker_stop.is_set():
        if not await store.heartbeat_worker_lease(owner_id):
            return
        run = await store.claim_next()
        if run is not None:
            await _execute_claimed(store, run, owner_id)
            continue
        _worker_wakeup.clear()
        try:
            await asyncio.wait_for(_worker_wakeup.wait(), timeout=0.5)
        except TimeoutError:
            continue


async def _supervise_worker(store: WayfinderStore, owner_id: str) -> None:
    assert _worker_stop is not None
    assert _worker_wakeup is not None
    while not _worker_stop.is_set():
        if await store.acquire_worker_lease(owner_id):
            try:
                await store.recover_orphans()
            except BaseException:
                await store.release_worker_lease(owner_id)
                raise
            await _worker_loop(store, owner_id)
            return
        _worker_wakeup.clear()
        try:
            await asyncio.wait_for(_worker_wakeup.wait(), timeout=0.5)
        except TimeoutError:
            continue


async def start_worker() -> None:
    global _worker_owner, _worker_stop, _worker_task, _worker_wakeup
    if not _worker_enabled():
        return
    if _worker_task is not None and not _worker_task.done():
        return
    store = WayfinderStore()
    owner_id = str(uuid4())
    _worker_owner = owner_id
    _worker_stop = asyncio.Event()
    _worker_wakeup = asyncio.Event()
    _worker_task = asyncio.create_task(_supervise_worker(store, owner_id))


async def stop_worker() -> None:
    global _worker_owner, _worker_stop, _worker_task, _worker_wakeup
    task = _worker_task
    owner_id = _worker_owner
    try:
        if task is not None:
            if _worker_stop is not None:
                _worker_stop.set()
            if _worker_wakeup is not None:
                _worker_wakeup.set()
            await task
    finally:
        try:
            if owner_id is not None:
                await WayfinderStore().release_worker_lease(owner_id)
        finally:
            _worker_task = None
            _worker_owner = None
            _worker_stop = None
            _worker_wakeup = None


def _wake_worker() -> None:
    if _worker_wakeup is not None:
        _worker_wakeup.set()


async def _read_limited_body(request: Request, limit: int, detail: str) -> bytes:
    content_length = request.headers.get('content-length')
    if content_length and content_length.isdigit() and int(content_length) > limit:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=detail)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=detail)
        body.extend(chunk)
    return bytes(body)


async def _child_execute(run_id: str, database: Path) -> None:
    from theHarvester import __main__ as main_module
    from theHarvester.lib.completed_result import CompletedResult

    store = WayfinderStore(database)
    run = await store.get(run_id)
    if run is None or run['status'] not in {'running', 'cancelling'}:
        raise RuntimeError('Wayfinder run is not executable')
    request = run['request']
    artifact_dir = _artifact_dir(run_id)
    _ensure_private_directory(artifact_dir)
    screenshot_dir = artifact_dir / 'screenshots'
    if request.get('screenshot'):
        _ensure_private_directory(screenshot_dir)
    recursive_depth = request.get('dns_recursive_depth', 0)
    resolver_list = request.get('dns_resolvers', DEFAULT_DNS_RESOLVERS.split(','))
    args = EnumerationOptions(
        api_scan=request.get('api_scan', False),
        dns_brute=request.get('dns_brute', False),
        dns_lookup=request.get('dns_lookup', False),
        dns_recursive_depth=recursive_depth,
        dns_recursive_query_limit=request.get('dns_recursive_query_limit', DEFAULT_DNS_RECURSIVE_QUERY_LIMIT),
        dns_recursive_runtime_seconds=request.get('dns_recursive_runtime_seconds', DEFAULT_DNS_RECURSIVE_RUNTIME_SECONDS),
        dns_resolve=','.join(resolver_list) if request.get('dns_resolve') or recursive_depth > 0 else '',
        dns_server=None,
        domain=run['target'],
        filename='',
        limit=request['limit'],
        proxies=request.get('proxies', False),
        quiet=True,
        screenshot=str(screenshot_dir) if request.get('screenshot') else '',
        shodan=request.get('shodan', False),
        source=','.join(request['sources']),
        start=request.get('start', DEFAULT_RESULT_START),
        take_over=request.get('take_over', False),
        wordlist='',
    )
    checkpoint_lock = asyncio.Lock()

    async def checkpoint(evidence: CompletedResult) -> None:
        async with checkpoint_lock:
            _write_child_evidence(artifact_dir, evidence, partial=True)

    task = asyncio.create_task(main_module.start(args, completed_result_checkpoint=checkpoint, return_completed_result=True))
    loop = asyncio.get_running_loop()
    signal_handler_installed = False
    if os.name != 'nt':
        try:
            loop.add_signal_handler(signal.SIGTERM, task.cancel)
            signal_handler_installed = True
        except (NotImplementedError, RuntimeError):
            pass
    try:
        response = await task
    except asyncio.CancelledError:
        return
    finally:
        if signal_handler_installed:
            loop.remove_signal_handler(signal.SIGTERM)
    evidence = response[-1]
    if not isinstance(evidence, CompletedResult):
        raise RuntimeError('theHarvester did not return terminal evidence')
    _write_child_evidence(artifact_dir, evidence, partial=False)


@router.get('/runs')
async def list_runs(_api_key: Annotated[str, Depends(get_api_key)]) -> list[dict[str, Any]]:
    return await WayfinderStore().list_runs()


@router.get('/sources')
async def list_sources(_api_key: Annotated[str, Depends(get_api_key)]) -> list[dict[str, Any]]:
    from theHarvester.lib.core import Core

    provider_aliases = {'chaos': 'projectDiscovery', 'github-code': 'github', 'pentesttools': 'pentestTools'}
    provider_names = {provider.casefold(): provider for provider in Core._API_KEY_FIELDS}

    def credentials(source: SourceSpec) -> list[str]:
        provider = provider_aliases.get(source.name, provider_names.get(source.name.casefold()))
        if provider is None:
            return []
        return [f'api-{field}' for field in Core._API_KEY_FIELDS.get(provider, ())]

    return [
        {
            'name': source.name,
            'activity': source.activity,
            'credentials': credentials(source),
            'capabilities': sorted(source.capabilities),
        }
        for source in sorted(SOURCE_SPECS.values(), key=lambda item: item.name)
    ]


@router.post('/runs', status_code=status.HTTP_201_CREATED)
@limiter.limit(API_RATE_LIMIT)
async def create_run(
    request: Request,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> dict[str, Any]:
    body = await _read_limited_body(request, MAX_RUN_REQUEST_BYTES, 'Run request exceeds the 64 KiB limit')
    try:
        run_request = RunRequest.model_validate_json(body)
    except ValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=error.errors(include_url=False, include_context=False),
        ) from error
    selected_sources = resolve_sources(run_request.sources)
    unsupported_sources = [source for source in selected_sources if _source_spec(source) is None]
    if unsupported_sources:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'Unsupported sources: {", ".join(sorted(unsupported_sources))}',
        )
    run_request.sources = [get_source_spec(source).name for source in selected_sources]
    has_direct_source = any(get_source_spec(source).activity is ActivityClass.DIRECT for source in run_request.sources)
    if (
        has_direct_source or run_request.screenshot or run_request.take_over or run_request.api_scan
    ) and not await is_public_target(run_request.target):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='P2 direct interaction requires a publicly routable target',
        )
    if not _worker_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Wayfinder execution worker is disabled',
        )
    if _worker_task is None or _worker_task.done():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Wayfinder execution worker is unavailable',
        )
    run = await WayfinderStore().create(run_request)
    _wake_worker()
    return run


@router.post('/import', status_code=status.HTTP_201_CREATED)
@limiter.limit(API_RATE_LIMIT)
async def import_run(
    request: Request,
    _api_key: Annotated[str, Depends(get_api_key)],
    filename: Annotated[str, Query(min_length=1, max_length=255)],
) -> dict[str, Any]:
    body = await _read_limited_body(request, MAX_IMPORT_BYTES, 'Result file exceeds the 10 MiB limit')
    safe_filename = Path(filename).name
    suffix = Path(safe_filename).suffix.casefold()
    if suffix == '.json':
        evidence = _parse_json_import(body)
    elif suffix == '.jsonl':
        evidence = _parse_jsonl_import(body)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Choose a .json or .jsonl result file')
    return await WayfinderStore().import_evidence(evidence, safe_filename)


@router.get('/runs/{run_id}')
async def get_run(run_id: str, _api_key: Annotated[str, Depends(get_api_key)]) -> dict[str, Any]:
    run = await WayfinderStore().get(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Wayfinder run not found')
    return run


@router.post('/runs/{run_id}/cancel')
@limiter.limit(API_RATE_LIMIT)
async def cancel_run(
    request: Request,
    run_id: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> dict[str, Any]:
    run = await WayfinderStore().cancel(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Wayfinder run not found')
    return run


@router.get('/runs/{run_id}/export.json')
async def export_run_json(run_id: str, _api_key: Annotated[str, Depends(get_api_key)]) -> Response:
    run = await WayfinderStore().get(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Wayfinder run not found')
    payload = {
        'wayfinder_run_id': run['run_id'],
        'evidence_run_id': (run['evidence'] or {}).get('run_id'),
        'target': run['target'],
        'lifecycle_status': run['status'],
        'evidence_status': run['evidence_status'],
        'created_at': run['created_at'],
        'started_at': run['started_at'],
        'completed_at': run['completed_at'],
        'request': run['request'],
        'source_executions': run['source_executions'],
        'results': run['results'],
    }
    return Response(
        json.dumps(payload, indent=2) + '\n',
        media_type='application/json',
        headers={'Content-Disposition': f'attachment; filename="{run["target"]}-{run_id}.json"'},
    )


@router.get('/runs/{run_id}/export.csv')
async def export_run_csv(run_id: str, _api_key: Annotated[str, Depends(get_api_key)]) -> Response:
    run = await WayfinderStore().get(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Wayfinder run not found')
    output = io.StringIO(newline='')
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator='\n')
    writer.writerow(('type', 'value', 'dns_status', 'sources'))
    for result in run['results']:
        writer.writerow(
            (
                _safe_csv_cell(result['type']),
                _safe_csv_cell(result['value']),
                _safe_csv_cell(result.get('dns_status', '')),
                _safe_csv_cell(','.join(result.get('sources', []))),
            )
        )
    return Response(
        output.getvalue(),
        media_type='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{run["target"]}-{run_id}.csv"'},
    )


def _safe_csv_cell(value: object) -> str:
    text = str(value)
    return f"'{text}" if text.startswith(('=', '+', '-', '@', '\t', '\r')) else text


@router.get('/runs/{run_id}/screenshots/{name}')
async def get_screenshot(
    run_id: str,
    name: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> FileResponse:
    if Path(name).name != name or Path(name).suffix.casefold() != '.png':
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Screenshot not found')
    run = await WayfinderStore().get(run_id)
    artifact_dir = _artifact_dir(run_id)
    screenshot_dir = artifact_dir / 'screenshots'
    path = screenshot_dir / name
    if run is None or artifact_dir.is_symlink() or screenshot_dir.is_symlink() or path.is_symlink() or not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Screenshot not found')
    return FileResponse(path, media_type='image/png', filename=name)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--execute', required=True)
    parser.add_argument('--database', required=True, type=Path)
    child_args = parser.parse_args()
    asyncio.run(_child_execute(child_args.execute, child_args.database))

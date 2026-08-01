import json
from types import SimpleNamespace

import pytest


def test_storage_normalization_does_not_widen_a_www_target() -> None:
    import theHarvester.__main__ as main_module

    assert main_module._normalize_hosts_for_storage(
        ['api.example.com', 'child.www.example.com'],
        'www.example.com',
    ) == {'child.www.example.com'}


@pytest.mark.asyncio
async def test_cli_finishes_selected_work_before_persisting_and_reporting(monkeypatch, tmp_path) -> None:
    import theHarvester.__main__ as main_module

    events: list[str] = []
    persisted = []

    class FakeCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, _proxy: bool = False) -> None:
            events.append('source')

        async def get_hostnames(self) -> list[str]:
            return ['api.example.com', 'outside.example.net']

    class FakeTakeOver:
        def __init__(self, hosts: list[str]) -> None:
            assert hosts == ['api.example.com']

        async def populate_fingerprints(self) -> None:
            return None

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False
            events.append('takeover')

        async def get_takeover_results(self) -> dict[str, str]:
            return {'api.example.com': 'not-vulnerable'}

    class FakeApiEndpoints:
        def __init__(self, word: str, wordlist: str) -> None:
            assert word == 'example.com'
            assert wordlist.endswith('api-words.txt')
            self.public = SimpleNamespace(method='GET')
            self.private = SimpleNamespace(method='POST')

        async def do_search(self) -> None:
            events.append('api-scan')

        def get_found_endpoints(self):
            return {'https://example.com/api': self.public, 'https://example.com/private': self.private}

        def get_interesting_endpoints(self):
            return {'https://example.com/api': self.public}

        def get_auth_required(self):
            return {'https://example.com/private': self.private}

        def get_api_versions(self):
            return {'v1'}

        def get_rate_limits(self):
            return {'https://example.com/api': self.public}

        def get_methods(self):
            return {'GET', 'POST'}

        def get_status_codes(self):
            return {200, 401}

    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            events.append('legacy-persist')

        async def store(self, *_args) -> None:
            return None

        async def store_run(self, run, *, legacy_results=()) -> None:
            assert run.completed_at is not None
            assert any(execution.name == 'action:takeover' for execution in run.executions)
            events.extend('legacy-persist' for _result in legacy_results)
            events.append('persist')
            persisted.append(run)

    class FailOnDefaultDnsResolution:
        def __init__(self, *_args, **_kwargs) -> None:
            raise AssertionError('DNS resolution must require --dns-resolve')

    real_formatter = main_module.format_run_terminal

    def format_after_actions(run, *, configuration=()):
        assert events[-1] == 'persist'
        events.append('report')
        return real_formatter(run, configuration=configuration)

    report = tmp_path / 'completed-run'
    wordlist = tmp_path / 'api-words.txt'
    wordlist.write_text('/api\n')
    monkeypatch.setattr(main_module.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(main_module.takeover, 'TakeOver', FakeTakeOver)
    monkeypatch.setattr(main_module.api_endpoints, 'SearchApiEndpoints', FakeApiEndpoints)
    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(main_module.hostchecker, 'Checker', FailOnDefaultDnsResolution)
    monkeypatch.setattr(main_module, 'format_run_terminal', format_after_actions)
    monkeypatch.setattr(
        main_module.sys,
        'argv',
        [
            'theHarvester',
            '-d',
            'Example.COM.',
            '-b',
            'crtsh',
            '-t',
            '-a',
            '-w',
            str(wordlist),
            '-f',
            str(report),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        await main_module.start()

    assert exit_info.value.code == 0
    assert events == [
        'source',
        'takeover',
        'api-scan',
        'legacy-persist',
        'legacy-persist',
        'persist',
        'report',
    ]
    assert persisted[0].source_executions[0].observation_count == 2
    assert persisted[0].source_executions[0].entity_count == 2
    result_records = {(record.type, record.value) for record in persisted[0].results}
    assert {
        ('subdomain', 'api.example.com'),
        ('scope-extension', 'outside.example.net'),
        ('api-endpoint', 'https://example.com/api'),
        ('api-endpoint', 'https://example.com/private'),
        ('api-auth-required', 'https://example.com/private'),
        ('api-version', 'v1'),
        ('api-rate-limited', 'https://example.com/api'),
        ('http-method', 'GET'),
        ('http-method', 'POST'),
        ('http-status', '200'),
        ('http-status', '401'),
    } <= result_records
    records_by_value = {record.value: record for record in persisted[0].results}
    assert records_by_value['api.example.com'].sources == ('crtsh',)
    assert records_by_value['https://example.com/private'].sources == ('api-scan',)
    assert json.loads((tmp_path / 'completed-run.json').read_text())['run']['status'] == 'complete'
    jsonl_records = {
        (record['type'], record.get('value'))
        for record in map(json.loads, (tmp_path / 'completed-run.jsonl').read_text().splitlines())
        if record['type'] != 'summary'
    }
    assert result_records == jsonl_records
    assert '<run status="complete" target="example.com">' in (tmp_path / 'completed-run.xml').read_text()

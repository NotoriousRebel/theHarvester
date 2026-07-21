import sys

import pytest


class DummyStashManager:
    async def do_init(self) -> None:
        return None

    async def store_all(self, _domain: str, _results: object, _result_type: str, _source: str) -> None:
        return None


class DummyNetlas:
    process_calls = 0

    def __init__(self, _domain: str, _limit: int) -> None:
        pass

    async def process(self, _proxy: bool = False) -> None:
        type(self).process_calls += 1

    async def get_hostnames(self) -> set[str]:
        return {'api.example.com'}


class DummySecurityScorecard:
    process_calls = 0

    def __init__(self, _domain: str) -> None:
        pass

    async def process(self, _proxy: bool = False) -> None:
        type(self).process_calls += 1

    async def get_hostnames(self) -> set[str]:
        return {'api.example.com'}

    async def get_ips(self) -> set[str]:
        return {'192.0.2.1'}


class DummyBuiltWith:
    process_calls = 0

    def __init__(self, _domain: str) -> None:
        pass

    async def process(self, _proxy: bool = False) -> None:
        type(self).process_calls += 1

    async def get_hostnames(self) -> set[str]:
        return {'api.example.com'}

    async def get_interestingurls(self) -> set[str]:
        return {'https://api.example.com/path'}


class DummyHackerTarget:
    process_calls = 0

    def __init__(self, _domain: str) -> None:
        pass

    async def process(self, _proxy: bool = False) -> None:
        type(self).process_calls += 1

    async def get_hostnames(self) -> set[str]:
        return {'api.example.com'}

    async def get_ips(self) -> set[str]:
        return {'192.0.2.10'}


@pytest.mark.parametrize(
    ('source', 'module_name', 'class_name', 'search_class', 'expected_results'),
    [
        (
            'builtwith',
            'builtwith',
            'SearchBuiltWith',
            DummyBuiltWith,
            ('api.example.com', 'https://api.example.com/path'),
        ),
        ('netlas', 'netlas', 'SearchNetlas', DummyNetlas, ('api.example.com',)),
        (
            'securityscorecard',
            'securityscorecard',
            'SearchSecurityScorecard',
            DummySecurityScorecard,
            ('api.example.com', '192.0.2.1'),
        ),
        (
            'hackertarget',
            'hackertarget',
            'SearchHackerTarget',
            DummyHackerTarget,
            ('api.example.com', '192.0.2.10'),
        ),
    ],
)
@pytest.mark.asyncio
async def test_cli_requests_only_results_exposed_by_source(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    source: str,
    module_name: str,
    class_name: str,
    search_class: type,
    expected_results: tuple[str, ...],
) -> None:
    import theHarvester.__main__ as main_module

    search_class.process_calls = 0
    monkeypatch.setattr(main_module.stash, 'StashManager', DummyStashManager)
    monkeypatch.setattr(getattr(main_module, module_name), class_name, search_class)
    monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', source])

    with pytest.raises(SystemExit) as excinfo:
        await main_module.start()

    assert excinfo.value.code == 0
    output = capsys.readouterr().out
    assert 'AttributeError' not in output
    assert all(result in output for result in expected_results)
    assert search_class.process_calls == 1

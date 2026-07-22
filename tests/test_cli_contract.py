from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from importlib.metadata import distribution
from pathlib import Path
from typing import Any

import pytest

from theHarvester import __main__ as harvester_main
from theHarvester.lib.core import Core


@pytest.mark.parametrize(
    ('script', 'target', 'flags'),
    [
        (
            'theHarvester',
            'theHarvester.theHarvester:main',
            ('--domain', '--source', '--filename', '--quiet'),
        ),
        (
            'restfulHarvest',
            'theHarvester.restfulHarvest:main',
            ('--host', '--port', '--rate-limit'),
        ),
    ],
)
def test_console_script_help_contract(script: str, target: str, flags: tuple[str, ...]) -> None:
    scripts = {
        entry_point.name: entry_point.value
        for entry_point in distribution('theHarvester').entry_points
        if entry_point.group == 'console_scripts'
    }
    module, function = target.split(':')
    result = subprocess.run(
        [sys.executable, '-c', f'from {module} import {function}; {function}()', '--help'],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert scripts[script] == target
    for flag in flags:
        assert flag in result.stdout


class FakeStashManager:
    async def do_init(self) -> None:
        return None

    async def store_all(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def store(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class FakeSearch:
    source = ''
    processed: list[str] = []

    def __init__(self, word: str, *_args: Any) -> None:
        self.word = word

    async def process(self, _proxy: bool) -> None:
        self.processed.append(self.source)

    async def get_hostnames(self) -> set[str]:
        return {f'{self.source}.{self.word}'}

    async def get_emails(self) -> set[str]:
        return {f'analyst@{self.word}'} if self.source == 'baidu' else set()


class FakeBaiduSearch(FakeSearch):
    source = 'baidu'


class FakeCrtshSearch(FakeSearch):
    source = 'crtsh'


@pytest.mark.asyncio
async def test_all_runs_through_parser_providers_and_reports(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report_base = tmp_path / 'all-sources'
    FakeSearch.processed = []
    monkeypatch.setattr(Core, 'get_supportedengines', staticmethod(lambda: ['baidu', 'crtsh']))
    monkeypatch.setattr(harvester_main.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(harvester_main.baidusearch, 'SearchBaidu', FakeBaiduSearch)
    monkeypatch.setattr(harvester_main.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'all', '-f', str(report_base)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await harvester_main.start()

    assert exit_info.value.code == 0
    assert set(FakeSearch.processed) == {'baidu', 'crtsh'}
    output = capsys.readouterr().out
    assert '[*] Target: example.com' in output
    assert '[*] Searching Baidu.' in output
    assert '[*] Searching CRTsh.' in output
    assert '[*] XML File saved.' in output
    assert '[*] JSON File saved.' in output

    xml_report = report_base.with_suffix('.xml')
    json_report = report_base.with_suffix('.json')
    xml_root = ElementTree.parse(xml_report).getroot()
    assert {element.text for element in xml_root.findall('host')} == {
        'baidu.example.com',
        'crtsh.example.com',
    }
    assert [element.text for element in xml_root.findall('email')] == ['analyst@example.com']

    report = json.loads(json_report.read_text(encoding='utf-8'))
    assert set(report['hosts']) == {'baidu.example.com', 'crtsh.example.com'}
    assert report['emails'] == ['analyst@example.com']
    assert report['shodan'] == []

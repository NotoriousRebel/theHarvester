import pytest

from theHarvester import __main__ as theharvester_main


@pytest.mark.parametrize(
    ('target', 'expected'),
    [('Example.COM.', {'api.example.com'}), ('WWW.Example.COM.', set())],
)
def test_normalize_hosts_for_storage_uses_the_parser_scope(target: str, expected: set[str]) -> None:
    discovered_hosts: set[object] = {
        'API.Example.COM.',
        'example.com',
        'badexample.com',
        'example.com.attacker.test',
        123,
    }

    assert theharvester_main._normalize_hosts_for_storage(discovered_hosts, target) == expected


@pytest.mark.asyncio
async def test_source_help_lists_shodanct(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(theharvester_main.sys, 'argv', ['theHarvester', '--help'])

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert 'shodanct' in capsys.readouterr().out

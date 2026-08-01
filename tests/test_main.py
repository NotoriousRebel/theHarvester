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

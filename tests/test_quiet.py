import argparse

import pytest

import theHarvester.__main__ as main_module
from theHarvester.discovery.constants import MissingKey


class FakeStashManager:
    async def do_init(self) -> None:
        return None


@pytest.mark.parametrize(
    ('provider_module', 'class_name', 'source'),
    [
        (main_module.bevigil, 'SearchBeVigil', 'bevigil'),
        (main_module.bitbucket, 'SearchBitBucket', 'bitbucket'),
        (main_module.builtwith, 'SearchBuiltWith', 'builtwith'),
    ],
)
@pytest.mark.asyncio
async def test_quiet_suppresses_missing_key_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], provider_module, class_name: str, source: str
) -> None:
    def missing_key(*_args, **_kwargs):
        raise MissingKey(source)

    monkeypatch.setattr(main_module.stash, 'StashManager', FakeStashManager)
    monkeypatch.setattr(provider_module, class_name, missing_key)

    await main_module.start(
        argparse.Namespace(
            api_scan=False,
            dns_brute=False,
            dns_lookup=False,
            dns_resolve='',
            dns_server=None,
            domain='example.com',
            filename='',
            limit=5,
            proxies=False,
            quiet=True,
            shodan=False,
            source=source,
            start=0,
            take_over=False,
            wordlist='',
        )
    )

    assert 'Missing API key' not in capsys.readouterr().out

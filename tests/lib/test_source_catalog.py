from __future__ import annotations

import ast
import importlib
from argparse import Namespace
from pathlib import Path

import pytest

from theHarvester.lib.core import Core
from theHarvester.lib.source_catalog import (
    ACTION_ACTIVITIES,
    SOURCE_CATALOG,
    ActivityClass,
    SourceSchedule,
    canonical_source_names,
    describe_activity,
    resolve_sources,
)


def _scheduled_source_names() -> list[str]:
    tree = ast.parse(Path('theHarvester/__main__.py').read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
            continue
        if not isinstance(node.left, ast.Name) or node.left.id != 'engineitem' or len(node.comparators) != 1:
            continue
        comparator = node.comparators[0]
        if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
            names.append(comparator.value)
    return names


def _engine_branches() -> dict[str, list[ast.stmt]]:
    tree = ast.parse(Path('theHarvester/__main__.py').read_text())
    branches: dict[str, list[ast.stmt]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        test = node.test
        if (
            isinstance(test.left, ast.Name)
            and test.left.id == 'engineitem'
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
            and isinstance(test.comparators[0].value, str)
        ):
            branches[test.comparators[0].value] = node.body
    return branches


def _calls(statements: list[ast.stmt]) -> list[ast.Call]:
    module = ast.Module(body=statements, type_ignores=[])
    return [node for node in ast.walk(module) if isinstance(node, ast.Call)]


def test_catalog_matches_runnable_scheduler_once() -> None:
    scheduled = _scheduled_source_names()

    assert len(scheduled) == len(set(scheduled))
    assert set(scheduled) == set(canonical_source_names())
    assert {'linkedin', 'linkedin_links', 'netcraft', 'omnisint', 'sublist3r', 'zoomeyeapi'}.isdisjoint(canonical_source_names())


def test_every_catalog_adapter_is_importable() -> None:
    assert len({(source.adapter_module, source.adapter_class) for source in SOURCE_CATALOG}) == len(SOURCE_CATALOG)
    for source in SOURCE_CATALOG:
        module = importlib.import_module(f'theHarvester.discovery.{source.adapter_module}')
        assert isinstance(getattr(module, source.adapter_class), type), source.name
        assert source.family
        assert source.capabilities
        assert source.pagination
        assert source.recursion


def test_catalog_recursion_matches_explicit_descendant_queries() -> None:
    expected = {
        'bevigil',
        'brave',
        'bufferoverun',
        'certspotter',
        'chaos',
        'commoncrawl',
        'criminalip',
        'crtsh',
        'dnsdumpster',
        'fofa',
        'fullhunt',
        'hackertarget',
        'hunterhow',
        'leakix',
        'netlas',
        'otx',
        'pentesttools',
        'projectdiscovery',
        'rapiddns',
        'robtex',
        'securitytrails',
        'subdomaincenter',
        'subdomainfinderc99',
        'thc',
        'threatcrowd',
        'urlscan',
        'virustotal',
        'waybackarchive',
        'whoisxml',
        'windvane',
        'zoomeye',
    }

    assert {source.name for source in SOURCE_CATALOG if source.recursion == 'provider-descendants'} == expected
    assert {source.recursion for source in SOURCE_CATALOG} <= {'none', 'provider-descendants'}


def test_catalog_adapter_and_capabilities_match_scheduler_branches() -> None:
    branches = _engine_branches()
    capability_keywords = {
        'store_host': 'hostnames',
        'store_emails': 'emails',
        'store_ip': 'ips',
        'store_people': 'people',
        'store_links': 'people-links',
        'store_interestingurls': 'interesting-urls',
        'store_asns': 'asns',
    }

    for source in SOURCE_CATALOG:
        calls = _calls(branches[source.name])
        constructors = {
            (call.func.value.id, call.func.attr)
            for call in calls
            if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
        }
        assert (source.adapter_module, source.adapter_class) in constructors, source.name

        store_call = next(call for call in calls if isinstance(call.func, ast.Name) and call.func.id == 'store')
        scheduled_capabilities = {
            capability_keywords[keyword.arg]
            for keyword in store_call.keywords
            if keyword.arg in capability_keywords and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        }
        assert set(source.capabilities) == scheduled_capabilities, source.name


def test_catalog_adapter_constructors_do_not_execute_twice_outside_scheduler() -> None:
    calls = _calls(ast.parse(Path('theHarvester/__main__.py').read_text()).body)
    counts = {
        source.name: sum(
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and (call.func.value.id, call.func.attr) == (source.adapter_module, source.adapter_class)
            for call in calls
        )
        for source in SOURCE_CATALOG
    }
    assert counts == {source.name: 2 if source.name == 'shodan' else 1 for source in SOURCE_CATALOG}


def test_source_schedule_rejects_wrong_adapter_and_duplicates() -> None:
    plan = resolve_sources('crtsh')
    schedule = SourceSchedule(plan)
    module = importlib.import_module('theHarvester.discovery.crtsh')
    adapter = object.__new__(module.SearchCrtsh)

    with pytest.raises(TypeError, match=r'requires crtsh\.SearchCrtsh'):
        schedule.register('crtsh', object())

    schedule.register('crtsh', adapter)
    assert schedule.registrations == (('crtsh', 'crtsh', 'SearchCrtsh'),)
    with pytest.raises(ValueError, match='scheduled more than once'):
        schedule.register('crtsh', adapter)


def test_dns_and_direct_source_activity_matches_adapter_behavior() -> None:
    assert {source.name: source.activity for source in SOURCE_CATALOG if source.activity is not ActivityClass.PASSIVE} == {
        'criminalip': ActivityClass.DIRECT,
        'pentesttools': ActivityClass.DIRECT,
        'shodan': ActivityClass.DNS,
        'shodaninternetdb': ActivityClass.DNS,
        'windvane': ActivityClass.DNS,
    }


def test_aliases_canonicalize_warn_and_schedule_once() -> None:
    with pytest.warns(FutureWarning, match='securityTrails.*securitytrails'):
        plan = resolve_sources(['securityTrails', 'securitytrails'])

    assert plan.names == ('securitytrails',)


def test_all_selects_only_passive_sources_and_reports_active_exclusions() -> None:
    plan = resolve_sources('all')

    assert plan.sources
    assert {source.activity for source in plan.sources} == {ActivityClass.PASSIVE}
    assert plan.excluded_names == ('criminalip', 'pentesttools', 'shodan', 'shodaninternetdb', 'windvane')
    assert plan.exclusion_notice == (
        "'all' excludes active provider sources: criminalip, pentesttools, shodan, shodaninternetdb, windvane; "
        "select them explicitly with '-b criminalip,pentesttools,shodan,shodaninternetdb,windvane'."
    )


def test_activity_summary_combines_sources_and_existing_action_options() -> None:
    plan = resolve_sources(['crtsh', 'pentesttools'])

    assert describe_activity(plan, actions=('dns-resolve', 'take-over', 'screenshot')) == (
        'Activity: P0 passive=1 source; P1 DNS=enabled; P2 direct=1 source (pentesttools) + take-over, screenshot.'
    )

    assert describe_activity(resolve_sources(()), actions=('shodan',)) == (
        'Activity: P0 passive=shodan; P1 DNS=disabled; P2 direct=disabled.'
    )


def test_cli_help_and_availability_share_canonical_names() -> None:
    from theHarvester import __main__

    source_action = next(action for action in __main__.build_parser()._actions if action.dest == 'source')
    assert source_action.help == ', '.join(canonical_source_names())
    assert tuple(Core.get_supportedengines()) == canonical_source_names()
    assert 'securityTrails' not in source_action.help
    assert 'shodanInternetDB' not in source_action.help


def test_existing_action_options_have_one_activity_class() -> None:
    assert ACTION_ACTIVITIES == {
        'dns-brute': ActivityClass.DNS,
        'dns-lookup': ActivityClass.DNS,
        'dns-recursive': ActivityClass.DNS,
        'dns-resolve': ActivityClass.DNS,
        'shodan': ActivityClass.PASSIVE,
        'api-scan': ActivityClass.DIRECT,
        'screenshot': ActivityClass.DIRECT,
        'take-over': ActivityClass.DIRECT,
    }


@pytest.mark.asyncio
async def test_rest_query_canonicalizes_aliases_before_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    from theHarvester.lib.api import api

    captured_source = ''

    async def fake_start(args, *, return_evidence_run: bool = False):
        nonlocal captured_source
        assert return_evidence_run is True
        captured_source = args.source
        return ([], [], [], [], [], [], [], [], [], None)

    monkeypatch.setattr(api.__main__, 'start', fake_start)

    with pytest.warns(FutureWarning, match='securityTrails.*securitytrails'):
        response = await api.query.__wrapped__(None, ['securityTrails', 'securitytrails'], 'example.com')

    assert response.status_code == 200
    assert captured_source == 'securitytrails'


@pytest.mark.asyncio
async def test_rest_all_preserves_passive_selection_notice(monkeypatch: pytest.MonkeyPatch) -> None:
    from theHarvester.lib.api import api

    captured_source = ''

    async def fake_start(args, *, return_evidence_run: bool = False):
        nonlocal captured_source
        assert return_evidence_run is True
        captured_source = args.source
        return ([], [], [], [], [], [], [], [], [], None)

    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = await api.query.__wrapped__(None, ['all'], 'example.com')

    assert response.status_code == 200
    assert captured_source == 'all'


@pytest.mark.asyncio
async def test_cli_and_rest_resolve_equivalent_activity_options(monkeypatch: pytest.MonkeyPatch) -> None:
    from theHarvester import __main__
    from theHarvester.lib.api import api

    captured_args = Namespace()

    async def fake_start(args, *, return_evidence_run: bool = False):
        nonlocal captured_args
        assert return_evidence_run is True
        captured_args = args
        return ([], [], [], [], [], [], [], [], [], None)

    monkeypatch.setattr(api.__main__, 'start', fake_start)
    await api.query.__wrapped__(
        None,
        ['all'],
        'example.com',
        dns_resolve='1.1.1.1',
        shodan=True,
        take_over=True,
    )
    cli_args = __main__.build_parser().parse_args(
        ['-d', 'example.com', '-b', 'all', '--dns-resolve', '1.1.1.1', '--shodan', '--take-over']
    )

    assert __main__.selected_actions(captured_args) == __main__.selected_actions(cli_args)
    assert captured_args.source == cli_args.source == 'all'

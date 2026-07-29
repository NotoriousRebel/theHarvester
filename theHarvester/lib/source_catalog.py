from __future__ import annotations

import warnings
from dataclasses import dataclass
from enum import StrEnum
from importlib import import_module
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterable


class ActivityClass(StrEnum):
    PASSIVE = 'P0'
    DNS = 'P1'
    DIRECT = 'P2'


ACTION_ACTIVITIES: Final = {
    'dns-brute': ActivityClass.DNS,
    'dns-lookup': ActivityClass.DNS,
    'dns-recursive': ActivityClass.DNS,
    'dns-resolve': ActivityClass.DNS,
    'shodan': ActivityClass.PASSIVE,
    'api-scan': ActivityClass.DIRECT,
    'screenshot': ActivityClass.DIRECT,
    'take-over': ActivityClass.DIRECT,
}


@dataclass(frozen=True, slots=True)
class SourceSpec:
    name: str
    adapter_module: str
    adapter_class: str
    family: str
    credentials: tuple[str, ...]
    capabilities: tuple[str, ...]
    activity: ActivityClass = ActivityClass.PASSIVE
    pagination: str = 'adapter-managed'
    # Provider descendants are requested by the adapter itself; active DNS recursion is a separate P1 action.
    recursion: str = 'none'
    declared_limits: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SourcePlan:
    sources: tuple[SourceSpec, ...]
    excluded: tuple[SourceSpec, ...] = ()

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(source.name for source in self.sources)

    @property
    def excluded_names(self) -> tuple[str, ...]:
        return tuple(source.name for source in self.excluded)

    @property
    def exclusion_notice(self) -> str:
        if not self.excluded:
            return ''
        names = ', '.join(self.excluded_names)
        selection = ','.join(self.excluded_names)
        return f"'all' excludes active provider sources: {names}; select them explicitly with '-b {selection}'."


def _source(
    name: str,
    adapter_module: str,
    adapter_class: str,
    *,
    family: str,
    credentials: tuple[str, ...] = (),
    capabilities: tuple[str, ...] = ('hostnames',),
    activity: ActivityClass = ActivityClass.PASSIVE,
    pagination: str = 'adapter-managed',
    recursion: str = 'none',
    limits: tuple[str, ...] = (),
    aliases: tuple[str, ...] = (),
) -> SourceSpec:
    return SourceSpec(
        name=name,
        adapter_module=adapter_module,
        adapter_class=adapter_class,
        family=family,
        credentials=credentials,
        capabilities=capabilities,
        activity=activity,
        pagination=pagination,
        recursion=recursion,
        declared_limits=limits,
        aliases=aliases,
    )


class SourceSchedule:
    def __init__(self, plan: SourcePlan) -> None:
        self._selected = {source.name: source for source in plan.sources}
        self._registrations: dict[str, tuple[str, str]] = {}

    @property
    def registrations(self) -> tuple[tuple[str, str, str], ...]:
        return tuple((name, *adapter) for name, adapter in sorted(self._registrations.items()))

    def register(self, name: str, adapter: object) -> None:
        source = _BY_NAME.get(name.casefold())
        if source is None or source.name not in self._selected:
            raise ValueError(f"Source '{name}' is not in the execution plan")
        if source.name in self._registrations:
            raise ValueError(f"Source '{source.name}' was scheduled more than once")
        adapter_type = getattr(import_module(f'theHarvester.discovery.{source.adapter_module}'), source.adapter_class)
        if not isinstance(adapter, adapter_type):
            actual = (adapter.__class__.__module__.rsplit('.', 1)[-1], adapter.__class__.__name__)
            raise TypeError(
                f"Source '{source.name}' requires {source.adapter_module}.{source.adapter_class}, got {actual[0]}.{actual[1]}"
            )
        self._registrations[source.name] = (source.adapter_module, source.adapter_class)


_LIMIT: Final = ('operator-result-limit',)

SOURCE_CATALOG: Final[tuple[SourceSpec, ...]] = (
    _source('baidu', 'baidusearch', 'SearchBaidu', family='web-search', capabilities=('hostnames', 'emails'), limits=_LIMIT),
    _source(
        'bevigil',
        'bevigil',
        'SearchBeVigil',
        family='bevigil',
        credentials=('api-key',),
        capabilities=('hostnames', 'interesting-urls'),
        recursion='provider-descendants',
    ),
    _source(
        'bitbucket',
        'bitbucket',
        'SearchBitBucket',
        family='source-code',
        credentials=('api-key',),
        capabilities=('hostnames', 'emails'),
        limits=_LIMIT,
    ),
    _source(
        'brave',
        'bravesearch',
        'SearchBrave',
        family='web-search',
        credentials=('api-key',),
        capabilities=('hostnames', 'emails'),
        recursion='provider-descendants',
        limits=_LIMIT,
    ),
    _source(
        'bufferoverun',
        'bufferoverun',
        'SearchBufferover',
        family='passive-dns',
        credentials=('api-key',),
        capabilities=('hostnames', 'ips'),
        recursion='provider-descendants',
    ),
    _source(
        'builtwith',
        'builtwith',
        'SearchBuiltWith',
        family='builtwith',
        credentials=('api-key',),
        capabilities=('hostnames', 'interesting-urls'),
    ),
    _source(
        'censys',
        'censysearch',
        'SearchCensys',
        family='censys',
        credentials=('api-id', 'api-secret'),
        capabilities=('hostnames', 'emails'),
        limits=_LIMIT,
    ),
    _source(
        'certspotter',
        'certspottersearch',
        'SearchCertspoter',
        family='certificate-transparency',
        pagination='cursor-until-exhausted',
        recursion='provider-descendants',
        limits=('maximum-pages-1000',),
    ),
    _source(
        'chaos', 'chaos', 'SearchChaos', family='projectdiscovery', credentials=('api-key',), recursion='provider-descendants'
    ),
    _source(
        'commoncrawl',
        'commoncrawl',
        'SearchCommoncrawl',
        family='web-archive',
        pagination='all-current-indexes',
        recursion='provider-descendants',
    ),
    _source(
        'criminalip',
        'criminalip',
        'SearchCriminalIP',
        family='criminalip',
        credentials=('api-key',),
        capabilities=('hostnames', 'ips', 'asns'),
        activity=ActivityClass.DIRECT,
        recursion='provider-descendants',
    ),
    _source(
        'crtsh',
        'crtsh',
        'SearchCrtsh',
        family='certificate-transparency',
        recursion='provider-descendants',
    ),
    _source(
        'dehashed', 'search_dehashed', 'SearchDehashed', family='breach-data', credentials=('api-key',), capabilities=('ips',)
    ),
    _source(
        'dnsdumpster',
        'search_dnsdumpster',
        'SearchDNSDumpster',
        family='dnsdumpster',
        credentials=('api-key',),
        capabilities=('hostnames', 'ips'),
        recursion='provider-descendants',
    ),
    _source(
        'duckduckgo',
        'duckduckgosearch',
        'SearchDuckDuckGo',
        family='web-search',
        capabilities=('hostnames', 'emails'),
        limits=_LIMIT,
    ),
    _source('dymo', 'dymosearch', 'SearchDymo', family='dymo', credentials=('api-key',)),
    _source(
        'fofa',
        'fofa',
        'SearchFofa',
        family='fofa',
        credentials=('api-key', 'account-email'),
        capabilities=('hostnames', 'ips'),
        recursion='provider-descendants',
    ),
    _source(
        'fullhunt',
        'fullhuntsearch',
        'SearchFullHunt',
        family='fullhunt',
        credentials=('api-key',),
        recursion='provider-descendants',
    ),
    _source(
        'github-code',
        'githubcode',
        'SearchGithubCode',
        family='source-code',
        credentials=('api-key',),
        capabilities=('hostnames', 'emails'),
        limits=_LIMIT,
    ),
    _source('gitlab', 'gitlabsearch', 'SearchGitlab', family='source-code', capabilities=('hostnames', 'emails')),
    _source(
        'hackertarget',
        'hackertarget',
        'SearchHackerTarget',
        family='hackertarget',
        credentials=('api-key',),
        capabilities=('hostnames',),
        recursion='provider-descendants',
    ),
    _source(
        'haveibeenpwned',
        'haveibeenpwned',
        'SearchHaveIBeenPwned',
        family='breach-data',
        credentials=('api-key',),
        capabilities=('emails',),
    ),
    _source(
        'hudsonrock',
        'hudsonrocksearch',
        'SearchHudsonRock',
        family='breach-data',
        capabilities=('hostnames', 'emails', 'ips'),
    ),
    _source(
        'hunter',
        'huntersearch',
        'SearchHunter',
        family='hunter',
        credentials=('api-key',),
        capabilities=('hostnames', 'emails'),
        limits=_LIMIT,
    ),
    _source(
        'hunterhow',
        'searchhunterhow',
        'SearchHunterHow',
        family='hunterhow',
        credentials=('api-key',),
        recursion='provider-descendants',
    ),
    _source(
        'intelx',
        'intelxsearch',
        'SearchIntelx',
        family='intelx',
        credentials=('api-key',),
        capabilities=('emails', 'interesting-urls'),
    ),
    _source(
        'leakix',
        'leakix',
        'SearchLeakix',
        family='leakix',
        credentials=('api-key',),
        capabilities=('hostnames', 'emails'),
        recursion='provider-descendants',
    ),
    _source(
        'leaklookup',
        'leaklookup',
        'SearchLeakLookup',
        family='breach-data',
        credentials=('api-key',),
        capabilities=('emails',),
    ),
    _source(
        'mojeek',
        'mojeek',
        'SearchMojeek',
        family='web-search',
        credentials=('api-key',),
        capabilities=('hostnames', 'emails'),
        limits=_LIMIT,
    ),
    _source(
        'netlas',
        'netlas',
        'SearchNetlas',
        family='netlas',
        credentials=('api-key',),
        capabilities=('hostnames', 'ips'),
        recursion='provider-descendants',
        limits=_LIMIT,
    ),
    _source(
        'onyphe',
        'onyphe',
        'SearchOnyphe',
        family='onyphe',
        credentials=('api-key',),
        capabilities=('hostnames', 'ips', 'asns'),
    ),
    _source(
        'otx',
        'otxsearch',
        'SearchOtx',
        family='alienvault-otx',
        capabilities=('hostnames', 'ips'),
        recursion='provider-descendants',
    ),
    _source(
        'pentesttools',
        'pentesttools',
        'SearchPentestTools',
        family='pentesttools',
        credentials=('api-key',),
        activity=ActivityClass.DIRECT,
        recursion='provider-descendants',
        limits=('provider-scan-budget',),
    ),
    _source(
        'projectdiscovery',
        'projectdiscovery',
        'SearchDiscovery',
        family='projectdiscovery',
        credentials=('api-key',),
        recursion='provider-descendants',
    ),
    _source(
        'rapiddns',
        'rapiddns',
        'SearchRapidDns',
        family='rapiddns',
        recursion='provider-descendants',
    ),
    _source(
        'robtex',
        'robtex',
        'SearchRobtex',
        family='robtex',
        capabilities=('hostnames', 'ips'),
        recursion='provider-descendants',
    ),
    _source(
        'rocketreach',
        'rocketreach',
        'SearchRocketReach',
        family='rocketreach',
        credentials=('api-key',),
        capabilities=('emails', 'people-links'),
        limits=_LIMIT,
    ),
    _source(
        'securityscorecard',
        'securityscorecard',
        'SearchSecurityScorecard',
        family='securityscorecard',
        credentials=('api-key',),
        capabilities=('hostnames', 'ips', 'interesting-urls', 'asns'),
    ),
    _source(
        'securitytrails',
        'securitytrailssearch',
        'SearchSecuritytrail',
        family='securitytrails',
        credentials=('api-key',),
        capabilities=('hostnames', 'ips'),
        recursion='provider-descendants',
        aliases=('securityTrails',),
    ),
    _source(
        'sherlockeye',
        'sherlockeye',
        'SearchSherlockeye',
        family='sherlockeye',
        credentials=('api-key',),
        capabilities=('hostnames', 'emails', 'ips'),
    ),
    _source('shodan', 'shodansearch', 'SearchShodan', family='shodan', credentials=('api-key',), activity=ActivityClass.DNS),
    _source(
        'shodaninternetdb',
        'shodan_internetdb',
        'SearchShodanInternetDB',
        family='shodan',
        capabilities=('hostnames', 'ips'),
        activity=ActivityClass.DNS,
        aliases=('shodanInternetDB',),
    ),
    _source(
        'subdomaincenter',
        'subdomaincenter',
        'SubdomainCenter',
        family='subdomaincenter',
        recursion='provider-descendants',
    ),
    _source(
        'subdomainfinderc99',
        'subdomainfinderc99',
        'SearchSubdomainfinderc99',
        family='subdomainfinderc99',
        recursion='provider-descendants',
    ),
    _source(
        'thc',
        'thc',
        'SearchThc',
        family='thc',
        recursion='provider-descendants',
        limits=('provider-result-limit-10000',),
    ),
    _source(
        'threatcrowd',
        'threatcrowd',
        'SearchThreatcrowd',
        family='threatcrowd',
        capabilities=('hostnames', 'ips'),
        recursion='provider-descendants',
    ),
    _source(
        'tomba',
        'tombasearch',
        'SearchTomba',
        family='tomba',
        credentials=('api-key', 'api-secret'),
        capabilities=('hostnames', 'emails'),
        limits=_LIMIT,
    ),
    _source(
        'urlscan',
        'urlscan',
        'SearchUrlscan',
        family='urlscan',
        capabilities=('hostnames', 'ips', 'interesting-urls', 'asns'),
        recursion='provider-descendants',
    ),
    _source(
        'venacus',
        'venacussearch',
        'SearchVenacus',
        family='venacus',
        credentials=('api-key',),
        capabilities=('emails', 'ips', 'people', 'interesting-urls'),
        limits=_LIMIT,
    ),
    _source(
        'virustotal',
        'virustotal',
        'SearchVirustotal',
        family='virustotal',
        credentials=('api-key',),
        recursion='provider-descendants',
    ),
    _source(
        'waybackarchive',
        'waybackarchive',
        'SearchWaybackarchive',
        family='web-archive',
        pagination='resume-key-until-exhausted',
        recursion='provider-descendants',
        limits=('page-size-1000', 'maximum-pages-per-query-1000'),
    ),
    _source(
        'whoisxml',
        'whoisxml',
        'SearchWhoisXML',
        family='whoisxml',
        credentials=('api-key',),
        recursion='provider-descendants',
    ),
    _source(
        'windvane',
        'windvane',
        'SearchWindvane',
        family='windvane',
        credentials=('api-key',),
        capabilities=('hostnames', 'emails', 'ips'),
        activity=ActivityClass.DNS,
        recursion='provider-descendants',
        limits=('dns-fallback-labels-20',),
    ),
    _source('yahoo', 'yahoosearch', 'SearchYahoo', family='web-search', capabilities=('hostnames', 'emails'), limits=_LIMIT),
    _source(
        'zoomeye',
        'zoomeyesearch',
        'SearchZoomEye',
        family='zoomeye',
        credentials=('api-key',),
        capabilities=('hostnames', 'emails', 'ips', 'interesting-urls', 'asns'),
        recursion='provider-descendants',
        limits=_LIMIT,
    ),
)

_BY_NAME: Final = {source.name: source for source in SOURCE_CATALOG}
_BY_ALIAS: Final = {alias: source for source in SOURCE_CATALOG for alias in source.aliases}
_BY_CASEFOLD: Final = {source.name.casefold(): source for source in SOURCE_CATALOG}


def canonical_source_names() -> tuple[str, ...]:
    return tuple(sorted(_BY_NAME))


def _tokens(selection: str | Iterable[str]) -> list[str]:
    values = [selection] if isinstance(selection, str) else selection
    return [token.strip() for value in values for token in value.split(',') if token.strip()]


def resolve_sources(selection: str | Iterable[str]) -> SourcePlan:
    requested = _tokens(selection)
    if len(requested) == 1 and requested[0].casefold() == 'all':
        passive = tuple(
            sorted(
                (source for source in SOURCE_CATALOG if source.activity is ActivityClass.PASSIVE), key=lambda source: source.name
            )
        )
        excluded = tuple(
            sorted(
                (source for source in SOURCE_CATALOG if source.activity is not ActivityClass.PASSIVE),
                key=lambda source: source.name,
            )
        )
        return SourcePlan(passive, excluded)

    resolved: dict[str, SourceSpec] = {}
    unsupported: list[str] = []
    for name in requested:
        source = _BY_NAME.get(name)
        if source is None and name in _BY_ALIAS:
            source = _BY_ALIAS[name]
            warnings.warn(
                f"Source alias '{name}' is deprecated; use '{source.name}'.",
                FutureWarning,
                stacklevel=2,
            )
        if source is None:
            source = _BY_CASEFOLD.get(name.casefold())
        if source is None:
            unsupported.append(name)
        else:
            resolved[source.name] = source

    if unsupported:
        raise ValueError(f'Unsupported sources: {", ".join(sorted(unsupported))}')
    return SourcePlan(tuple(resolved[name] for name in sorted(resolved)))


def describe_activity(
    plan: SourcePlan,
    *,
    actions: Iterable[str] = (),
) -> str:
    selected_actions = tuple(actions)
    unknown = set(selected_actions) - set(ACTION_ACTIVITIES)
    if unknown:
        raise ValueError(f'Unclassified actions: {", ".join(sorted(unknown))}')
    passive_count = sum(source.activity is ActivityClass.PASSIVE for source in plan.sources)
    passive_actions = tuple(action for action in selected_actions if ACTION_ACTIVITIES[action] is ActivityClass.PASSIVE)
    passive_parts: list[str] = []
    if passive_count:
        noun = 'source' if passive_count == 1 else 'sources'
        passive_parts.append(f'{passive_count} {noun}')
    if passive_actions:
        passive_parts.append(', '.join(passive_actions))
    passive = ' + '.join(passive_parts) if passive_parts else 'disabled'
    dns = any(source.activity is ActivityClass.DNS for source in plan.sources) or any(
        ACTION_ACTIVITIES[action] is ActivityClass.DNS for action in selected_actions
    )
    direct_sources = tuple(source.name for source in plan.sources if source.activity is ActivityClass.DIRECT)
    direct_actions = tuple(action for action in selected_actions if ACTION_ACTIVITIES[action] is ActivityClass.DIRECT)
    direct_parts: list[str] = []
    if direct_sources:
        noun = 'source' if len(direct_sources) == 1 else 'sources'
        direct_parts.append(f'{len(direct_sources)} {noun} ({", ".join(direct_sources)})')
    if direct_actions:
        direct_parts.append(', '.join(direct_actions))
    direct = ' + '.join(direct_parts) if direct_parts else 'disabled'
    return f'Activity: P0 passive={passive}; P1 DNS={"enabled" if dns else "disabled"}; P2 direct={direct}.'

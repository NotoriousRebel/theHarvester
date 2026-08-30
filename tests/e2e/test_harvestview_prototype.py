from __future__ import annotations

import os
from pathlib import Path

import pytest
from playwright.sync_api import Locator, Page, Route, expect

pytestmark = pytest.mark.harvestview_e2e


def tab_to(page: Page, locator: Locator, maximum: int = 100) -> None:
    for _ in range(maximum):
        if locator.evaluate('node => node === document.activeElement'):
            return
        page.keyboard.press('Tab')
    pytest.fail(f'Could not reach {locator} with {maximum} Tab presses')


def prototype_run() -> dict[str, object]:
    return {
        'run_id': 'prototype-run',
        'target': 'example.test',
        'status': 'completed',
        'origin': 'local',
        'created_at': '2026-08-29T13:00:00+00:00',
        'started_at': '2026-08-29T13:00:02+00:00',
        'completed_at': '2026-08-29T13:01:12+00:00',
        'cancellation_requested_at': None,
        'evidence_status': 'partial',
        'result_count': 4,
        'activities': ['P0'],
        'sources': ['crtsh', 'certspotter'],
        'request': {'sources': ['crtsh', 'certspotter'], 'limit': 500, 'deadline_seconds': 1800},
        'source_executions': [
            {'source': 'crtsh', 'status': 'completed', 'result_count': 3, 'duration_ms': 218},
            {
                'source': 'certspotter',
                'status': 'partial',
                'result_count': 1,
                'duration_ms': 920,
                'error_type': 'TimeoutError',
                'stop_reason': 'provider-timeout',
            },
        ],
        'action_executions': [],
        'results': [
            {'type': 'hostname', 'value': 'api.example.test', 'sources': ['crtsh'], 'actions': []},
            {'type': 'hostname', 'value': 'login.example.test', 'sources': ['certspotter'], 'actions': []},
            {'type': 'ip', 'value': '192.0.2.10', 'sources': ['crtsh'], 'actions': []},
            {'type': 'email', 'value': 'security@example.test', 'sources': ['crtsh'], 'actions': []},
        ],
        'screenshots': [],
        'log': '',
        'error': None,
        'hostname_tracking': {
            'target': 'example.test',
            'comparison_count': 1,
            'comparisons': [
                {
                    'run_id': 'prototype-run',
                    'completed_at': '2026-08-29T13:01:12+00:00',
                    'baseline_run_id': 'prototype-baseline',
                    'baseline_completed_at': '2026-08-28T13:01:12+00:00',
                    'source_cohort': ['crtsh', 'certspotter'],
                    'counts': {'new': 1, 'persisting': 1, 'missing': 0, 'inconclusive': 1},
                }
            ],
            'hostname_changes': [
                {
                    'change': 'new',
                    'hostname': 'api.example.test',
                    'previous_sources': [],
                    'current_sources': ['crtsh'],
                    'source_exclusive': True,
                    'previous_resolution_evidence': 'not-checked',
                    'current_resolution_evidence': 'positive',
                    'previous_addressability': None,
                    'current_addressability': 'currently-addressable',
                    'blocking_sources': [],
                },
                {
                    'change': 'inconclusive',
                    'hostname': 'login.example.test',
                    'previous_sources': [],
                    'current_sources': ['certspotter'],
                    'source_exclusive': True,
                    'previous_resolution_evidence': 'not-checked',
                    'current_resolution_evidence': 'not-retained',
                    'previous_addressability': None,
                    'current_addressability': None,
                    'blocking_sources': [
                        {
                            'source': 'certspotter',
                            'status': 'partial',
                            'error_type': 'TimeoutError',
                            'stop_reason': 'provider-timeout',
                        }
                    ],
                },
            ],
        },
    }


def prototype_schedule() -> dict[str, object]:
    return {
        'schedule_id': 'prototype-schedule',
        'name': 'Weekly external evidence',
        'targets': ['example.test', 'example.org', '192.0.2.10'],
        'run': {'sources': ['crtsh'], 'limit': 500},
        'timing': {
            'frequency': 'weekly',
            'start_at': '2026-09-01T13:00:00+00:00',
            'timezone': 'America/New_York',
            'interval': 1,
            'weekdays': [2],
        },
        'enabled': True,
        'overlap_policy': 'skip',
        'next_run_at': '2026-09-01T13:00:00+00:00',
        'last_run_at': '2026-08-25T13:00:00+00:00',
        'upcoming_occurrences': ['2026-09-01T13:00:00+00:00', '2026-09-08T13:00:00+00:00'],
        'last_error': None,
    }


def route_prototype_evidence(page: Page, base_url: str) -> None:
    run = prototype_run()
    page.route(f'{base_url}/api/v1/runs', lambda route: route.fulfill(json=[run]))
    page.route(f'{base_url}/api/v1/runs/prototype-run', lambda route: route.fulfill(json=run))
    page.route(
        f'{base_url}/api/v1/schedules?limit=500',
        lambda route: route.fulfill(json=[prototype_schedule()]),
    )


def route_edge_case_evidence(page: Page, base_url: str) -> tuple[str, str, str]:
    long_id = 'failed-provider-' + ('x' * 96)
    failed = {
        **prototype_run(),
        'run_id': long_id,
        'target': 'provider-error.example.test',
        'status': 'failed',
        'evidence_status': 'failed',
        'result_count': 0,
        'source_executions': [
            {
                'source': 'certspotter',
                'status': 'failed',
                'result_count': 0,
                'duration_ms': 310,
                'error_type': 'ProviderUnavailableError',
                'stop_reason': 'provider-unavailable',
            }
        ],
        'results': [],
        'hostname_tracking': None,
        'error': 'ProviderUnavailableError: provider did not return evidence',
    }
    zero_id = 'zero-result-run'
    zero = {
        **prototype_run(),
        'run_id': zero_id,
        'target': 'zero.example.test',
        'evidence_status': 'complete',
        'result_count': 0,
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'limit': 500},
        'source_executions': [{'source': 'crtsh', 'status': 'completed', 'result_count': 0, 'duration_ms': 125}],
        'results': [],
        'hostname_tracking': None,
    }
    thousand_id = 'thousand-result-run'
    thousand = {
        **prototype_run(),
        'run_id': thousand_id,
        'target': 'thousand.example.test',
        'evidence_status': 'complete',
        'result_count': 1000,
        'sources': ['crtsh'],
        'request': {'sources': ['crtsh'], 'limit': 0},
        'source_executions': [{'source': 'crtsh', 'status': 'completed', 'result_count': 1000, 'duration_ms': 925}],
        'results': [
            {'type': 'hostname', 'value': f'host-{index:04d}.example.test', 'sources': ['crtsh'], 'actions': []}
            for index in range(1000)
        ],
        'hostname_tracking': None,
    }
    runs = [failed, zero, thousand]
    page.route(f'{base_url}/api/v1/runs', lambda route: route.fulfill(json=runs))

    def detail_handler(detail):
        return lambda route: route.fulfill(json=detail)

    for run in runs:
        page.route(
            f'{base_url}/api/v1/runs/{run["run_id"]}',
            detail_handler(run),
        )
    return long_id, zero_id, thousand_id


def test_prototype_variants_change_structure_and_follow_existing_routes(
    harvestview_server_url: str,
    page: Page,
) -> None:
    route_prototype_evidence(page, harvestview_server_url)
    page.set_viewport_size({'width': 1440, 'height': 900})
    page.goto(f'{harvestview_server_url}/?variant=mineral')

    expect(page.locator('html')).to_have_attribute('data-prototype-variant', 'mineral')
    expect(page.locator('#prototype-variant-label')).to_have_text('Mineral Run Desk')
    assert page.locator('.app-shell').evaluate("node => getComputedStyle(node).display") == 'grid'

    page.get_by_role('button', name='Next visual territory').click()
    expect(page.locator('html')).to_have_attribute('data-prototype-variant', 'ledger')
    expect(page.locator('#prototype-variant-label')).to_have_text('Field Evidence Ledger')
    expect(page).to_have_url(f'{harvestview_server_url}/?variant=ledger')
    assert page.locator('.run-detail').evaluate("node => getComputedStyle(node).maxWidth") == '1180px'

    page.get_by_role('button', name='Next visual territory').click()
    expect(page.locator('html')).to_have_attribute('data-prototype-variant', 'signal')
    expect(page.locator('#prototype-variant-label')).to_have_text('Signal Bay')
    assert page.locator('.app-shell').evaluate("node => getComputedStyle(node).display") == 'block'
    assert page.locator('.run-list').evaluate("node => getComputedStyle(node).display") == 'flex'
    page.locator('#prototype-color-mode').select_option('dark')
    expect(page.locator('html')).to_have_attribute('data-theme', 'dark')
    page.locator('#prototype-color-mode').select_option('light')
    expect(page.locator('html')).to_have_attribute('data-theme', 'light')

    page.locator('#history-search').focus()
    page.keyboard.press('ArrowLeft')
    expect(page.locator('html')).to_have_attribute('data-prototype-variant', 'signal')

    page.get_by_role('link', name='Schedules').click()
    expect(page).to_have_url(f'{harvestview_server_url}/schedules?variant=signal')
    expect(page.locator('#prototype-variant-label')).to_have_text('Signal Bay')


def test_prototype_distills_attention_and_inactive_request_options(
    harvestview_server_url: str,
    page: Page,
) -> None:
    route_prototype_evidence(page, harvestview_server_url)
    page.goto(f'{harvestview_server_url}/?variant=mineral')

    next_action = page.locator('#prototype-next-action')
    expect(next_action).to_be_visible()
    expect(next_action).to_contain_text('certspotter')
    expect(next_action).to_contain_text('TimeoutError')
    expect(next_action).to_contain_text('before deciding whether to retry or export')

    inactive = page.locator('#prototype-inactive-options')
    expect(inactive).to_be_visible()
    expect(inactive.locator('summary')).to_contain_text('inactive or unrecorded options')
    expect(page.locator('#request-options')).not_to_contain_text('Off')
    expect(page.locator('#request-options')).not_to_contain_text('Not recorded')
    inactive.locator('summary').click()
    expect(inactive).to_contain_text('DNS resolution')
    expect(inactive).to_contain_text('Off')


def test_prototype_limits_peer_actions_and_discloses_delete(
    harvestview_server_url: str,
    page: Page,
) -> None:
    route_prototype_evidence(page, harvestview_server_url)
    page.goto(f'{harvestview_server_url}/?variant=mineral')
    assert page.locator('.header-actions > :visible').count() <= 4

    page.goto(f'{harvestview_server_url}/schedules?variant=mineral')
    assert page.locator('.header-actions > :visible').count() <= 4
    card = page.locator('.schedule-card').filter(has_text='Weekly external evidence')
    expect(card).to_be_visible()
    assert card.locator('.prototype-schedule-peer-actions > button:visible').count() == 4
    expect(card.locator('[data-action="run-now"]')).to_be_visible()

    disclosure = card.locator('.prototype-delete-disclosure')
    expect(disclosure).to_be_visible()
    expect(disclosure.locator('[data-action="delete"]')).to_be_hidden()
    disclosure.locator('summary').click()
    expect(disclosure.locator('[data-action="delete"]')).to_be_visible()

    confirmation: list[str] = []

    def dismiss_delete(dialog) -> None:
        confirmation.append(dialog.message)
        dialog.dismiss()

    page.once('dialog', dismiss_delete)
    disclosure.locator('[data-action="delete"]').click()
    assert confirmation == ['Delete “Weekly external evidence”? Existing run evidence will not be deleted.']
    expect(card).to_be_visible()


def test_prototype_terminal_edge_records_remain_actionable(
    harvestview_server_url: str,
    page: Page,
) -> None:
    long_id, _, _ = route_edge_case_evidence(page, harvestview_server_url)
    page.set_viewport_size({'width': 390, 'height': 844})
    page.goto(f'{harvestview_server_url}/?variant=mineral')

    expect(page.locator('#detail-run-id')).to_have_text(long_id)
    expect(page.locator('#prototype-next-action')).to_contain_text('ProviderUnavailableError')
    expect(page.locator('#results-summary')).to_have_text('0 normalized results.')
    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')

    page.locator('.run-item').filter(has_text='zero.example.test').click()
    expect(page.locator('#results-summary')).to_contain_text('0 normalized results')
    expect(page.locator('#provider-outcome-summary')).to_contain_text('1 zero-result')

    page.locator('.run-item').filter(has_text='thousand.example.test').click()
    expect(page.get_by_role('button', name='Hostnames 1000')).to_be_visible()
    expect(page.locator('.tabulator-row')).to_have_count(15)
    expect(page.locator('.tabulator-footer')).to_contain_text('1000')
    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')


def test_planner_supports_keyboard_only_zero_source_action_run(
    harvestview_server_url: str,
    page: Page,
    browser_failures,
) -> None:
    submissions: list[dict[str, object]] = []
    browser_failures.allow_response('POST', 503, '/api/v1/runs')
    browser_failures.allow_console_error(
        'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    )

    def route_runs(route: Route) -> None:
        if route.request.method == 'POST':
            submissions.append(route.request.post_data_json)
            route.fulfill(status=503, json={'detail': 'Prototype stops before execution.'})
        else:
            route.fulfill(json=[])

    page.route(f'{harvestview_server_url}/api/v1/runs', route_runs)
    page.goto(f'{harvestview_server_url}/?variant=mineral')
    start = page.get_by_role('button', name='Start enumeration').first
    expect(start).to_be_enabled()
    start.focus()
    page.keyboard.press('Enter')

    expect(page.locator('#run-target')).to_be_focused()
    page.keyboard.type('action-only.example.test')
    continue_sources = page.get_by_role('button', name='Continue to sources')
    tab_to(page, continue_sources)
    page.keyboard.press('Enter')

    expect(page.get_by_role('heading', name='Passive source cohort')).to_be_focused()
    expect(page.get_by_role('navigation', name='Enumeration plan progress')).to_be_visible()
    expect(page.locator('[aria-current="step"]')).to_contain_text('Sources')
    clear_sources = page.get_by_role('button', name='Clear')
    tab_to(page, clear_sources)
    page.keyboard.press('Enter')
    expect(page.locator('#source-selection-summary')).to_contain_text('Selected 0 ready sources')
    continue_activity = page.get_by_role('button', name='Continue to activity')
    tab_to(page, continue_activity)
    page.keyboard.press('Enter')

    expect(page.get_by_role('heading', name='Optional activity')).to_be_focused()
    expect(page.locator('[aria-current="step"]')).to_contain_text('Activity')
    dns_lookup = page.locator('input[name="dns_lookup"]')
    tab_to(page, dns_lookup)
    page.keyboard.press('Space')
    review = page.get_by_role('button', name='Review authorization')
    tab_to(page, review)
    page.keyboard.press('Enter')

    expect(page.get_by_role('heading', name='Final authorization review')).to_be_focused()
    expect(page.locator('[aria-current="step"]')).to_contain_text('Review')
    expect(page.locator('#final-authorization-summary')).to_contain_text('0 sources')
    expect(page.locator('#final-authorization-summary')).to_contain_text('P1 selected')
    submit = page.locator('#submit-run-button')
    tab_to(page, submit)
    page.keyboard.press('Enter')

    expect(page.locator('#new-run-error')).to_contain_text('Prototype stops before execution.')
    assert len(submissions) == 1
    assert submissions[0]['target'] == 'action-only.example.test'
    assert submissions[0]['sources'] == []
    assert submissions[0]['dns_lookup'] is True


@pytest.mark.parametrize('variant', ['mineral', 'ledger', 'signal'])
@pytest.mark.parametrize('theme', ['light', 'dark'])
def test_prototype_key_token_pairs_meet_wcag_aa(
    harvestview_server_url: str,
    page: Page,
    variant: str,
    theme: str,
) -> None:
    route_prototype_evidence(page, harvestview_server_url)
    page.goto(f'{harvestview_server_url}/?variant={variant}')
    expect(page.locator('#run-detail')).to_be_visible()
    page.locator('#prototype-color-mode').select_option(theme)

    ratios = page.evaluate(
        """
        () => {
          const canvas = document.createElement('canvas');
          canvas.width = canvas.height = 1;
          const context = canvas.getContext('2d', {willReadFrequently: true});
          const rgba = (value) => {
            context.clearRect(0, 0, 1, 1);
            context.fillStyle = value;
            context.fillRect(0, 0, 1, 1);
            return [...context.getImageData(0, 0, 1, 1).data].map(component => component / 255);
          };
          const composite = (foreground, background, opacity = foreground[3]) => [
            foreground[0] * opacity + background[0] * (1 - opacity),
            foreground[1] * opacity + background[1] * (1 - opacity),
            foreground[2] * opacity + background[2] * (1 - opacity),
            1,
          ];
          const luminance = (color) => {
            const linear = color.slice(0, 3).map(channel => channel <= 0.04045
              ? channel / 12.92
              : ((channel + 0.055) / 1.055) ** 2.4);
            return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
          };
          const ratio = (foreground, background) => {
            const lighter = Math.max(luminance(foreground), luminance(background));
            const darker = Math.min(luminance(foreground), luminance(background));
            return (lighter + 0.05) / (darker + 0.05);
          };
          const token = (name) => {
            const sample = document.createElement('span');
            sample.style.color = `var(${name})`;
            document.body.append(sample);
            const value = rgba(getComputedStyle(sample).color);
            sample.remove();
            return value;
          };
          const pair = (foreground, background) => ratio(token(foreground), token(background));
          const disabledOpacity = Number(getComputedStyle(document.querySelector('#copy-route-button')).opacity);
          const disabledBackdrop = token('--surface');
          return {
            body_text: pair('--ink', '--bg'),
            nav_text: pair('--nav-ink', '--nav'),
            success_status: pair('--success', '--success-soft'),
            warning_status: pair('--warning', '--warning-soft'),
            danger_status: pair('--danger', '--danger-soft'),
            focus_indicator: pair('--focus', '--bg'),
            disabled_text: ratio(
              composite(token('--ink'), disabledBackdrop, disabledOpacity),
              composite(token('--surface-raised'), disabledBackdrop, disabledOpacity),
            ),
          };
        }
        """
    )

    for name in ('body_text', 'nav_text', 'success_status', 'warning_status', 'danger_status', 'disabled_text'):
        assert ratios[name] >= 4.5, f'{variant}/{theme} {name} contrast was {ratios[name]:.2f}:1'
    assert ratios['focus_indicator'] >= 3.0, (
        f'{variant}/{theme} focus_indicator contrast was {ratios["focus_indicator"]:.2f}:1'
    )


@pytest.mark.parametrize(('width', 'height'), [(1440, 900), (390, 844)], ids=['desktop', 'mobile'])
def test_four_step_planner_preserves_controls_and_values(
    harvestview_server_url: str,
    page: Page,
    width: int,
    height: int,
) -> None:
    page.set_viewport_size({'width': width, 'height': height})
    page.goto(f'{harvestview_server_url}/?variant=mineral')
    page.get_by_role('button', name='Start enumeration').first.click()
    dialog = page.locator('#new-run-dialog')

    expect(dialog.locator('[data-prototype-step="1"]')).to_be_visible()
    expect(dialog.locator('.source-fieldset')).to_be_hidden()
    page.locator('#run-target').fill('example.test')
    page.locator('#run-limit').fill('25')
    dialog.get_by_role('button', name='Continue to sources').click()

    expect(dialog.locator('[data-prototype-step="2"]')).to_be_visible()
    expect(dialog.locator('[data-activity="P0"]')).to_be_visible()
    expect(dialog.locator('[data-activity="P1"]')).to_be_hidden()
    dialog.get_by_role('button', name='Continue to activity').click()

    expect(dialog.locator('[data-prototype-step="3"]')).to_be_visible()
    expect(dialog.locator('[data-activity="P0"]')).to_be_hidden()
    expect(dialog.locator('[data-activity="P1"]')).to_be_visible()
    page.locator('input[name="dns_lookup"]').check()
    dialog.get_by_role('button', name='Review authorization').click()

    expect(dialog.locator('[data-prototype-step="4"]')).to_be_visible()
    expect(page.locator('#final-authorization-summary')).to_contain_text('example.test')
    expect(page.locator('#final-authorization-summary')).to_contain_text('P1 selected')
    expect(dialog.locator('[aria-current="step"]')).to_contain_text('Review')
    assert dialog.locator('[data-prototype-step="4"] button:visible').count() == 2
    assert dialog.locator('[data-prototype-step="4"] .primary:visible').count() == 1

    dialog.get_by_role('button', name='Back to activity').click()
    dialog.get_by_role('button', name='Back').click()
    dialog.get_by_role('button', name='Back').click()
    expect(page.locator('#run-target')).to_have_value('example.test')
    expect(page.locator('#run-limit')).to_have_value('25')
    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')


def test_clean_routes_do_not_activate_the_prototype(harvestview_server_url: str, page: Page) -> None:
    page.goto(f'{harvestview_server_url}/')

    expect(page.locator('.prototype-switcher')).to_have_count(0)
    expect(page.locator('[data-prototype-step]')).to_have_count(0)

    page.goto(f'{harvestview_server_url}/schedules')
    expect(page.locator('.prototype-switcher')).to_have_count(0)
    expect(page.locator('.prototype-delete-disclosure')).to_have_count(0)


SCREENSHOT_DIR = os.getenv('HARVESTVIEW_PROTOTYPE_SCREENSHOT_DIR')


@pytest.mark.skipif(not SCREENSHOT_DIR, reason='set HARVESTVIEW_PROTOTYPE_SCREENSHOT_DIR to render the prototype matrix')
@pytest.mark.parametrize('variant', ['mineral', 'ledger', 'signal'])
@pytest.mark.parametrize('surface', ['run-overview', 'planner', 'hostname-changes', 'execution-outcomes', 'schedules'])
@pytest.mark.parametrize(('width', 'height'), [(1440, 900), (390, 844)], ids=['desktop', 'mobile'])
def test_render_prototype_matrix(
    harvestview_server_url: str,
    page: Page,
    variant: str,
    surface: str,
    width: int,
    height: int,
) -> None:
    assert SCREENSHOT_DIR is not None
    route_prototype_evidence(page, harvestview_server_url)
    page.set_viewport_size({'width': width, 'height': height})
    page.emulate_media(color_scheme='dark')

    route = '/schedules' if surface == 'schedules' else '/'
    page.goto(f'{harvestview_server_url}{route}?variant={variant}')
    if surface == 'schedules':
        expect(page.locator('.schedule-card')).to_be_visible()
        if width <= 1000:
            page.locator('.schedule-card').first.scroll_into_view_if_needed()
    else:
        expect(page.locator('#run-detail')).to_be_visible()

    if surface == 'planner':
        page.get_by_role('button', name='Start enumeration').first.click()
        page.locator('#new-run-dialog').evaluate('node => { node.scrollTop = 0; }')
    elif surface == 'hostname-changes':
        expect(page.locator('#hostname-tracking-section')).to_be_visible()
        page.locator('#hostname-tracking-section').scroll_into_view_if_needed()
    elif surface == 'execution-outcomes':
        page.locator('#provider-details summary').click()
        expect(page.locator('#provider-details')).to_have_attribute('open', '')
        page.locator('#provider-details').scroll_into_view_if_needed()

    assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')

    output = Path(SCREENSHOT_DIR)
    output.mkdir(parents=True, exist_ok=True)
    viewport = 'desktop' if width > 1000 else 'mobile'
    page.screenshot(path=output / f'{variant}-{surface}-{viewport}.png')

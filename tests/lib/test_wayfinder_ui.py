from __future__ import annotations

import ipaddress

from fastapi.testclient import TestClient


def test_wayfinder_owns_root_and_issues_an_http_only_session(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        legacy = client.get('/app')
        runs = client.get('/api/wayfinder/runs')

    assert root.status_code == 200
    assert '<title>Wayfinder · theHarvester</title>' in root.text
    assert legacy.status_code == 404
    cookie = root.headers['set-cookie']
    assert 'theharvester-api-key=' in cookie
    assert 'test-key' not in cookie
    assert 'HttpOnly' in cookie
    assert 'SameSite=strict' in cookie
    assert 'Path=/api/wayfinder' in cookie
    assert runs.status_code == 200
    assert runs.json() == []


def test_docker_mode_trusts_only_the_detected_gateway(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, wayfinder

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_DB', str(tmp_path / 'wayfinder.sqlite'))
    monkeypatch.setenv('THEHARVESTER_WAYFINDER_WORKER', 'disabled')
    monkeypatch.setattr(wayfinder, '_docker_gateway', lambda: ipaddress.ip_address('172.18.0.1'))

    with TestClient(api.app, base_url='http://127.0.0.1', client=('172.18.0.1', 50000)) as client:
        disabled = client.get('/')

    monkeypatch.setenv('THEHARVESTER_WAYFINDER_LOCAL_PROXY', 'enabled')
    with TestClient(api.app, base_url='http://127.0.0.1', client=('172.18.0.1', 50000)) as client:
        gateway = client.get('/')
    with TestClient(api.app, base_url='http://127.0.0.1', client=('172.18.0.2', 50000)) as client:
        sibling = client.get('/')
    with TestClient(api.app, base_url='http://attacker.example', client=('172.18.0.1', 50000)) as client:
        rebound = client.get('/')

    assert disabled.status_code == 403
    assert gateway.status_code == 200
    assert sibling.status_code == 403
    assert rebound.status_code == 403

"""Daemon integration API tests."""

import json

import pytest

from app import create_app
from app.bpf_accessor import BPFMapAccessor


@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_token(client):
    response = client.post(
        '/api/auth/login',
        json={'username': 'admin', 'password': 'test-admin-password'},
        content_type='application/json',
    )
    return json.loads(response.data)['access_token']


class TestDaemon:
    def test_get_daemon_status(self, client, auth_token):
        response = client.get(
            '/api/daemon/status',
            headers={'Authorization': f'Bearer {auth_token}'},
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'daemon' in data
        assert 'config' in data

    def test_start_and_stop_daemon(self, client, auth_token):
        start_response = client.post(
            '/api/daemon/start',
            json={},
            headers={'Authorization': f'Bearer {auth_token}'},
            content_type='application/json',
        )
        assert start_response.status_code in [200, 500]

        stop_response = client.post(
            '/api/daemon/stop',
            json={},
            headers={'Authorization': f'Bearer {auth_token}'},
            content_type='application/json',
        )
        assert stop_response.status_code in [200, 500]

    def test_restart_daemon(self, client, auth_token):
        response = client.post(
            '/api/daemon/restart',
            json={},
            headers={'Authorization': f'Bearer {auth_token}'},
            content_type='application/json',
        )
        assert response.status_code in [200, 500]

    def test_daemon_requires_auth(self, client):
        response = client.get('/api/daemon/status')
        assert response.status_code == 401


class TestSabbathMode:
    def test_live_accessor_refuses_start_on_saturday(self, tmp_path, monkeypatch):
        accessor = BPFMapAccessor(
            config_store_path=str(tmp_path / 'config.json'),
            daemon_log_path=str(tmp_path / 'knockd.log'),
            use_sudo=False,
            sabbath_mode=True,
        )
        monkeypatch.setattr(accessor, '_is_sabbath_active', lambda: True)

        result = accessor.start_daemon({
            'hmac_key': '0' * 64,
            'sabbath_mode': True,
        })

        assert result['success'] is False
        assert result['sabbath_active'] is True
        assert 'Saturday' in result['error']

    def test_live_accessor_passes_sabbath_flag_to_knockd(self, tmp_path, monkeypatch):
        captured = {}
        accessor = BPFMapAccessor(
            config_store_path=str(tmp_path / 'config.json'),
            daemon_log_path=str(tmp_path / 'knockd.log'),
            use_sudo=False,
            sabbath_mode=True,
        )
        monkeypatch.setattr(accessor, '_is_sabbath_active', lambda: False)
        monkeypatch.setattr(accessor, '_resolve_knockd_bin', lambda: '/usr/local/bin/knockd')
        monkeypatch.setattr(accessor, '_get_knockd_pids', lambda: [])
        monkeypatch.setattr('app.bpf_accessor.time.sleep', lambda _seconds: None)

        class FakeProcess:
            pid = 12345
            returncode = None

            def poll(self):
                return None

        def fake_popen(cmd, **_kwargs):
            captured['cmd'] = cmd
            return FakeProcess()

        monkeypatch.setattr('app.bpf_accessor.subprocess.Popen', fake_popen)

        result = accessor.start_daemon({
            'hmac_key': '0' * 64,
            'sabbath_mode': True,
        })

        assert result['success'] is True
        assert '--sabbath-mode' in captured['cmd']

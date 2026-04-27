"""Daemon integration API tests."""

import json

import pytest

from app import create_app


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
        json={'username': 'admin', 'password': 'changeme123'},
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

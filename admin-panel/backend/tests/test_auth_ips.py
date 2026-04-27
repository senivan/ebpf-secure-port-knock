"""
Authorized IP API tests
"""
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
        json={'username': 'admin', 'password': 'test-admin-password'},
        content_type='application/json'
    )
    return json.loads(response.data)['access_token']


class TestAuthorizedIps:
    def test_list_authorized_ips_exposes_capabilities(self, client, auth_token):
        response = client.get(
            '/api/auth-ips/list',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['mode'] == 'mock'
        assert data['manual_authorize_supported'] is True
        assert data['manual_revoke_supported'] is True
        assert isinstance(data['authorized_ips'], list)

    def test_authorize_and_revoke_ip(self, client, auth_token):
        headers = {'Authorization': f'Bearer {auth_token}'}

        authorize = client.post(
            '/api/auth-ips/authorize',
            json={'ip': '192.0.2.10', 'duration_ms': 5000},
            headers=headers,
            content_type='application/json'
        )
        assert authorize.status_code == 200

        revoke = client.post(
            '/api/auth-ips/revoke',
            json={'ip': '192.0.2.10'},
            headers=headers,
            content_type='application/json'
        )
        assert revoke.status_code == 200

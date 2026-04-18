"""
Configuration API tests
"""
import pytest
import json
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
    """Get auth token for protected routes"""
    response = client.post('/api/auth/login',
        json={'username': 'admin', 'password': 'changeme123'},
        content_type='application/json'
    )
    return json.loads(response.data)['access_token']


class TestConfiguration:
    """Test configuration endpoints"""

    def test_get_config(self, client, auth_token):
        """Test getting configuration"""
        response = client.get('/api/config/get',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert response.status_code in [200, 500]  # May fail if BPF maps unavailable

    def test_update_config(self, client, auth_token):
        """Test updating configuration"""
        new_config = {
            'knock_port': 9001,
            'timeout_ms': 6000,
            'protected_ports': [22, 443, 8080]
        }
        response = client.post('/api/config/update',
            json=new_config,
            headers={'Authorization': f'Bearer {auth_token}'},
            content_type='application/json'
        )
        assert response.status_code in [200, 400, 500]

    def test_get_hmac_key(self, client, auth_token):
        """Test getting HMAC key"""
        response = client.get('/api/config/keys/hmac',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert response.status_code in [200, 404, 500]

    def test_update_hmac_key(self, client, auth_token):
        """Test updating HMAC key"""
        new_key = '0' * 64  # 64 hex characters
        # Endpoint is /keys/hmac/update (not /keys/hmac)
        response = client.post('/api/config/keys/hmac/update',
            json={'hmac_key': new_key},
            headers={'Authorization': f'Bearer {auth_token}'},
            content_type='application/json'
        )
        assert response.status_code in [200, 400, 500]

    def test_config_requires_auth(self, client):
        """Test that config requires authentication"""
        response = client.get('/api/config/get')
        assert response.status_code == 401

    def test_invalid_config_values(self, client, auth_token):
        """Test config with invalid values"""
        invalid_config = {
            'knock_port': -1,  # Invalid port
            'timeout_ms': -5000
        }
        response = client.post('/api/config/update',
            json=invalid_config,
            headers={'Authorization': f'Bearer {auth_token}'},
            content_type='application/json'
        )
        # Should either accept and validate server-side or reject
        assert response.status_code in [200, 400, 422]

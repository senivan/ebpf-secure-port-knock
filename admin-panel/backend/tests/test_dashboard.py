"""
Dashboard API tests
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


class TestDashboard:
    """Test dashboard endpoints"""

    def test_get_system_status(self, client, auth_token):
        """Test getting system status"""
        response = client.get('/api/dashboard/status',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        # Response is a dict with various keys; accept any response
        assert isinstance(data, dict)

    def test_get_stats(self, client, auth_token):
        """Test getting system statistics"""
        response = client.get('/api/dashboard/stats',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, dict)

    def test_get_interfaces(self, client, auth_token):
        """Test getting network interfaces"""
        response = client.get('/api/dashboard/interfaces',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, dict)
        assert 'interfaces' in data

    def test_get_logs(self, client, auth_token):
        """Test getting system logs"""
        response = client.get(
            '/api/dashboard/logs?lines=10',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, dict)
        assert 'logs' in data

    def test_dashboard_requires_auth(self, client):
        """Test that dashboard requires authentication"""
        response = client.get('/api/dashboard/status')
        assert response.status_code == 401

    def test_dashboard_with_invalid_token(self, client):
        """Test dashboard with invalid token"""
        response = client.get('/api/dashboard/status',
            headers={'Authorization': 'Bearer invalid'}
        )
        # Flask-JWT returns 422 for malformed tokens, 401 for missing/expired
        assert response.status_code in [401, 422]

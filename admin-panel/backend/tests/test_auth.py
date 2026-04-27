"""
Authentication API tests
"""
import pytest
import json
from app import create_app
from werkzeug.security import generate_password_hash


@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


class TestAuthentication:
    """Test authentication endpoints"""

    def test_login_success(self, client):
        """Test successful login with correct credentials"""
        response = client.post('/api/auth/login', 
            json={'username': 'admin', 'password': 'test-admin-password'},
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert data['user'] == 'admin'
        assert data['message'] == 'Login successful'

    def test_login_invalid_password(self, client):
        """Test login with invalid password"""
        response = client.post('/api/auth/login',
            json={'username': 'admin', 'password': 'wrongpassword'},
            content_type='application/json'
        )
        assert response.status_code == 401

    def test_login_with_prehashed_password(self, app, client):
        """Test login against a pre-hashed configured password"""
        app.config['ADMIN_PASSWORD_HASH'] = generate_password_hash('hash-only-password')
        response = client.post('/api/auth/login',
            json={'username': 'admin', 'password': 'hash-only-password'},
            content_type='application/json'
        )
        assert response.status_code == 200

    def test_login_invalid_username(self, client):
        """Test login with invalid username"""
        response = client.post('/api/auth/login',
            json={'username': 'invalid', 'password': 'test-admin-password'},
            content_type='application/json'
        )
        assert response.status_code == 401

    def test_login_missing_fields(self, client):
        """Test login with missing fields"""
        response = client.post('/api/auth/login',
            json={'username': 'admin'},
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_verify_token_valid(self, client):
        """Test token verification with valid token"""
        # First login to get token
        login_response = client.post('/api/auth/login',
            json={'username': 'admin', 'password': 'test-admin-password'},
            content_type='application/json'
        )
        token = json.loads(login_response.data)['access_token']
        
        # Then verify token
        response = client.get('/api/auth/verify',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['valid'] == True

    def test_verify_token_invalid(self, client):
        """Test token verification with invalid token"""
        response = client.get('/api/auth/verify',
            headers={'Authorization': 'Bearer invalid_token'}
        )
        # Flask-JWT returns 422 for malformed tokens
        assert response.status_code in [401, 422]

    def test_verify_token_missing(self, client):
        """Test token verification without token"""
        response = client.get('/api/auth/verify')
        assert response.status_code == 401

    def test_get_user_info(self, client):
        """Test getting user info"""
        # First login
        login_response = client.post('/api/auth/login',
            json={'username': 'admin', 'password': 'test-admin-password'},
            content_type='application/json'
        )
        token = json.loads(login_response.data)['access_token']
        
        # Get user info (endpoint is /user-info, not /user)
        response = client.get('/api/auth/user-info',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['username'] == 'admin'
        assert data['role'] == 'admin'

"""
Security hardening tests.
"""
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


def test_api_cors_allows_only_configured_origin(client):
    response = client.options(
        '/api/auth/login',
        headers={
            'Origin': 'http://localhost:3000',
            'Access-Control-Request-Method': 'POST',
        },
    )

    assert response.headers.get('Access-Control-Allow-Origin') == 'http://localhost:3000'


def test_api_cors_rejects_untrusted_origin(client):
    response = client.options(
        '/api/auth/login',
        headers={
            'Origin': 'https://evil.example',
            'Access-Control-Request-Method': 'POST',
        },
    )

    assert response.headers.get('Access-Control-Allow-Origin') is None


def test_security_headers_are_added(client):
    response = client.get('/health')

    assert response.headers['Content-Security-Policy'] == "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['Referrer-Policy'] == 'no-referrer'
    assert response.headers['Permissions-Policy'] == 'camera=(), microphone=(), geolocation=(), payment=()'


def test_hsts_is_added_for_forwarded_https(app, client):
    app.config['SECURITY_HSTS_ENABLED'] = True

    response = client.get('/health', headers={'X-Forwarded-Proto': 'https'})

    assert response.headers['Strict-Transport-Security'] == 'max-age=63072000; includeSubDomains'

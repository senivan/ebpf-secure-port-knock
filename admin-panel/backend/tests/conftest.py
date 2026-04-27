"""
Pytest configuration and shared fixtures
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('FLASK_ENV', 'testing')
os.environ.setdefault('USE_MOCK_BPF', 'auto')
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-admin-panel-suite-1234')
os.environ.setdefault('JWT_SECRET_KEY', 'test-jwt-secret-key-for-admin-panel-suite-1234')
os.environ.setdefault('ADMIN_USERNAME', 'admin')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')

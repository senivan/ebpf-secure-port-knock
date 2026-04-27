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

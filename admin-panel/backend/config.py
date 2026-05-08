import os
from dotenv import load_dotenv

load_dotenv()

INSECURE_SECRET_VALUES = {
    'dev-secret-key-change-me',
    'replace-this-secret-key',
    'your-secret-key-change-me',
    'your-secret-key-change-in-production',
}

INSECURE_JWT_SECRET_VALUES = {
    'jwt-secret-key-change-me',
    'replace-this-jwt-secret',
    'your-jwt-key-change-me',
    'your-jwt-secret-key-change-in-production',
}

INSECURE_ADMIN_PASSWORD_VALUES = {
    'changeme123',
    'replace-this-password',
}


def parse_csv_env(name, default=''):
    """Parse a comma-separated environment variable into a clean list."""
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(',') if item.strip()]

class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-me')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', False)
    
    # BPF Configuration
    BPFFS_PATH = os.getenv('BPFFS_PATH', '/sys/fs/bpf')
    BPF_MAP_PATH = os.getenv('BPF_MAP_PATH', '/sys/fs/bpf/knock_gate')

    # knockd integration
    KNOCKD_BIN = os.getenv('KNOCKD_BIN', '/home/user/ebpf-secure-port-knock/build/knockd')
    KNOCKD_CONFIG_PATH = os.getenv('KNOCKD_CONFIG_PATH', '/tmp/knock_admin_config.json')
    KNOCKD_LOG_PATH = os.getenv('KNOCKD_LOG_PATH', '/tmp/knockd-admin.log')
    KNOCKD_DEFAULT_IFACE = os.getenv('KNOCKD_DEFAULT_IFACE', 'eth0')
    KNOCKD_USERS_FILE = os.getenv('KNOCKD_USERS_FILE', '')
    KNOCKD_PIN_DIR = os.getenv('KNOCKD_PIN_DIR', '/sys/fs/bpf/knock_gate')
    KNOCKD_USE_SUDO = os.getenv('KNOCKD_USE_SUDO', 'true').lower() in ['1', 'true', 'yes']
    KNOCKD_SABBATH_MODE = os.getenv('KNOCKD_SABBATH_MODE', 'false').lower() in ['1', 'true', 'yes']
    
    # Admin credentials
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'changeme123')
    ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH')
    
    # API settings
    API_PORT = int(os.getenv('API_PORT', 5000))
    JSON_SORT_KEYS = False
    CORS_ORIGINS = parse_csv_env(
        'CORS_ORIGINS',
        'http://localhost:3000,http://127.0.0.1:3000'
    )
    SECURITY_HSTS_ENABLED = os.getenv('SECURITY_HSTS_ENABLED', 'false').lower() in ['1', 'true', 'yes']
    
    # Mock/Demo mode (use if BPF maps don't exist)
    USE_MOCK_BPF = os.getenv('USE_MOCK_BPF', 'auto')  # 'auto', 'true', 'false'

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SECURITY_HSTS_ENABLED = os.getenv('SECURITY_HSTS_ENABLED', 'true').lower() in ['1', 'true', 'yes']

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True

def get_config():
    """Get config based on environment"""
    env = os.getenv('FLASK_ENV', 'development')
    if env == 'production':
        return ProductionConfig()
    elif env == 'testing':
        return TestingConfig()
    return DevelopmentConfig()


def validate_config(config):
    """Reject insecure runtime defaults outside tests."""
    if getattr(config, 'TESTING', False):
        return

    errors = []

    if config.SECRET_KEY in INSECURE_SECRET_VALUES:
        errors.append('SECRET_KEY must be changed from the repository default')

    if config.JWT_SECRET_KEY in INSECURE_JWT_SECRET_VALUES:
        errors.append('JWT_SECRET_KEY must be changed from the repository default')

    if not config.ADMIN_USERNAME:
        errors.append('ADMIN_USERNAME must be set')

    if not config.ADMIN_PASSWORD and not config.ADMIN_PASSWORD_HASH:
        errors.append('Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH')

    if config.ADMIN_PASSWORD in INSECURE_ADMIN_PASSWORD_VALUES:
        errors.append('ADMIN_PASSWORD must not use the repository default value')

    if not config.CORS_ORIGINS:
        errors.append('CORS_ORIGINS must list explicit trusted origins')

    if '*' in config.CORS_ORIGINS:
        errors.append('CORS_ORIGINS must not contain wildcard origins')

    if errors:
        joined = '\n'.join(f'- {error}' for error in errors)
        raise RuntimeError(f'Invalid admin-panel configuration:\n{joined}')

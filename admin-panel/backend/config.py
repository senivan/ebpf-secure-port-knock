import os
from dotenv import load_dotenv

load_dotenv()

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
    
    # Admin credentials
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'changeme123')
    
    # API settings
    API_PORT = int(os.getenv('API_PORT', 5000))
    JSON_SORT_KEYS = False
    
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

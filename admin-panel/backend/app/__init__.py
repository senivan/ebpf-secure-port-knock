from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash
from config import get_config, validate_config

def get_bpf_accessor():
    """Get BPF accessor (real or mock based on availability)"""
    config = get_config()
    
    # Check if we should use mock
    use_mock = config.USE_MOCK_BPF
    if use_mock == 'auto':
        use_mock = bool(getattr(config, 'TESTING', False))
    elif use_mock in ['true', 'True', '1']:
        use_mock = True
    else:
        use_mock = False
    
    if use_mock:
        from app.bpf_mock import MockBPFMapAccessor
        return MockBPFMapAccessor()
    else:
        from app.bpf_accessor import BPFMapAccessor
        return BPFMapAccessor(
            bpf_path=config.BPF_MAP_PATH,
            knockd_bin=config.KNOCKD_BIN,
            config_store_path=config.KNOCKD_CONFIG_PATH,
            daemon_log_path=config.KNOCKD_LOG_PATH,
            use_sudo=config.KNOCKD_USE_SUDO,
            default_ifname=config.KNOCKD_DEFAULT_IFACE,
            default_users_file=config.KNOCKD_USERS_FILE,
            default_pin_dir=config.KNOCKD_PIN_DIR,
        )

def create_app():
    """Application factory"""
    app = Flask(__name__)
    config = get_config()
    validate_config(config)
    app.config.from_object(config)
    app.config['ADMIN_PASSWORD_HASH'] = (
        config.ADMIN_PASSWORD_HASH or generate_password_hash(config.ADMIN_PASSWORD)
    )

    # Initialize BPF accessor and store in app context
    app.bpf_accessor = get_bpf_accessor()

    # Initialize extensions
    CORS(app)
    jwt = JWTManager(app)

    # Initialize rate limiter
    from app.routes.auth import limiter
    limiter.init_app(app)

    # Register blueprints
    from app.routes import auth, dashboard, config_routes, auth_ips, logs, test, daemon
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(config_routes.bp)
    app.register_blueprint(auth_ips.bp)
    app.register_blueprint(logs.bp)
    app.register_blueprint(test.bp)
    app.register_blueprint(daemon.bp)
    
    # Health check
    @app.route('/health', methods=['GET'])
    def health():
        if getattr(app.bpf_accessor, 'is_mock', False):
            return {
                'status': 'degraded',
                'message': 'DEMO MODE - KERNEL GATE IS NOT ACTIVE',
                'mode': 'mock',
            }, 503
        return {'status': 'ok', 'message': 'Admin panel is running', 'mode': 'live'}, 200
    
    return app

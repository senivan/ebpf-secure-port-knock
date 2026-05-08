from flask import Flask, request
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
            sabbath_mode=config.KNOCKD_SABBATH_MODE,
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
    CORS(app, resources={
        r"/api/*": {
            "origins": config.CORS_ORIGINS,
            "allow_headers": ["Authorization", "Content-Type"],
            "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "supports_credentials": False,
        }
    })
    jwt = JWTManager(app)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
        if app.config.get('SECURITY_HSTS_ENABLED') and (
            request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
        ):
            response.headers.setdefault('Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
        return response

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

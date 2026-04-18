from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from config import get_config
from pathlib import Path

def get_bpf_accessor():
    """Get BPF accessor (real or mock based on availability)"""
    config = get_config()
    
    # Check if we should use mock
    use_mock = config.USE_MOCK_BPF
    if use_mock == 'auto':
        # Auto-detect: use mock if real maps don't exist
        bpf_path = Path(config.BPF_MAP_PATH)
        use_mock = not (bpf_path / "config_map").exists()
    elif use_mock in ['true', 'True', '1']:
        use_mock = True
    else:
        use_mock = False
    
    if use_mock:
        from app.bpf_mock import MockBPFMapAccessor
        return MockBPFMapAccessor()
    else:
        from app.bpf_accessor import BPFMapAccessor
        return BPFMapAccessor()

def create_app():
    """Application factory"""
    app = Flask(__name__)
    config = get_config()
    app.config.from_object(config)
    
    # Initialize BPF accessor and store in app context
    app.bpf_accessor = get_bpf_accessor()
    
    # Initialize extensions
    CORS(app)
    jwt = JWTManager(app)
    
    # Register blueprints
    from app.routes import auth, dashboard, config_routes, auth_ips, logs, test
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(config_routes.bp)
    app.register_blueprint(auth_ips.bp)
    app.register_blueprint(logs.bp)
    app.register_blueprint(test.bp)
    
    # Health check
    @app.route('/health', methods=['GET'])
    def health():
        return {'status': 'ok', 'message': 'Admin panel is running'}, 200
    
    return app

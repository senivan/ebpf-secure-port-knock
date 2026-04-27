from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import jwt_required

bp = Blueprint('daemon', __name__, url_prefix='/api/daemon')


@bp.route('/status', methods=['GET'])
@jwt_required()
def status():
    """Get knockd daemon status and effective config."""
    try:
        bpf = current_app.bpf_accessor
        return jsonify({
            'daemon': bpf.get_daemon_status(),
            'config': bpf.get_config(),
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/start', methods=['POST'])
@jwt_required()
def start():
    """Start knockd using current or provided config."""
    try:
        bpf = current_app.bpf_accessor
        data = request.get_json(silent=True) or {}
        result = bpf.start_daemon(config=data if isinstance(data, dict) else None)
        return jsonify(result), 200 if result.get('success') else 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/stop', methods=['POST'])
@jwt_required()
def stop():
    """Stop running knockd processes."""
    try:
        bpf = current_app.bpf_accessor
        result = bpf.stop_daemon()
        return jsonify(result), 200 if result.get('success') else 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/restart', methods=['POST'])
@jwt_required()
def restart():
    """Restart knockd with optional config updates."""
    try:
        bpf = current_app.bpf_accessor
        data = request.get_json(silent=True) or {}
        result = bpf.restart_daemon(config=data if isinstance(data, dict) else None)
        return jsonify(result), 200 if result.get('success') else 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

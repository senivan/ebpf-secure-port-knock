from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import jwt_required

bp = Blueprint('config', __name__, url_prefix='/api/config')

@bp.route('/get', methods=['GET'])
@jwt_required()
def get_config():
    """Get current configuration"""
    try:
        bpf = current_app.bpf_accessor
        config = bpf.get_config()
        return jsonify(config), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/update', methods=['POST'])
@jwt_required()
def update_config():
    """Update configuration and optionally restart daemon."""
    try:
        bpf = current_app.bpf_accessor
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON body'}), 400

        required_fields = ['knock_port', 'protected_ports', 'timeout_ms']
        
        missing_fields = [f for f in required_fields if f not in data]
        if missing_fields:
            return jsonify({
                'error': f'Missing fields: {missing_fields}'
            }), 400
        
        # Validate inputs
        if not isinstance(data['knock_port'], int) or not (1 <= data['knock_port'] <= 65535):
            return jsonify({'error': 'Invalid knock port'}), 400
        
        if not isinstance(data['protected_ports'], list):
            return jsonify({'error': 'Protected ports must be a list'}), 400
        
        if not isinstance(data['timeout_ms'], int) or data['timeout_ms'] <= 0:
            return jsonify({'error': 'Invalid timeout'}), 400

        hmac_key = data.get('hmac_key', '')
        if hmac_key:
            if len(hmac_key) != 64:
                return jsonify({'error': 'HMAC key must be 32 bytes (64 hex chars)'}), 400
            try:
                int(hmac_key, 16)
            except ValueError:
                return jsonify({'error': 'HMAC key must be valid hexadecimal'}), 400

        restart_daemon = bool(data.get('restart_daemon', False))
        result = bpf.update_config(data, restart_daemon=restart_daemon)
        if not result.get('success'):
            return jsonify(result), 500

        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/ports/protected', methods=['GET'])
@jwt_required()
def get_protected_ports():
    """Get protected ports"""
    try:
        bpf = current_app.bpf_accessor
        config = bpf.get_config()
        return jsonify({
            'protected_ports': config.get('protected_ports', []),
            'count': len(config.get('protected_ports', []))
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/ports/knock', methods=['GET'])
@jwt_required()
def get_knock_port():
    """Get knock port configuration"""
    try:
        bpf = current_app.bpf_accessor
        config = bpf.get_config()
        return jsonify({
            'knock_port': config.get('knock_port'),
            'timeout_ms': config.get('timeout_ms')
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/keys/hmac', methods=['GET'])
@jwt_required()
def get_hmac_key():
    """Get HMAC key (last 4 chars visible for security)"""
    try:
        bpf = current_app.bpf_accessor
        config = bpf.get_config()
        hmac_key = config.get('hmac_key', '')
        masked_key = '*' * (len(hmac_key) - 4) + hmac_key[-4:] if hmac_key else ''
        
        return jsonify({
            'hmac_key_masked': masked_key,
            'key_length_bytes': len(hmac_key) // 2
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/keys/hmac/update', methods=['POST'])
@jwt_required()
def update_hmac_key():
    """Update HMAC key"""
    try:
        bpf = current_app.bpf_accessor
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON body'}), 400
        
        if 'hmac_key' not in data:
            return jsonify({'error': 'Missing hmac_key'}), 400
        
        hmac_key = data['hmac_key']
        
        # Validate hex string and length
        if len(hmac_key) != 64:
            return jsonify({'error': 'HMAC key must be 64 hex characters (32 bytes)'}), 400
        
        try:
            int(hmac_key, 16)
        except ValueError:
            return jsonify({'error': 'HMAC key must be valid hexadecimal'}), 400
        
        restart_daemon = bool(data.get('restart_daemon', False))
        result = bpf.update_config({'hmac_key': hmac_key}, restart_daemon=restart_daemon)
        if not result.get('success'):
            return jsonify(result), 500

        return jsonify({
            'success': True,
            'message': 'HMAC key updated',
            'masked_key': '*' * 60 + hmac_key[-4:],
            'daemon': result.get('daemon')
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/timeout', methods=['GET'])
@jwt_required()
def get_timeout():
    """Get protocol timeout"""
    try:
        bpf = current_app.bpf_accessor
        config = bpf.get_config()
        return jsonify({
            'timeout_ms': config.get('timeout_ms')
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/timeout/update', methods=['POST'])
@jwt_required()
def update_timeout():
    """Update timeout value"""
    try:
        bpf = current_app.bpf_accessor
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON body'}), 400
        
        if 'timeout_ms' not in data:
            return jsonify({'error': 'Missing timeout_ms'}), 400
        
        timeout_ms = data['timeout_ms']
        
        if not isinstance(timeout_ms, int) or timeout_ms <= 0 or timeout_ms > 3600000:
            return jsonify({'error': 'Timeout must be between 1ms and 1 hour'}), 400
        
        restart_daemon = bool(data.get('restart_daemon', False))
        result = bpf.update_config({'timeout_ms': timeout_ms}, restart_daemon=restart_daemon)
        if not result.get('success'):
            return jsonify(result), 500

        return jsonify({
            'success': True,
            'message': f'Timeout updated to {timeout_ms}ms',
            'timeout_ms': timeout_ms,
            'daemon': result.get('daemon')
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

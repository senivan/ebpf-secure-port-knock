from flask import Blueprint, jsonify, current_app
from flask_jwt_extended import jwt_required
import time

bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')

@bp.route('/status', methods=['GET'])
@jwt_required()
def get_status():
    """Get system status overview"""
    try:
        bpf = current_app.bpf_accessor
        status = bpf.get_system_status()
        config = bpf.get_config()
        counters = bpf.get_debug_counters()
        auth_ips = bpf.get_authorized_ips()
        snapshot = bpf.get_last_knock_snapshot()
        
        return jsonify({
            'system': status,
            'config': config,
            'counters': counters,
            'authorized_ips_count': len([ip for ip in auth_ips if ip.get('authorized')]),
            'total_verified_knocks': counters.get('knock_valid', 0),
            'last_knock': snapshot,
            'timestamp': int(time.time() * 1000)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get detailed statistics"""
    try:
        bpf = current_app.bpf_accessor
        counters = bpf.get_debug_counters()
        auth_ips = bpf.get_authorized_ips()
        config = bpf.get_config()
        
        total_knockes = counters.get('knock_seen', 0)
        valid_knocks = counters.get('knock_valid', 0)
        
        return jsonify({
            'packets': {
                'total_seen': total_knockes,
                'valid': valid_knocks,
                'invalid': total_knockes - valid_knocks,
                'replay_dropped': counters.get('replay_drop', 0),
                'success_rate': (valid_knocks / max(1, total_knockes)) * 100
            },
            'protection': {
                'protected_dropped': counters.get('protected_drop', 0),
                'protected_passed': counters.get('protected_pass', 0),
                'protected_ports': config.get('protected_ports', []),
                'pass_rate': (counters.get('protected_pass', 0) / 
                         max(1, counters.get('protected_drop', 0) + 
                             counters.get('protected_pass', 0))) * 100
            },
            'authorization': {
                'active_ips': len([ip for ip in auth_ips if ip.get('authorized')]),
                'total_entries': len(auth_ips),
                'timeout_seconds': config.get('timeout_ms', 5000) // 1000
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/interfaces', methods=['GET'])
@jwt_required()
def get_interfaces():
    """Get network interfaces"""
    try:
        interfaces = bpf.get_network_interfaces()
        return jsonify({'interfaces': interfaces}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/logs', methods=['GET'])
@jwt_required()
def get_logs():
    """Get system logs"""
    try:
        lines = request.args.get('lines', 100, type=int)
        logs = bpf.get_system_logs(lines)
        return jsonify({'logs': logs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

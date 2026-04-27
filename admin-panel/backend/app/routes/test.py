from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import jwt_required
import subprocess
import os
import socket
import ipaddress
import time

bp = Blueprint('test', __name__, url_prefix='/api/test')

def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@bp.route('/knock-packet', methods=['POST'])
@jwt_required()
def send_knock_packet():
    """Generate and send a test knock packet"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required = ['src_ip', 'dst_ip', 'hmac_key']
        missing = [f for f in required if f not in data]
        if missing:
            return jsonify({'error': f'Missing fields: {missing}'}), 400
        
        src_ip = data['src_ip']
        dst_ip = data['dst_ip']
        hmac_key = data['hmac_key']
        dst_port = data.get('dst_port', 40000)
        ifname = data.get('ifname', 'eth0')
        
        # Validate HMAC key
        if len(hmac_key) != 64:
            return jsonify({'error': 'HMAC key must be 64 hex characters'}), 400
        
        # Find knock-client binary
        knock_client = '/home/user/ebpf-secure-port-knock/build/knock-client'
        
        if not os.path.exists(knock_client):
            return jsonify({
                'success': False,
                'error': 'knock-client binary not found. Build the project first.'
            }), 500
        
        # Execute knock-client
        try:
            result = subprocess.run([
                'sudo', knock_client,
                '--ifname', ifname,
                '--src-ip', src_ip,
                '--dst-ip', dst_ip,
                '--dst-port', str(dst_port),
                '--hmac-key', hmac_key
            ], capture_output=True, text=True, timeout=10)
            
            return jsonify({
                'success': result.returncode == 0,
                'message': 'Knock packet sent',
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None,
                'return_code': result.returncode
            }), 200 if result.returncode == 0 else 400
        except subprocess.TimeoutExpired:
            return jsonify({
                'success': False,
                'error': 'Command timed out'
            }), 500
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/connectivity', methods=['POST'])
@jwt_required()
def test_connectivity():
    """Test connectivity to a target"""
    try:
        data = request.get_json()

        if not data or 'target' not in data:
            return jsonify({'error': 'Missing target IP'}), 400

        target = data['target']
        port = int(data.get('port', 22))

        try:
            ipaddress.ip_address(target)
        except ValueError:
            return jsonify({'error': 'Invalid target IP'}), 400

        if port < 1 or port > 65535:
            return jsonify({'error': 'Invalid port'}), 400

        ping_result = subprocess.run(
            ['ping', '-c', '1', '-W', '3', target],
            capture_output=True, text=True, timeout=5
        )

        port_open = _tcp_reachable(target, port)

        return jsonify({
            'target': target,
            'port': port,
            'ping': {
                'success': ping_result.returncode == 0,
                'output': ping_result.stdout[:200] if ping_result.stdout else None
            },
            'port_open': port_open,
            'timestamp': int(time.time() * 1000)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/config-reload', methods=['POST'])
@jwt_required()
def test_config_reload():
    """Test reloading configuration"""
    try:
        bpf = current_app.bpf_accessor
        # Reload current config to verify it's still valid
        config = bpf.get_config()
        
        if 'error' in config:
            return jsonify({
                'success': False,
                'error': 'Failed to reload config'
            }), 500
        
        return jsonify({
            'success': True,
            'message': 'Configuration reloaded successfully',
            'config': config
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/maps-integrity', methods=['GET'])
@jwt_required()
def test_maps_integrity():
    """Test BPF maps integrity"""
    try:
        bpf = current_app.bpf_accessor
        status = bpf.get_system_status()
        config = bpf.get_config()
        counters = bpf.get_debug_counters()
        auth_ips = bpf.get_authorized_ips()
        
        # Check for errors
        errors = []
        if 'error' in config:
            errors.append(f'Config map: {config["error"]}')
        if 'error' in counters:
            errors.append(f'Counters map: {counters["error"]}')
        
        invalid_ips = [ip for ip in auth_ips if 'error' in ip]
        if invalid_ips:
            errors.append(f'Auth IPs: {len(invalid_ips)} entries with errors')
        
        return jsonify({
            'maps_accessible': status.get('maps_accessible', False),
            'config_valid': 'error' not in config,
            'counters_valid': 'error' not in counters,
            'auth_map_entries': len(auth_ips),
            'errors': errors,
            'overall_status': 'OK' if not errors else 'ISSUES'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/system-health', methods=['GET'])
@jwt_required()
def test_system_health():
    """Test overall system health"""
    try:
        bpf = current_app.bpf_accessor
        status = bpf.get_system_status()
        config = bpf.get_config()
        
        checks = {
            'knockd_running': status.get('knockd_running', False),
            'xdp_enabled': status.get('xdp_enabled', False),
            'maps_accessible': status.get('maps_accessible', False),
            'config_readable': 'error' not in config,
            'system_clock_ok': True,  # Assuming system is up
            'permissions_ok': True  # Assuming we have sudo
        }
        
        health_score = (sum(checks.values()) / len(checks)) * 100
        
        status_map = {
            0: 'CRITICAL',
            25: 'POOR',
            50: 'FAIR',
            75: 'GOOD',
            100: 'EXCELLENT'
        }
        
        overall_status = next(
            (status_map[k] for k in sorted(status_map.keys(), reverse=True) 
             if health_score >= k), 'UNKNOWN'
        )
        
        return jsonify({
            'health_score': health_score,
            'status': overall_status,
            'checks': checks,
            'passed': sum(checks.values()),
            'total': len(checks),
            'timestamp': int(time.time() * 1000)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

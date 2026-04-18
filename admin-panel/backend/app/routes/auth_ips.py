from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import jwt_required
import re

bp = Blueprint('auth_ips', __name__, url_prefix='/api/auth-ips')

def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)

@bp.route('/list', methods=['GET'])
@jwt_required()
def list_authorized_ips():
    """List all authorized IPs"""
    try:
        bpf = current_app.bpf_accessor
        ips = bpf.get_authorized_ips()
        
        # Filter out error entries and sort by TTL
        valid_ips = [ip for ip in ips if 'error' not in ip]
        
        return jsonify({
            'authorized_ips': valid_ips,
            'total': len(valid_ips),
            'active': len([ip for ip in valid_ips if ip.get('authorized')])
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/authorize', methods=['POST'])
@jwt_required()
def authorize_ip():
    """Authorize an IP address"""
    try:
        bpf = current_app.bpf_accessor
        data = request.get_json()
        
        if 'ip' not in data:
            return jsonify({'error': 'Missing IP address'}), 400
        
        ip = data['ip']
        duration_ms = data.get('duration_ms', 5000)
        
        if not is_valid_ip(ip):
            return jsonify({'error': f'Invalid IP address: {ip}'}), 400
        
        if not isinstance(duration_ms, int) or duration_ms <= 0:
            return jsonify({'error': 'Duration must be positive integer in milliseconds'}), 400
        
        result = bpf.authorize_ip(ip, duration_ms)
        
        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/revoke', methods=['POST'])
@jwt_required()
def revoke_ip():
    """Revoke authorization for an IP"""
    try:
        data = request.get_json()
        
        if 'ip' not in data:
            return jsonify({'error': 'Missing IP address'}), 400
        
        ip = data['ip']
        
        if not is_valid_ip(ip):
            return jsonify({'error': f'Invalid IP address: {ip}'}), 400
        
        result = bpf.revoke_ip(ip)
        
        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/revoke-all', methods=['POST'])
@jwt_required()
def revoke_all():
    """Revoke all authorized IPs"""
    try:
        ips = bpf.get_authorized_ips()
        valid_ips = [ip for ip in ips if 'error' not in ip]
        
        revoked_count = 0
        for ip_info in valid_ips:
            if ip_info.get('authorized'):
                result = bpf.revoke_ip(ip_info['ip'])
                if result.get('success'):
                    revoked_count += 1
        
        return jsonify({
            'success': True,
            'message': f'Revoked {revoked_count} authorized IPs',
            'count': revoked_count
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/info/<ip>', methods=['GET'])
@jwt_required()
def get_ip_info(ip):
    """Get information about a specific authorized IP"""
    try:
        if not is_valid_ip(ip):
            return jsonify({'error': f'Invalid IP address: {ip}'}), 400
        
        ips = bpf.get_authorized_ips()
        ip_info = next((i for i in ips if i.get('ip') == ip), None)
        
        if not ip_info:
            return jsonify({'error': f'IP {ip} not found in authorization map'}), 404
        
        return jsonify(ip_info), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get authorization statistics"""
    try:
        ips = bpf.get_authorized_ips()
        valid_ips = [ip for ip in ips if 'error' not in ip]
        
        authorized = [ip for ip in valid_ips if ip.get('authorized')]
        expired = [ip for ip in valid_ips if not ip.get('authorized')]
        
        if authorized:
            avg_ttl = sum(ip['ttl_seconds'] for ip in authorized) / len(authorized)
            max_ttl = max(ip['ttl_seconds'] for ip in authorized)
        else:
            avg_ttl = 0
            max_ttl = 0
        
        return jsonify({
            'total_entries': len(valid_ips),
            'active_authorizations': len(authorized),
            'expired_entries': len(expired),
            'average_ttl_seconds': avg_ttl,
            'max_ttl_seconds': max_ttl
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

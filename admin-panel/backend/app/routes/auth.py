from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash
from flask import current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

bp = Blueprint('auth', __name__, url_prefix='/api/auth')
limiter = Limiter(key_func=get_remote_address)

@bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    username = data['username']
    password = data['password']
    
    config_user = current_app.config.get('ADMIN_USERNAME', 'admin')
    config_pass_hash = current_app.config.get('ADMIN_PASSWORD_HASH')

    if username == config_user and config_pass_hash and check_password_hash(config_pass_hash, password):
        access_token = create_access_token(identity=username)
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': username,
            'role': 'admin'
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@bp.route('/verify', methods=['GET'])
@jwt_required()
def verify():
    """Verify JWT token"""
    current_user = get_jwt_identity()
    return jsonify({
        'valid': True,
        'user': current_user,
        'role': 'admin'
    }), 200

@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout (client-side token removal)"""
    return jsonify({'message': 'Logged out successfully'}), 200

@bp.route('/user-info', methods=['GET'])
@jwt_required()
def user_info():
    """Get current user information"""
    current_user = get_jwt_identity()
    return jsonify({
        'username': current_user,
        'role': 'admin',
        'permissions': ['read', 'write', 'delete', 'manage-keys']
    }), 200

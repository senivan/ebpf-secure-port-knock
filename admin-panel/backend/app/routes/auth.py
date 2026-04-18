from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from flask import current_app

bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Simple in-memory user storage (in production, use a database)
USERS = {
    'admin': {
        'password_hash': generate_password_hash('changeme123'),
        'role': 'admin'
    }
}

@bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    username = data['username']
    password = data['password']
    
    # Check credentials from environment or hardcoded
    config_user = current_app.config.get('ADMIN_USERNAME', 'admin')
    config_pass = current_app.config.get('ADMIN_PASSWORD', 'changeme123')
    
    if username == config_user and password == config_pass:
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

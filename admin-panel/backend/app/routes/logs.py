from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import jwt_required
import time
import json

bp = Blueprint('logs', __name__, url_prefix='/api/logs')

# In-memory event log (in production, use a database)
EVENT_LOG = []
MAX_LOG_ENTRIES = 1000

def log_event(event_type: str, description: str, severity: str = 'info', details: dict = None):
    """Log an event"""
    global EVENT_LOG
    
    event = {
        'id': len(EVENT_LOG) + 1,
        'timestamp': int(time.time() * 1000),
        'type': event_type,
        'description': description,
        'severity': severity,  # info, warning, error, critical
        'details': details or {}
    }
    
    EVENT_LOG.append(event)
    
    # Keep only last MAX_LOG_ENTRIES
    if len(EVENT_LOG) > MAX_LOG_ENTRIES:
        EVENT_LOG = EVENT_LOG[-MAX_LOG_ENTRIES:]

@bp.route('/events', methods=['GET'])
@jwt_required()
def get_events():
    """Get event log"""
    try:
        limit = request.args.get('limit', 100, type=int)
        severity = request.args.get('severity', None)
        event_type = request.args.get('type', None)
        
        filtered_log = EVENT_LOG
        
        if severity:
            filtered_log = [e for e in filtered_log if e['severity'] == severity]
        
        if event_type:
            filtered_log = [e for e in filtered_log if e['type'] == event_type]
        
        # Return most recent first
        events = sorted(filtered_log, key=lambda x: x['timestamp'], reverse=True)[:limit]
        
        return jsonify({
            'events': events,
            'total': len(EVENT_LOG),
            'returned': len(events)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/events/<int:event_id>', methods=['GET'])
@jwt_required()
def get_event(event_id):
    """Get specific event details"""
    try:
        event = next((e for e in EVENT_LOG if e['id'] == event_id), None)
        
        if not event:
            return jsonify({'error': f'Event {event_id} not found'}), 404
        
        return jsonify(event), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/system-logs', methods=['GET'])
@jwt_required()
def get_system_logs():
    """Get system logs from journalctl/dmesg"""
    try:
        bpf = current_app.bpf_accessor
        lines = request.args.get('lines', 50, type=int)
        logs = bpf.get_system_logs(lines)
        
        return jsonify({
            'logs': logs,
            'count': len(logs)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/clear', methods=['POST'])
@jwt_required()
def clear_logs():
    """Clear event log"""
    global EVENT_LOG
    try:
        old_count = len(EVENT_LOG)
        EVENT_LOG = []
        
        return jsonify({
            'success': True,
            'message': f'Cleared {old_count} events',
            'cleared': old_count
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/stats', methods=['GET'])
@jwt_required()
def get_log_stats():
    """Get log statistics"""
    try:
        by_severity = {}
        by_type = {}
        
        for event in EVENT_LOG:
            severity = event.get('severity', 'unknown')
            event_type = event.get('type', 'unknown')
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[event_type] = by_type.get(event_type, 0) + 1
        
        return jsonify({
            'total_events': len(EVENT_LOG),
            'by_severity': by_severity,
            'by_type': by_type,
            'oldest_event': EVENT_LOG[0]['timestamp'] if EVENT_LOG else None,
            'newest_event': EVENT_LOG[-1]['timestamp'] if EVENT_LOG else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/export', methods=['GET'])
@jwt_required()
def export_logs():
    """Export logs as JSON"""
    try:
        return jsonify({
            'export_count': len(EVENT_LOG),
            'events': EVENT_LOG,
            'exported_at': int(time.time() * 1000)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

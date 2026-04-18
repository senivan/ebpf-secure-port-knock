"""
Mock BPF Map Accessor for testing without actual eBPF program loaded
"""
from typing import Dict, List, Any, Optional
import time
import json
from pathlib import Path

class MockBPFMapAccessor:
    """Mock BPF map accessor that simulates the knock system without real BPF maps"""
    
    def __init__(self):
        self.mock_data_file = Path("/tmp/knock_admin_mock.json")
        self.authorized_ips = {}
        self.config = {
            'knock_port': 9000,
            'protected_ports': [22, 443, 8080],
            'timeout_ms': 5000,
            'hmac_key': '0' * 64
        }
        self.counters = {
            'total_knocksd': 0,
            'valid_knocksd': 0,
            'invalid_knocksd': 0,
            'authorized_count': 0
        }
        self.load_mock_data()
    
    def load_mock_data(self):
        """Load mock data from file if exists"""
        if self.mock_data_file.exists():
            try:
                with open(self.mock_data_file) as f:
                    data = json.load(f)
                    self.authorized_ips = data.get('ips', {})
                    self.config = data.get('config', self.config)
                    self.counters = data.get('counters', self.counters)
            except Exception:
                pass
    
    def save_mock_data(self):
        """Save mock data to file"""
        try:
            with open(self.mock_data_file, 'w') as f:
                json.dump({
                    'ips': self.authorized_ips,
                    'config': self.config,
                    'counters': self.counters
                }, f, indent=2)
        except Exception:
            pass
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get system status (mock)"""
        return {
            'knockd_running': True,
            'xdp_enabled': True,
            'maps_accessible': True,
            'system_status': 'ACTIVE (MOCK)',
            'timestamp': int(time.time() * 1000),
            'note': 'Demo mode - using mock data instead of real BPF maps'
        }
    
    def get_config(self) -> Dict[str, Any]:
        """Get configuration (mock)"""
        return self.config.copy()
    
    def update_config(self, config: Dict[str, Any]) -> bool:
        """Update configuration (mock)"""
        self.config.update(config)
        self.save_mock_data()
        return True
    
    def authorize_ip(self, ip: str, timeout_ms: Optional[int] = None) -> bool:
        """Authorize an IP address (mock)"""
        self.authorized_ips[ip] = {
            'authorized_time': int(time.time() * 1000),
            'timeout_ms': timeout_ms or self.config['timeout_ms'],
            'expires_at': int((time.time() + (timeout_ms or self.config['timeout_ms']) / 1000) * 1000)
        }
        self.counters['authorized_count'] = len(self.authorized_ips)
        self.counters['valid_knocksd'] += 1
        self.save_mock_data()
        return True
    
    def revoke_ip(self, ip: str) -> bool:
        """Revoke IP authorization (mock)"""
        if ip in self.authorized_ips:
            del self.authorized_ips[ip]
            self.counters['authorized_count'] = len(self.authorized_ips)
            self.save_mock_data()
            return True
        return False
    
    def get_authorized_ips(self) -> Dict[str, Any]:
        """Get all authorized IPs (mock)"""
        # Filter expired IPs
        current_time = int(time.time() * 1000)
        active_ips = {}
        for ip, data in self.authorized_ips.items():
            if data['expires_at'] > current_time:
                active_ips[ip] = data
        
        return {
            'authorized_ips': active_ips,
            'count': len(active_ips),
            'total': len(self.authorized_ips)
        }
    
    def get_counters(self) -> Dict[str, Any]:
        """Get system counters (mock)"""
        return self.counters.copy()
    
    def get_logs(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get system logs (mock)"""
        return [
            {
                'timestamp': int(time.time() * 1000),
                'severity': 'INFO',
                'message': 'Admin panel running in demo mode (mock BPF maps)',
                'ip': '127.0.0.1',
                'port': 5000
            }
        ]
    
    def send_knock_packet(self, target_ip: str, knock_port: int, hmac_key: str) -> Dict[str, Any]:
        """Simulate sending knock packet (mock)"""
        # Simulate successful knock
        self.counters['total_knocksd'] += 1
        self.counters['valid_knocksd'] += 1
        self.save_mock_data()
        
        return {
            'success': True,
            'message': 'Knock packet sent (simulated)',
            'target_ip': target_ip,
            'knock_port': knock_port,
            'timestamp': int(time.time() * 1000),
            'note': 'Demo mode - packet not actually sent'
        }
    
    def test_connectivity(self, target_ip: str, test_port: int) -> Dict[str, Any]:
        """Test connectivity (mock)"""
        return {
            'reachable': True,
            'target_ip': target_ip,
            'test_port': test_port,
            'response_time_ms': 5,
            'note': 'Demo mode - not actually tested'
        }
    
    def reload_config(self) -> Dict[str, Any]:
        """Reload configuration from maps (mock)"""
        self.load_mock_data()
        return {'success': True, 'message': 'Config reloaded from mock storage'}

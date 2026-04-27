"""Mock BPF map accessor for development and tests."""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

class MockBPFMapAccessor:
    """Mock BPF map accessor that simulates the knock system without real BPF maps"""
    
    def __init__(self):
        self.mock_data_file = Path("/tmp/knock_admin_mock.json")
        self.log_path = "/tmp/knockd-admin-mock.log"
        self.daemon_running = False
        self.authorized_ips = {}
        self.config = {
            'ifname': 'eth0',
            'users_file': '',
            'pin_dir': '/sys/fs/bpf/knock_gate',
            'knock_port': 9000,
            'protected_ports': [22, 443, 8080],
            'timeout_ms': 5000,
            'bind_window_ms': 15000,
            'replay_window_ms': 30000,
            'duration_sec': 86400,
            'hmac_key': '0' * 64
        }
        self.counters = {
            'knock_seen': 0,
            'knock_short': 0,
            'knock_valid': 0,
            'replay_drop': 0,
            'protected_drop': 0,
            'protected_pass': 0,
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
                    self.daemon_running = data.get('daemon_running', self.daemon_running)
            except Exception:
                pass
    
    def save_mock_data(self):
        """Save mock data to file"""
        try:
            with open(self.mock_data_file, 'w') as f:
                json.dump({
                    'ips': self.authorized_ips,
                    'config': self.config,
                    'counters': self.counters,
                    'daemon_running': self.daemon_running,
                }, f, indent=2)
        except Exception:
            pass

    def _build_ip_info(self, ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
        now_sec = int(time.time())
        expires_sec = int(data.get('expires_at', 0) / 1000)
        ttl_sec = max(0, expires_sec - now_sec)
        return {
            'ip': ip,
            'expires_ns': int(data.get('expires_at', 0) * 1_000_000),
            'ttl_seconds': ttl_sec,
            'authorized': ttl_sec > 0,
        }

    def get_daemon_status(self) -> Dict[str, Any]:
        return {
            'running': self.daemon_running,
            'pids': [99999] if self.daemon_running else [],
            'binary': 'mock-knockd',
            'log_path': self.log_path,
        }

    def start_daemon(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if config:
            self.config.update(config)
        self.daemon_running = True
        self.save_mock_data()
        return {
            'success': True,
            'message': 'knockd started (mock)',
            'pid': 99999,
            'config': self.config.copy(),
        }

    def stop_daemon(self) -> Dict[str, Any]:
        was_running = self.daemon_running
        self.daemon_running = False
        self.save_mock_data()
        return {
            'success': True,
            'message': 'knockd stopped (mock)',
            'stopped': 1 if was_running else 0,
            'errors': [],
        }

    def restart_daemon(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        stop = self.stop_daemon()
        start = self.start_daemon(config)
        return {
            'success': True,
            'stop': stop,
            'start': start,
        }
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get system status (mock)"""
        daemon = self.get_daemon_status()
        return {
            'knockd_running': daemon['running'],
            'xdp_enabled': True,
            'maps_accessible': True,
            'daemon': daemon,
            'system_status': 'ACTIVE (MOCK)' if daemon['running'] else 'INACTIVE (MOCK)',
            'timestamp': int(time.time() * 1000),
            'note': 'Demo mode - using mock data instead of real BPF maps'
        }

    def get_auth_capabilities(self) -> Dict[str, Any]:
        return {
            'mode': 'mock',
            'manual_authorize_supported': True,
            'manual_revoke_supported': True,
        }
    
    def get_config(self) -> Dict[str, Any]:
        """Get configuration (mock)"""
        cfg = self.config.copy()
        cfg['protected_count'] = len(cfg.get('protected_ports', []))
        return cfg
    
    def update_config(self, config: Dict[str, Any], restart_daemon: bool = False) -> Dict[str, Any]:
        """Update configuration (mock)"""
        self.config.update(config)
        self.save_mock_data()
        result = {
            'success': True,
            'message': 'Configuration updated (mock)',
            'config': self.get_config(),
        }
        if restart_daemon:
            result['daemon'] = self.restart_daemon(self.config)
        return result
    
    def authorize_ip(self, ip: str, timeout_ms: Optional[int] = None) -> Dict[str, Any]:
        """Authorize an IP address (mock)"""
        self.authorized_ips[ip] = {
            'authorized_time': int(time.time() * 1000),
            'timeout_ms': timeout_ms or self.config['timeout_ms'],
            'expires_at': int((time.time() + (timeout_ms or self.config['timeout_ms']) / 1000) * 1000)
        }
        self.counters['authorized_count'] = len(self.authorized_ips)
        self.counters['knock_valid'] += 1
        self.save_mock_data()
        return {
            'success': True,
            'message': f'IP {ip} authorized',
            'ip': ip,
            'expires_ns': int(self.authorized_ips[ip]['expires_at'] * 1_000_000),
        }
    
    def revoke_ip(self, ip: str) -> Dict[str, Any]:
        """Revoke IP authorization (mock)"""
        if ip in self.authorized_ips:
            del self.authorized_ips[ip]
            self.counters['authorized_count'] = len(self.authorized_ips)
            self.save_mock_data()
            return {'success': True, 'message': f'IP {ip} revoked', 'ip': ip}
        return {'success': False, 'error': f'IP {ip} not found'}
    
    def get_authorized_ips(self) -> List[Dict[str, Any]]:
        """Get all authorized IPs (mock)"""
        # Filter expired IPs
        current_time = int(time.time() * 1000)
        valid_ips: List[Dict[str, Any]] = []
        for ip, data in self.authorized_ips.items():
            if data['expires_at'] > current_time:
                valid_ips.append(self._build_ip_info(ip, data))

        return sorted(valid_ips, key=lambda item: item['ttl_seconds'], reverse=True)

    def get_debug_counters(self) -> Dict[str, Any]:
        """Get debug counters (mock)"""
        counters = self.counters.copy()
        counters['total_packets'] = counters.get('knock_seen', 0)
        counters['valid_percentage'] = (
            (counters.get('knock_valid', 0) / max(1, counters.get('knock_seen', 0))) * 100
        )
        return counters

    def get_last_knock_snapshot(self) -> Optional[Dict[str, Any]]:
        return None

    def get_network_interfaces(self) -> List[Dict[str, str]]:
        return [{'name': 'eth0', 'index': '1'}, {'name': 'lo', 'index': '2'}]

    def get_system_logs(self, lines: int = 100) -> List[str]:
        return [
            f'{int(time.time() * 1000)} mock: admin panel running in demo mode',
            f'{int(time.time() * 1000)} mock: requested {lines} log lines',
        ]
    
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
        self.counters['knock_seen'] += 1
        self.counters['knock_valid'] += 1
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

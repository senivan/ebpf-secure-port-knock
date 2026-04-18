import os
import struct
import ctypes
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import subprocess
import re
import time

class BPFMapAccessor:
    """Access and manage eBPF maps for the knock system"""
    
    def __init__(self, bpf_path: str = "/sys/fs/bpf/knock", knockd_bin: str = None):
        self.bpf_path = Path(bpf_path)
        self.knockd_bin = knockd_bin or "/usr/local/bin/knockd"
        self.config_map = None
        self.auth_map = None
        self.counters_map = None
        self.last_knock = None
        
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        try:
            knockd_running = self._is_knockd_running()
            xdp_enabled = self._is_xdp_attached()
            maps_accessible = self._are_maps_accessible()
            
            return {
                'knockd_running': knockd_running,
                'xdp_enabled': xdp_enabled,
                'maps_accessible': maps_accessible,
                'system_status': 'ACTIVE' if (knockd_running and xdp_enabled) else 'INACTIVE',
                'timestamp': int(time.time() * 1000)
            }
        except Exception as e:
            return {'error': str(e), 'system_status': 'ERROR'}
    
    def _is_knockd_running(self) -> bool:
        """Check if knockd daemon is running"""
        try:
            result = subprocess.run(['pgrep', '-f', 'knockd'], 
                                    capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _is_xdp_attached(self) -> bool:
        """Check if XDP program is attached"""
        try:
            result = subprocess.run(['ip', 'link'], 
                                    capture_output=True, text=True, timeout=5)
            return 'xdp' in result.stdout
        except Exception:
            return False
    
    def _are_maps_accessible(self) -> bool:
        """Check if BPF maps are accessible"""
        config_map = self.bpf_path / "config_map"
        auth_map = self.bpf_path / "auth_map"
        return config_map.exists() and auth_map.exists()
    
    def get_config(self) -> Dict[str, Any]:
        """Read current configuration from BPF map"""
        try:
            config_map = self.bpf_path / "config_map"
            if not config_map.exists():
                return {'error': 'Config map not found'}
            
            with open(config_map, 'rb') as f:
                data = f.read(64)  # knock_config struct size
            
            # Parse configuration
            knock_port, protected_count = struct.unpack_from('HH', data, 0)
            timeout_ms = struct.unpack_from('I', data, 4)[0]
            
            protected_ports = []
            for i in range(protected_count):
                offset = 8 + (i * 2)
                port = struct.unpack_from('H', data, offset)[0]
                if port > 0:
                    protected_ports.append(port)
            
            hmac_key_offset = 8 + 32  # After protected_ports array
            hmac_key = data[hmac_key_offset:hmac_key_offset+32]
            
            return {
                'knock_port': knock_port,
                'protected_ports': protected_ports,
                'timeout_ms': timeout_ms,
                'hmac_key': hmac_key.hex(),
                'protected_count': len(protected_ports)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_authorized_ips(self) -> List[Dict[str, Any]]:
        """Get list of currently authorized IP addresses"""
        try:
            auth_map = self.bpf_path / "auth_map"
            if not auth_map.exists():
                return []
            
            authorized_ips = []
            with open(auth_map, 'rb') as f:
                while True:
                    key = f.read(4)  # uint32 IP
                    if not key:
                        break
                    value = f.read(8)  # uint64 timestamp
                    
                    if len(key) == 4 and len(value) == 8:
                        ip_int = struct.unpack('I', key)[0]
                        expires_ns = struct.unpack('Q', value)[0]
                        
                        # Convert to IP string
                        ip_str = '.'.join(str((ip_int >> (i*8)) & 0xff) 
                                         for i in range(4))
                        
                        expires_sec = expires_ns // 1_000_000_000
                        ttl_sec = max(0, expires_sec - int(time.time()))
                        
                        authorized_ips.append({
                            'ip': ip_str,
                            'ip_int': ip_int,
                            'expires_ns': expires_ns,
                            'ttl_seconds': ttl_sec,
                            'authorized': ttl_sec > 0
                        })
            
            return sorted(authorized_ips, key=lambda x: x['ttl_seconds'], 
                         reverse=True)
        except Exception as e:
            return [{'error': str(e)}]
    
    def get_debug_counters(self) -> Dict[str, Any]:
        """Get debug counters from kernel"""
        try:
            counters_map = self.bpf_path / "counters_map"
            if not counters_map.exists():
                return {'error': 'Counters map not found'}
            
            with open(counters_map, 'rb') as f:
                data = f.read(64)  # 8 uint64 counters
            
            counters = struct.unpack('8Q', data)
            
            return {
                'knock_seen': counters[0],
                'knock_short': counters[1],
                'knock_valid': counters[2],
                'replay_drop': counters[3],
                'protected_drop': counters[4],
                'protected_pass': counters[5],
                'total_packets': counters[0],
                'valid_percentage': (counters[2] / max(1, counters[0])) * 100 
                    if counters[0] > 0 else 0
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_last_knock_snapshot(self) -> Optional[Dict[str, Any]]:
        """Get last saw knock packet snapshot"""
        try:
            snapshot_map = self.bpf_path / "knock_snapshot"
            if not snapshot_map.exists():
                return None
            
            with open(snapshot_map, 'rb') as f:
                data = f.read(20)  # debug_knock_snapshot struct
            
            if len(data) < 20:
                return None
            
            magic, timestamp_sec, nonce, sig0, sig1, sig2, sig3 = struct.unpack(
                'IIIIIII', data)
            
            return {
                'magic': hex(magic),
                'timestamp_sec': timestamp_sec,
                'nonce': nonce,
                'signature': [hex(sig0), hex(sig1), hex(sig2), hex(sig3)],
                'captured_at': int(time.time() * 1000)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def authorize_ip(self, ip: str, duration_ms: int = 5000) -> Dict[str, Any]:
        """Manually authorize an IP address"""
        try:
            auth_map = self.bpf_path / "auth_map"
            if not auth_map.exists():
                return {'success': False, 'error': 'Auth map not found'}
            
            # Convert IP string to integer
            parts = ip.split('.')
            ip_int = sum(int(part) << (i*8) for i, part in enumerate(reversed(parts)))
            
            expires_ns = int((time.time() + duration_ms/1000) * 1_000_000_000)
            
            with open(auth_map, 'r+b') as f:
                key = struct.pack('I', ip_int)
                value = struct.pack('Q', expires_ns)
                f.write(key)
                f.write(value)
            
            return {
                'success': True,
                'message': f'IP {ip} authorized for {duration_ms}ms',
                'ip': ip,
                'expires_ns': expires_ns
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def revoke_ip(self, ip: str) -> Dict[str, Any]:
        """Revoke authorization for an IP"""
        try:
            auth_map = self.bpf_path / "auth_map"
            if not auth_map.exists():
                return {'success': False, 'error': 'Auth map not found'}
            
            parts = ip.split('.')
            ip_int = sum(int(part) << (i*8) for i, part in enumerate(reversed(parts)))
            
            # Set expires_ns to 0 (expired)
            with open(auth_map, 'r+b') as f:
                key = struct.pack('I', ip_int)
                value = struct.pack('Q', 0)
                f.write(key)
                f.write(value)
            
            return {
                'success': True,
                'message': f'IP {ip} revoked',
                'ip': ip
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get available network interfaces"""
        try:
            result = subprocess.run(['ip', 'link', 'show'], 
                                    capture_output=True, text=True, timeout=5)
            interfaces = []
            
            for line in result.stdout.split('\n'):
                match = re.match(r'^(\d+):\s+(\w+):', line)
                if match:
                    interfaces.append({
                        'name': match.group(2),
                        'index': match.group(1)
                    })
            
            return interfaces
        except Exception as e:
            return [{'error': str(e)}]
    
    def get_system_logs(self, lines: int = 100) -> List[str]:
        """Get system logs related to eBPF"""
        try:
            result = subprocess.run(['sudo', 'journalctl', '-u', 'knock', '-n', str(lines)], 
                                    capture_output=True, text=True, timeout=5)
            return result.stdout.split('\n')
        except Exception:
            # Fallback to kernel logs
            try:
                result = subprocess.run(['dmesg'], 
                                        capture_output=True, text=True, timeout=5)
                return result.stdout.split('\n')[-lines:]
            except Exception as e:
                return [f'Error getting logs: {str(e)}']

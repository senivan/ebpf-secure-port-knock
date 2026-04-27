import ctypes
import errno
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4

SYS_BPF_BY_ARCH = {
    "x86_64": 321,
    "amd64": 321,
    "aarch64": 280,
    "arm64": 280,
}

LIVE_MAP_NAMES = (
    "config_map",
    "active_session_map",
    "session_index_map",
    "stats_map",
    "debug_knock_map",
)

COUNTER_FIELDS = (
    "knock_seen",
    "knock_short",
    "knock_valid",
    "knock_deauth",
    "replay_drop",
    "bind_drop",
    "session_timeout_drop",
    "deauth_miss",
    "unknown_user",
    "key_mismatch",
    "grace_key_used",
    "knock_rate_drop",
    "session_limit_drop",
    "map_update_fail",
    "protected_drop",
    "protected_pass",
)


class BPFAttrMapElem(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value_or_next_key", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


class KnockConfig(ctypes.Structure):
    _fields_ = [
        ("knock_port", ctypes.c_uint16),
        ("protected_count", ctypes.c_uint16),
        ("protected_ports", ctypes.c_uint16 * 16),
        ("timeout_ms", ctypes.c_uint32),
        ("bind_window_ms", ctypes.c_uint32),
        ("replay_window_ms", ctypes.c_uint32),
        ("hmac_key", ctypes.c_ubyte * 32),
    ]


class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("l4_proto", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]


class ActiveSessionState(ctypes.Structure):
    _fields_ = [
        ("session_id_hi", ctypes.c_uint32),
        ("session_id_lo", ctypes.c_uint32),
        ("expires_at_ns", ctypes.c_uint64),
        ("deleting", ctypes.c_uint8),
    ]


class SessionLookupKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("session_id_hi", ctypes.c_uint32),
        ("session_id_lo", ctypes.c_uint32),
    ]


class DebugCounters(ctypes.Structure):
    _fields_ = [(field, ctypes.c_uint64) for field in COUNTER_FIELDS]


class DebugKnockSnapshot(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("timestamp_sec", ctypes.c_uint32),
        ("nonce", ctypes.c_uint32),
        ("packet_type", ctypes.c_uint32),
        ("session_id_hi", ctypes.c_uint32),
        ("session_id_lo", ctypes.c_uint32),
        ("sig0", ctypes.c_uint32),
        ("sig1", ctypes.c_uint32),
        ("sig2", ctypes.c_uint32),
        ("sig3", ctypes.c_uint32),
    ]

class BPFMapAccessor:
    """Access and manage eBPF maps for the knock system"""
    
    def __init__(
        self,
        bpf_path: str = "/sys/fs/bpf/knock_gate",
        knockd_bin: str = "/home/user/ebpf-secure-port-knock/build/knockd",
        config_store_path: str = "/tmp/knock_admin_config.json",
        daemon_log_path: str = "/tmp/knockd-admin.log",
        use_sudo: bool = True,
        default_ifname: str = "eth0",
        default_users_file: str = "",
        default_pin_dir: str = "/sys/fs/bpf/knock_gate",
    ):
        self.bpf_path = Path(bpf_path)
        self.knockd_bin = knockd_bin
        self.config_store_path = Path(config_store_path)
        self.daemon_log_path = Path(daemon_log_path)
        self.use_sudo = use_sudo
        self.default_ifname = default_ifname
        self.default_users_file = default_users_file
        self.default_pin_dir = default_pin_dir

        self.default_config = {
            "ifname": default_ifname,
            "users_file": default_users_file,
            "pin_dir": default_pin_dir,
            "knock_port": 40000,
            "protected_ports": [22],
            "timeout_ms": 5000,
            "bind_window_ms": 15000,
            "replay_window_ms": 30000,
            "duration_sec": 86400,
            "hmac_key": "",
        }
        self.last_knock: Optional[Dict[str, Any]] = None
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._libc.syscall.restype = ctypes.c_long
        self._sys_bpf = SYS_BPF_BY_ARCH.get(platform.machine().lower())

    def _run_cmd(self, args: List[str], timeout: int = 8) -> subprocess.CompletedProcess:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

    def _resolve_knockd_bin(self) -> Optional[str]:
        candidate = Path(self.knockd_bin)
        if candidate.exists():
            return str(candidate)

        resolved = shutil.which("knockd")
        return resolved

    def _build_cmd(self, args: List[str], sudo: Optional[bool] = None) -> List[str]:
        cmd = list(args)
        if sudo is None:
            sudo = self.use_sudo
        if sudo:
            cmd = ["sudo", *cmd]
        return cmd

    def _load_local_config(self) -> Dict[str, Any]:
        cfg = dict(self.default_config)
        if self.config_store_path.exists():
            try:
                with open(self.config_store_path, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                if isinstance(data, dict):
                    cfg.update(data)
            except Exception:
                pass
        return cfg

    def _save_local_config(self, config: Dict[str, Any]) -> None:
        self.config_store_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_store_path, "w", encoding="utf-8") as fp:
            json.dump(config, fp, indent=2, sort_keys=True)

    def _validate_config(self, config: Dict[str, Any]) -> Optional[str]:
        required = ["knock_port", "protected_ports", "timeout_ms"]
        missing = [field for field in required if field not in config]
        if missing:
            return f"Missing fields: {missing}"

        knock_port = config.get("knock_port")
        if not isinstance(knock_port, int) or knock_port < 1 or knock_port > 65535:
            return "Invalid knock_port"

        protected_ports = config.get("protected_ports")
        if not isinstance(protected_ports, list) or not protected_ports:
            return "protected_ports must be a non-empty list"
        if any((not isinstance(p, int) or p < 1 or p > 65535) for p in protected_ports):
            return "protected_ports contains invalid port values"

        timeout_ms = config.get("timeout_ms")
        if not isinstance(timeout_ms, int) or timeout_ms <= 0:
            return "Invalid timeout_ms"

        hmac_key = config.get("hmac_key", "")
        users_file = config.get("users_file", "")
        if hmac_key:
            if not isinstance(hmac_key, str) or len(hmac_key) != 64:
                return "hmac_key must be exactly 64 hex characters"
            try:
                int(hmac_key, 16)
            except ValueError:
                return "hmac_key must be valid hexadecimal"
        elif not users_file:
            return "Either hmac_key or users_file must be configured"

        return None

    def _get_knockd_pids(self) -> List[int]:
        try:
            result = self._run_cmd(["pgrep", "-f", r"knockd\s+daemon"]) 
            if result.returncode != 0:
                return []
            pids = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.isdigit():
                    pids.append(int(line))
            return pids
        except Exception:
            return []

    def get_daemon_status(self) -> Dict[str, Any]:
        pids = self._get_knockd_pids()
        running = len(pids) > 0
        return {
            "running": running,
            "pids": pids,
            "binary": self.knockd_bin,
            "log_path": str(self.daemon_log_path),
        }

    def start_daemon(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        cfg = self._load_local_config()
        if config:
            cfg.update(config)

        err = self._validate_config(cfg)
        if err:
            return {"success": False, "error": err}

        knockd_bin = self._resolve_knockd_bin()
        if not knockd_bin:
            return {"success": False, "error": "knockd binary not found"}

        if self.get_daemon_status().get("running"):
            return {"success": False, "error": "knockd is already running"}

        cmd = [
            knockd_bin,
            "daemon",
            "--ifname",
            cfg.get("ifname", self.default_ifname),
            "--protect",
            ",".join(str(p) for p in cfg["protected_ports"]),
            "--knock-port",
            str(cfg["knock_port"]),
            "--timeout-ms",
            str(cfg["timeout_ms"]),
            "--bind-window-ms",
            str(cfg.get("bind_window_ms", 15000)),
            "--replay-window-ms",
            str(cfg.get("replay_window_ms", 30000)),
            "--duration-sec",
            str(cfg.get("duration_sec", 86400)),
            "--pin-dir",
            cfg.get("pin_dir", self.default_pin_dir),
        ]

        users_file = cfg.get("users_file", "")
        hmac_key = cfg.get("hmac_key", "")
        if users_file:
            cmd.extend(["--users-file", users_file])
        elif hmac_key:
            cmd.extend(["--hmac-key", hmac_key])

        cmd = self._build_cmd(cmd)

        try:
            self.daemon_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.daemon_log_path, "a", encoding="utf-8") as log_fp:
                proc = subprocess.Popen(  # nosec B603
                    cmd,
                    stdout=log_fp,
                    stderr=log_fp,
                    start_new_session=True,
                )

            time.sleep(0.3)
            if proc.poll() is not None:
                return {
                    "success": False,
                    "error": "knockd failed to start",
                    "return_code": proc.returncode,
                }

            self._save_local_config(cfg)
            return {
                "success": True,
                "message": "knockd started",
                "pid": proc.pid,
                "config": cfg,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop_daemon(self) -> Dict[str, Any]:
        pids = self._get_knockd_pids()
        if not pids:
            return {"success": True, "message": "knockd already stopped", "stopped": 0}

        stopped = 0
        errors: List[str] = []
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
                stopped += 1
            except OSError as e:
                errors.append(f"pid {pid}: {e}")

        time.sleep(0.2)
        return {
            "success": len(errors) == 0,
            "message": f"Stopped {stopped} process(es)",
            "stopped": stopped,
            "errors": errors,
        }

    def restart_daemon(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        stop = self.stop_daemon()
        start = self.start_daemon(config=config)
        return {
            "success": stop.get("success", False) and start.get("success", False),
            "stop": stop,
            "start": start,
        }

    def update_config(self, config_update: Dict[str, Any], restart_daemon: bool = False) -> Dict[str, Any]:
        cfg = self._load_local_config()
        cfg.update(config_update)

        err = self._validate_config(cfg)
        if err:
            return {"success": False, "error": err}

        self._save_local_config(cfg)

        result: Dict[str, Any] = {
            "success": True,
            "message": "Configuration updated",
            "config": cfg,
        }

        if restart_daemon:
            daemon_result = self.restart_daemon(config=cfg)
            result["daemon"] = daemon_result
            if not daemon_result.get("success"):
                result["success"] = False
                result["error"] = "Configuration saved, but daemon restart failed"

        return result
        
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        try:
            daemon = self.get_daemon_status()
            knockd_running = daemon.get("running", False)
            xdp_enabled = self._is_xdp_attached()
            maps_accessible = self._are_maps_accessible()
            
            return {
                'knockd_running': knockd_running,
                'xdp_enabled': xdp_enabled,
                'maps_accessible': maps_accessible,
                'daemon': daemon,
                'system_status': 'ACTIVE' if (knockd_running and xdp_enabled) else 'INACTIVE',
                'timestamp': int(time.time() * 1000)
            }
        except Exception as e:
            return {'error': str(e), 'system_status': 'ERROR'}
    
    def _is_knockd_running(self) -> bool:
        """Check if knockd daemon is running"""
        return self.get_daemon_status().get("running", False)
    
    def _is_xdp_attached(self) -> bool:
        """Check if XDP program is attached"""
        try:
            result = subprocess.run(['ip', 'link'], 
                                    capture_output=True, text=True, timeout=5)
            return 'xdp' in result.stdout
        except Exception:
            return False

    def get_auth_capabilities(self) -> Dict[str, Any]:
        return {
            "mode": "live",
            "manual_authorize_supported": False,
            "manual_revoke_supported": True,
        }

    def _require_bpf_syscall(self) -> int:
        if self._sys_bpf is None:
            raise OSError(errno.ENOSYS, f"unsupported architecture for bpf syscall: {platform.machine()}")
        return self._sys_bpf

    def _bpf_syscall(self, cmd: int, attr: BPFAttrMapElem) -> None:
        sys_bpf = self._require_bpf_syscall()
        result = self._libc.syscall(sys_bpf, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
        if result != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))

    def _map_path(self, map_name: str) -> Path:
        return self.bpf_path / map_name

    def _open_map_fd(self, map_name: str) -> int:
        return os.open(self._map_path(map_name), os.O_RDWR | getattr(os, "O_CLOEXEC", 0))

    def _lookup_map_value(self, map_fd: int, key: Any, value_type: Any) -> Any:
        value = value_type()
        attr = BPFAttrMapElem(
            map_fd=map_fd,
            key=ctypes.addressof(key),
            value_or_next_key=ctypes.addressof(value),
            flags=0,
        )
        self._bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)
        return value

    def _delete_map_value(self, map_fd: int, key: Any) -> None:
        attr = BPFAttrMapElem(
            map_fd=map_fd,
            key=ctypes.addressof(key),
            value_or_next_key=0,
            flags=0,
        )
        self._bpf_syscall(BPF_MAP_DELETE_ELEM, attr)

    def _next_map_key(
        self,
        map_fd: int,
        key_type: Any,
        current_key: Optional[Any],
    ) -> Optional[Any]:
        next_key = key_type()
        attr = BPFAttrMapElem(
            map_fd=map_fd,
            key=ctypes.addressof(current_key) if current_key is not None else 0,
            value_or_next_key=ctypes.addressof(next_key),
            flags=0,
        )
        try:
            self._bpf_syscall(BPF_MAP_GET_NEXT_KEY, attr)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return None
            raise
        return next_key

    def _iter_map_entries(
        self,
        map_name: str,
        key_type: Any,
        value_type: Any,
    ) -> List[Any]:
        entries: List[Any] = []
        map_fd = self._open_map_fd(map_name)
        try:
            current_key = None
            while True:
                next_key = self._next_map_key(map_fd, key_type, current_key)
                if next_key is None:
                    break
                try:
                    value = self._lookup_map_value(map_fd, next_key, value_type)
                    entries.append((next_key, value))
                except OSError as exc:
                    if exc.errno != errno.ENOENT:
                        raise
                current_key = next_key
        finally:
            os.close(map_fd)
        return entries

    def _read_singleton_map(self, map_name: str, value_type: Any) -> Any:
        map_fd = self._open_map_fd(map_name)
        try:
            return self._lookup_map_value(map_fd, ctypes.c_uint32(0), value_type)
        finally:
            os.close(map_fd)

    def _ipv4_from_u32(self, value: int) -> str:
        return socket.inet_ntoa(value.to_bytes(4, "big"))

    def _ipv4_to_u32(self, ip: str) -> int:
        return int.from_bytes(socket.inet_aton(ip), "big")

    def _struct_key_bytes(self, key: ctypes.Structure) -> bytes:
        return ctypes.string_at(ctypes.addressof(key), ctypes.sizeof(key))
    
    def _are_maps_accessible(self) -> bool:
        """Check if BPF maps are accessible"""
        return all(self._map_path(map_name).exists() for map_name in LIVE_MAP_NAMES)
    
    def get_config(self) -> Dict[str, Any]:
        """Read current configuration from local admin state and live maps when available"""
        cfg = self._load_local_config()
        try:
            if self._are_maps_accessible():
                live_cfg = self._read_singleton_map("config_map", KnockConfig)
                protected_count = min(int(live_cfg.protected_count), len(live_cfg.protected_ports))
                cfg.update({
                    "knock_port": int(live_cfg.knock_port),
                    "protected_ports": [int(live_cfg.protected_ports[i]) for i in range(protected_count)],
                    "timeout_ms": int(live_cfg.timeout_ms),
                    "bind_window_ms": int(live_cfg.bind_window_ms),
                    "replay_window_ms": int(live_cfg.replay_window_ms),
                })
                if any(live_cfg.hmac_key):
                    cfg["hmac_key"] = bytes(live_cfg.hmac_key).hex()
        except Exception as exc:
            cfg["live_error"] = str(exc)
        cfg["protected_count"] = len(cfg.get("protected_ports", []))
        return cfg
    
    def get_authorized_ips(self) -> List[Dict[str, Any]]:
        """Get list of currently authorized IP addresses"""
        if not self._are_maps_accessible():
            return []

        now_ns = time.time_ns()
        ip_entries: Dict[str, Dict[str, Any]] = {}
        try:
            for flow, session in self._iter_map_entries("active_session_map", FlowKey, ActiveSessionState):
                ip = self._ipv4_from_u32(int(flow.src_ip))
                expires_ns = int(session.expires_at_ns)
                ttl_seconds = max(0, int((expires_ns - now_ns) / 1_000_000_000))
                entry = ip_entries.setdefault(
                    ip,
                    {
                        "ip": ip,
                        "expires_ns": expires_ns,
                        "ttl_seconds": ttl_seconds,
                        "authorized": False,
                        "session_count": 0,
                    },
                )
                entry["session_count"] += 1
                if expires_ns >= entry["expires_ns"]:
                    entry["expires_ns"] = expires_ns
                    entry["ttl_seconds"] = ttl_seconds
                if not bool(session.deleting) and expires_ns > now_ns:
                    entry["authorized"] = True

            return sorted(
                ip_entries.values(),
                key=lambda item: (item.get("authorized", False), item.get("ttl_seconds", 0)),
                reverse=True,
            )
        except Exception as exc:
            return [{"error": str(exc)}]
    
    def get_debug_counters(self) -> Dict[str, Any]:
        """Get debug counters from kernel"""
        counters = {field: 0 for field in COUNTER_FIELDS}
        try:
            if self._are_maps_accessible():
                live_counters = self._read_singleton_map("stats_map", DebugCounters)
                for field in COUNTER_FIELDS:
                    counters[field] = int(getattr(live_counters, field))
        except Exception as exc:
            counters["error"] = str(exc)

        counters["total_packets"] = counters.get("knock_seen", 0)
        counters["valid_percentage"] = (
            (counters.get("knock_valid", 0) / max(1, counters.get("knock_seen", 0))) * 100
        )
        return counters
    
    def get_last_knock_snapshot(self) -> Optional[Dict[str, Any]]:
        """Get last saw knock packet snapshot"""
        if not self._are_maps_accessible():
            return self.last_knock

        try:
            snap = self._read_singleton_map("debug_knock_map", DebugKnockSnapshot)
        except Exception:
            return self.last_knock

        if int(snap.magic) == 0:
            return self.last_knock

        snapshot = {
            "magic": int(snap.magic),
            "timestamp_sec": int(snap.timestamp_sec),
            "nonce": int(snap.nonce),
            "packet_type": int(snap.packet_type),
            "session_id_hi": int(snap.session_id_hi),
            "session_id_lo": int(snap.session_id_lo),
            "signature": [int(snap.sig0), int(snap.sig1), int(snap.sig2), int(snap.sig3)],
        }
        self.last_knock = snapshot
        return snapshot
    
    def authorize_ip(self, ip: str, duration_ms: int = 5000) -> Dict[str, Any]:
        """Manually authorize an IP address"""
        return {
            "success": False,
            "error": (
                "Manual live authorization is unsupported: the XDP program authorizes "
                "flow-bound sessions, not standalone IP entries"
            ),
            "ip": ip,
            "duration_ms": duration_ms,
            "status_code": 501,
        }
    
    def revoke_ip(self, ip: str) -> Dict[str, Any]:
        """Revoke authorization for an IP"""
        if not self._are_maps_accessible():
            return {"success": False, "error": "Live BPF maps are not accessible", "ip": ip, "status_code": 503}

        target_ip = self._ipv4_to_u32(ip)
        session_keys: Dict[bytes, FlowKey] = {}
        index_keys: Dict[bytes, SessionLookupKey] = {}

        try:
            for lookup_key, flow_key in self._iter_map_entries("session_index_map", SessionLookupKey, FlowKey):
                if int(lookup_key.src_ip) != target_ip:
                    continue
                index_keys[self._struct_key_bytes(lookup_key)] = lookup_key
                session_keys[self._struct_key_bytes(flow_key)] = flow_key

            for flow_key, _session in self._iter_map_entries("active_session_map", FlowKey, ActiveSessionState):
                if int(flow_key.src_ip) == target_ip:
                    session_keys[self._struct_key_bytes(flow_key)] = flow_key

            if not session_keys and not index_keys:
                return {"success": False, "error": f"IP {ip} not found", "ip": ip, "status_code": 404}

            session_fd = self._open_map_fd("active_session_map")
            index_fd = self._open_map_fd("session_index_map")
            try:
                for lookup_key in index_keys.values():
                    try:
                        self._delete_map_value(index_fd, lookup_key)
                    except OSError as exc:
                        if exc.errno != errno.ENOENT:
                            raise
                for flow_key in session_keys.values():
                    try:
                        self._delete_map_value(session_fd, flow_key)
                    except OSError as exc:
                        if exc.errno != errno.ENOENT:
                            raise
            finally:
                os.close(index_fd)
                os.close(session_fd)

            return {
                "success": True,
                "message": f"Revoked {len(session_keys)} active session(s) for {ip}",
                "ip": ip,
                "revoked_sessions": len(session_keys),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc), "ip": ip, "status_code": 500}
    
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
            result = subprocess.run(self._build_cmd(['journalctl', '-u', 'knock', '-n', str(lines)]),
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

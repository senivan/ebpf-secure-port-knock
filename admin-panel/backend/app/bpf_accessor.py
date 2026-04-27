import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    
    def _are_maps_accessible(self) -> bool:
        """Check if BPF maps are accessible"""
        config_map = self.bpf_path / "config_map"
        auth_map = self.bpf_path / "auth_map"
        return config_map.exists() and auth_map.exists()
    
    def get_config(self) -> Dict[str, Any]:
        """Read current configuration from local admin state"""
        cfg = self._load_local_config()
        cfg["protected_count"] = len(cfg.get("protected_ports", []))
        return cfg
    
    def get_authorized_ips(self) -> List[Dict[str, Any]]:
        """Get list of currently authorized IP addresses"""
        return []
    
    def get_debug_counters(self) -> Dict[str, Any]:
        """Get debug counters from kernel"""
        return {
            "knock_seen": 0,
            "knock_short": 0,
            "knock_valid": 0,
            "replay_drop": 0,
            "protected_drop": 0,
            "protected_pass": 0,
            "total_packets": 0,
            "valid_percentage": 0,
        }
    
    def get_last_knock_snapshot(self) -> Optional[Dict[str, Any]]:
        """Get last saw knock packet snapshot"""
        return self.last_knock
    
    def authorize_ip(self, ip: str, duration_ms: int = 5000) -> Dict[str, Any]:
        """Manually authorize an IP address"""
        return {
            "success": False,
            "error": "Manual auth map writes are not implemented in real accessor",
            "ip": ip,
            "duration_ms": duration_ms,
        }
    
    def revoke_ip(self, ip: str) -> Dict[str, Any]:
        """Revoke authorization for an IP"""
        return {
            "success": False,
            "error": "Manual auth map writes are not implemented in real accessor",
            "ip": ip,
        }
    
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

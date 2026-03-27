#!/usr/bin/env bash
set -euo pipefail

KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PROTECTED_PORT=2222
KNOCK_PORT=40000
TIMEOUT_MS=2000

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: run as root (required for XDP attach and raw knock packets)" >&2
    exit 1
fi

cd "$(dirname "$0")/.."

print_section() {
    echo
    echo "==== $1 ===="
}

print_runtime_logs() {
    print_section "knockd log"
    sed -n '1,200p' /tmp/knockd_test.log 2>/dev/null || true

    print_section "knock client log"
    sed -n '1,120p' /tmp/knock_client_test.log 2>/dev/null || true

    print_section "knock replay log"
    sed -n '1,120p' /tmp/knock_client_replay_test.log 2>/dev/null || true

    print_section "bpf stats map"
    bpftool map dump pinned /sys/fs/bpf/knock_gate/stats_map 2>/dev/null || true

    print_section "bpf auth map"
    bpftool map dump pinned /sys/fs/bpf/knock_gate/auth_map 2>/dev/null || true

    print_section "bpf replay map"
    bpftool map dump pinned /sys/fs/bpf/knock_gate/replay_nonce_map 2>/dev/null || true
}

fail_with_logs() {
    echo "fail: $1" >&2
    print_runtime_logs >&2
    exit 1
}

cleanup() {
    set +e
    if [[ -n "${LOADER_PID:-}" ]]; then
        kill "$LOADER_PID" >/dev/null 2>&1 || true
        wait "$LOADER_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${LISTENER_PID:-}" ]]; then
        kill "$LISTENER_PID" >/dev/null 2>&1 || true
        wait "$LISTENER_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

python3 - <<'PY' &
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 2222))
sock.listen(8)

for _ in range(4):
    conn, _ = sock.accept()
    _ = conn.recv(4096)
    conn.sendall(b"ok")
    conn.close()

sock.close()
PY
LISTENER_PID=$!

./build/knockd \
  --ifname lo \
  --hmac-key "$KEY" \
  --protect "$PROTECTED_PORT" \
  --knock-port "$KNOCK_PORT" \
    --timeout-ms "$TIMEOUT_MS" \
    --duration-sec 30 \
  >/tmp/knockd_test.log 2>&1 &
LOADER_PID=$!

sleep 2

echo "[1/3] checking unauthorized access is blocked..."
if python3 - <<'PY'
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.5)
try:
    s.connect(("127.0.0.1", 2222))
    s.sendall(b"unauthorized")
    _ = s.recv(16)
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
then
    fail_with_logs "protected port accepted unauthorized client"
else
    echo "ok: unauthorized client blocked"
fi

echo "[2/3] sending signed knock packet..."
TS="$(cut -d. -f1 /proc/uptime)"
NONCE=424242
./build/knock-client \
    --ifname lo \
  --src-ip 127.0.0.1 \
  --dst-ip 127.0.0.1 \
  --dst-port "$KNOCK_PORT" \
    --timestamp-sec "$TS" \
    --nonce "$NONCE" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_test.log 2>&1

print_section "sent knock"
cat /tmp/knock_client_test.log

sleep 1

echo "[3/3] checking authorized access now succeeds..."
python3 - <<'PY'
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.connect(("127.0.0.1", 2222))
    s.sendall(b"authorized")
    data = s.recv(16)
    s.close()
    if data == b"ok":
        sys.exit(0)
except Exception:
    pass
sys.exit(1)
PY

if [[ $? -ne 0 ]]; then
    fail_with_logs "authorized client did not reach protected port"
fi

echo "ok: authorized client reached protected port"
print_section "state after authorization"
bpftool map dump pinned /sys/fs/bpf/knock_gate/stats_map 2>/dev/null || true

echo "[4/5] waiting for authorization timeout then confirming re-block..."
sleep 3
if python3 - <<'PY'
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.5)
try:
    s.connect(("127.0.0.1", 2222))
    s.sendall(b"after-timeout")
    _ = s.recv(16)
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
then
    fail_with_logs "client still authorized after timeout"
else
    echo "ok: authorization expired and access is blocked again"
fi

echo "[5/5] replaying the same knock should not reauthorize..."
./build/knock-client \
  --ifname lo \
  --src-ip 127.0.0.1 \
  --dst-ip 127.0.0.1 \
  --dst-port "$KNOCK_PORT" \
  --timestamp-sec "$TS" \
  --nonce "$NONCE" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_replay_test.log 2>&1

sleep 1

if python3 - <<'PY'
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.5)
try:
    s.connect(("127.0.0.1", 2222))
    s.sendall(b"replay")
    _ = s.recv(16)
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
then
    fail_with_logs "replayed knock reauthorized client"
else
    echo "ok: replayed knock rejected"
fi

print_section "final runtime logs"
print_runtime_logs

echo "pass: e2e signed knock smoke test passed"

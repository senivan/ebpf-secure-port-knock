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

    print_section "knock deauth log"
    sed -n '1,120p' /tmp/knock_client_deauth_test.log 2>/dev/null || true

    print_section "bpf stats map"
    bpftool map dump pinned /sys/fs/bpf/knock_gate/stats_map 2>/dev/null || true

    print_section "bpf pending auth map"
    bpftool map dump pinned /sys/fs/bpf/knock_gate/pending_auth_map 2>/dev/null || true

    print_section "bpf active session map"
    bpftool map dump pinned /sys/fs/bpf/knock_gate/active_session_map 2>/dev/null || true

    print_section "bpf replay map"
    bpftool map dump pinned /sys/fs/bpf/knock_gate/replay_nonce_map 2>/dev/null || true
}

read_stat_counter() {
    local name="$1"
    bpftool map dump pinned /sys/fs/bpf/knock_gate/stats_map 2>/dev/null | \
        awk -v n="$name" '
            $0 ~ "\"" n "\"" {
                split($0, a, ":");
                gsub(/[^0-9]/, "", a[2]);
                print (a[2] == "" ? 0 : a[2]);
                found=1;
                exit;
            }
            END {
                if (!found) {
                    print 0;
                }
            }
        '
}

active_session_count() {
    local count
    count="$(bpftool map dump pinned /sys/fs/bpf/knock_gate/active_session_map 2>/dev/null | grep -c '"key"' || true)"
    if [[ -z "$count" ]]; then
        echo 0
    else
        echo "$count"
    fi
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

for _ in range(8):
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

echo "[1/9] checking unauthorized access is blocked..."
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

echo "[2/9] sending signed auth packet..."
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

SESSION_ID="$(sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' /tmp/knock_client_test.log | head -n1)"
if [[ -z "$SESSION_ID" ]]; then
        fail_with_logs "unable to parse session_id from auth client output"
fi

print_section "sent knock"
cat /tmp/knock_client_test.log

sleep 1

echo "[3/9] checking authorized access now succeeds..."
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
DEAUTH_MISS_BEFORE_BAD="$(read_stat_counter deauth_miss)"

BAD_SESSION_ID="$(python3 - <<PY
sid = int("$SESSION_ID")
print((sid + 1) & ((1 << 64) - 1))
PY
)"

echo "[4/11] sending signed deauth packet with wrong session id..."
TS_DEAUTH_BAD="$(cut -d. -f1 /proc/uptime)"
NONCE_DEAUTH_BAD=424241
./build/knock-client \
  --ifname lo \
  --src-ip 127.0.0.1 \
  --dst-ip 127.0.0.1 \
  --dst-port "$KNOCK_PORT" \
  --packet-type deauth \
  --session-id "$BAD_SESSION_ID" \
  --timestamp-sec "$TS_DEAUTH_BAD" \
  --nonce "$NONCE_DEAUTH_BAD" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_deauth_bad_test.log 2>&1

echo "[5/11] wrong-session deauth must be ignored by the kernel..."
sleep 1
DEAUTH_MISS_AFTER_BAD="$(read_stat_counter deauth_miss)"
if [[ "$DEAUTH_MISS_AFTER_BAD" -le "$DEAUTH_MISS_BEFORE_BAD" ]]; then
    fail_with_logs "wrong-session deauth did not increment deauth_miss"
fi
if [[ "$(active_session_count)" -lt 1 ]]; then
    fail_with_logs "active session missing after wrong-session deauth"
fi

echo "ok: wrong-session deauth ignored"

echo "[6/11] sending signed deauth packet for the active session..."
TS_DEAUTH="$(cut -d. -f1 /proc/uptime)"
NONCE_DEAUTH=424243
./build/knock-client \
  --ifname lo \
  --src-ip 127.0.0.1 \
  --dst-ip 127.0.0.1 \
  --dst-port "$KNOCK_PORT" \
  --packet-type deauth \
  --session-id "$SESSION_ID" \
  --timestamp-sec "$TS_DEAUTH" \
  --nonce "$NONCE_DEAUTH" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_deauth_test.log 2>&1

echo "[7/11] verifying deauth immediately blocks access..."
sleep 1
if python3 - <<'PY'
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.5)
try:
    s.connect(("127.0.0.1", 2222))
    s.sendall(b"after-deauth")
    _ = s.recv(16)
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
then
    fail_with_logs "client still authorized after deauth"
else
    echo "ok: deauth closed active session"
fi

echo "[8/11] sending fresh auth packet to reopen session for timeout checks..."
TS2="$(cut -d. -f1 /proc/uptime)"
NONCE2=424244
./build/knock-client \
  --ifname lo \
  --src-ip 127.0.0.1 \
  --dst-ip 127.0.0.1 \
  --dst-port "$KNOCK_PORT" \
  --timestamp-sec "$TS2" \
  --nonce "$NONCE2" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_reauth_test.log 2>&1

sleep 1

echo "[9/11] replaying previous-session deauth must not revoke new session..."
TS_DEAUTH_REPLAY="$(cut -d. -f1 /proc/uptime)"
NONCE_DEAUTH_REPLAY=424245
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --packet-type deauth \
    --session-id "$SESSION_ID" \
    --timestamp-sec "$TS_DEAUTH_REPLAY" \
    --nonce "$NONCE_DEAUTH_REPLAY" \
    --hmac-key "$KEY" \
    >/tmp/knock_client_deauth_replay_test.log 2>&1

sleep 1
python3 - <<'PY'
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
        s.connect(("127.0.0.1", 2222))
        s.sendall(b"after-old-session-deauth")
        data = s.recv(16)
        s.close()
        if data == b"ok":
                sys.exit(0)
except Exception:
        pass
sys.exit(1)
PY

if [[ $? -ne 0 ]]; then
        fail_with_logs "old-session deauth revoked new active session"
fi

echo "ok: old-session deauth did not affect new session"

echo "[10/11] validating reauthorized session remains active..."
if [[ "$(active_session_count)" -lt 1 ]]; then
    fail_with_logs "reauthorized active session missing"
fi
echo "ok: reauthorized session is active"

echo "[11/11] waiting for authorization timeout then confirming re-block..."
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

echo "[extra] replaying the original auth knock should not reauthorize..."
./build/knock-client \
  --ifname lo \
  --src-ip 127.0.0.1 \
  --dst-ip 127.0.0.1 \
  --dst-port "$KNOCK_PORT" \
    --session-id "$SESSION_ID" \
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

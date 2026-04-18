#!/usr/bin/env bash
set -euo pipefail

KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PROTECTED_PORT=2222
KNOCK_PORT=40000
TIMEOUT_MS=15000
BIND_WINDOW_MS=3000
FLOW_BASE_PORT=56000
MAX_ACTIVE_PER_SOURCE=32

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: run as root (required for XDP attach and raw knock packets)" >&2
    exit 1
fi

cd "$(dirname "$0")/.."

print_section() {
    echo
    echo "==== $1 ===="
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
    bpftool map dump pinned /sys/fs/bpf/knock_gate/active_session_map 2>/dev/null | grep -c '"key"' || true
}

send_auth_and_bind() {
    local src_port="$1"
    local nonce_auth="$2"
    local nonce_bind="$3"
    local session_log="/tmp/knock_client_pressure_${src_port}_auth.log"
    local bind_log="/tmp/knock_client_pressure_${src_port}_bind.log"
    local session_id

    ./build/knock-client \
        --ifname lo \
        --src-ip 127.0.0.1 \
        --dst-ip 127.0.0.1 \
        --dst-port "$KNOCK_PORT" \
        --user-id 0 \
        --hmac-key "$KEY" \
        --nonce "$nonce_auth" \
        >"$session_log" 2>&1

    session_id="$(sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' "$session_log" | head -n1)"
    if [[ -z "$session_id" ]]; then
        echo "error: unable to parse session id for source port $src_port" >&2
        sed -n '1,120p' "$session_log" >&2 || true
        exit 1
    fi

    ./build/knock-client \
        --ifname lo \
        --src-ip 127.0.0.1 \
        --dst-ip 127.0.0.1 \
        --dst-port "$KNOCK_PORT" \
        --packet-type bind \
        --session-id "$session_id" \
        --src-port "$src_port" \
        --bind-port "$PROTECTED_PORT" \
        --nonce "$nonce_bind" \
        --hmac-key "$KEY" \
        >"$bind_log" 2>&1
}

run_connect_test() {
    local src_port="$1"

    python3 - <<PY
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(1.5)
try:
    s.bind(("127.0.0.1", int(${src_port@Q})))
    s.connect(("127.0.0.1", 2222))
    s.sendall(b"ok")
    data = s.recv(16)
    s.close()
    sys.exit(0 if data == b"ok" else 1)
except Exception:
    sys.exit(1)
PY
}

fail_with_logs() {
    echo "fail: $1" >&2
    print_section "knockd log" >&2
    sed -n '1,220p' /tmp/knockd_pressure_test.log >&2 || true
    print_section "stats map" >&2
    bpftool map dump pinned /sys/fs/bpf/knock_gate/stats_map >&2 || true
    print_section "active session map" >&2
    bpftool map dump pinned /sys/fs/bpf/knock_gate/active_session_map >&2 || true
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
sock.listen(32)

while True:
    conn, _ = sock.accept()
    try:
        _ = conn.recv(4096)
        conn.sendall(b"ok")
    finally:
        conn.close()
PY
LISTENER_PID=$!

./build/knockd daemon \
    --ifname lo \
    --hmac-key "$KEY" \
    --protect "$PROTECTED_PORT" \
    --knock-port "$KNOCK_PORT" \
    --bind-window-ms "$BIND_WINDOW_MS" \
    --timeout-ms "$TIMEOUT_MS" \
    --duration-sec 60 \
    >/tmp/knockd_pressure_test.log 2>&1 &
LOADER_PID=$!

sleep 2

echo "[1/4] establish one valid session..."
send_auth_and_bind "$FLOW_BASE_PORT" 910001 910101
sleep 1
if ! run_connect_test "$FLOW_BASE_PORT"; then
    fail_with_logs "baseline authorized flow failed"
fi
echo "ok: baseline session works"

SESSION_LIMIT_BEFORE="$(read_stat_counter session_limit_drop)"
echo "[2/4] attempt to exceed per-source active-session cap..."
for i in $(seq 1 31); do
    port="$((FLOW_BASE_PORT + i))"
    send_auth_and_bind "$port" "$((920000 + i))" "$((930000 + i))"
done

send_auth_and_bind "$((FLOW_BASE_PORT + 32))" 940001 940101
sleep 1

SESSION_LIMIT_AFTER="$(read_stat_counter session_limit_drop)"
ACTIVE_COUNT="$(active_session_count)"

if [[ "$SESSION_LIMIT_AFTER" -le "$SESSION_LIMIT_BEFORE" ]]; then
    fail_with_logs "session_limit_drop counter did not increment"
fi

if [[ "$ACTIVE_COUNT" -ne "$MAX_ACTIVE_PER_SOURCE" ]]; then
    fail_with_logs "expected $MAX_ACTIVE_PER_SOURCE active sessions, found $ACTIVE_COUNT"
fi

if ! run_connect_test "$FLOW_BASE_PORT"; then
    fail_with_logs "baseline session was lost after cap enforcement"
fi
echo "ok: active-session cap enforced"

KNOCK_RATE_BEFORE="$(read_stat_counter knock_rate_drop)"
echo "[3/4] burst auth knocks to trigger source rate limiting..."
for i in $(seq 1 80); do
    ./build/knock-client \
        --ifname lo \
        --src-ip 127.0.0.1 \
        --dst-ip 127.0.0.1 \
        --dst-port "$KNOCK_PORT" \
        --user-id 0 \
        --nonce "$((950000 + i))" \
        --hmac-key "$KEY" \
        >/tmp/knock_client_pressure_rate_${i}.log 2>&1
done

sleep 1
KNOCK_RATE_AFTER="$(read_stat_counter knock_rate_drop)"

if [[ "$KNOCK_RATE_AFTER" -le "$KNOCK_RATE_BEFORE" ]]; then
    fail_with_logs "knock_rate_drop counter did not increment"
fi

echo "ok: source knock rate limit enforced"
echo "[4/4] pressure test complete"
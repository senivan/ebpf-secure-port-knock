#!/usr/bin/env bash
set -euo pipefail

KEY_USER100="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
KEY_USER200="22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff"
KEY_USER200_V2="33445566778899001122aabbccddeeff33445566778899001122aabbccddeeff"
PROTECTED_PORT=2222
KNOCK_PORT=40000
TIMEOUT_MS=2500
FLOW_SRC_PORT=55300

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "error: run as root (required for XDP attach and raw knock packets)" >&2
        exit 1
    fi
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
    s.sendall(b"probe")
    data = s.recv(16)
    s.close()
    sys.exit(0 if data == b"ok" else 1)
except Exception:
    sys.exit(1)
PY
}

send_bind_knock() {
    local session_id="$1"
    local src_port="$2"
    local nonce="$3"
    local hmac_key="$4"
    local out_file="$5"
    local ts

    ts="$(cut -d. -f1 /proc/uptime)"

    ./build/knock-client \
        --ifname lo \
        --src-ip 127.0.0.1 \
        --dst-ip 127.0.0.1 \
        --dst-port "$KNOCK_PORT" \
        --packet-type bind \
        --session-id "$session_id" \
        --src-port "$src_port" \
        --bind-port "$PROTECTED_PORT" \
        --timestamp-sec "$ts" \
        --nonce "$nonce" \
        --hmac-key "$hmac_key" \
        >"$out_file" 2>&1
}

fail_with_logs() {
    echo "fail: $1" >&2
    echo "==== knockd log ====" >&2
    sed -n '1,260p' /tmp/knockd_user_admin_test.log >&2 || true
    echo "==== users map view ====" >&2
    ./build/knockd list-users >&2 || true
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
    rm -f /tmp/knock_users_admin_test.csv
}
trap cleanup EXIT

require_root
cd "$ROOT_DIR"

cat > /tmp/knock_users_admin_test.csv <<EOF
100,$KEY_USER100
EOF

python3 - <<'PY' &
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 2222))
sock.listen(24)

for _ in range(48):
    conn, _ = sock.accept()
    try:
        _ = conn.recv(4096)
        conn.sendall(b"ok")
    finally:
        conn.close()

sock.close()
PY
LISTENER_PID=$!

./build/knockd daemon \
    --ifname lo \
    --users-file /tmp/knock_users_admin_test.csv \
    --protect "$PROTECTED_PORT" \
    --knock-port "$KNOCK_PORT" \
    --timeout-ms "$TIMEOUT_MS" \
    --duration-sec 60 \
    >/tmp/knockd_user_admin_test.log 2>&1 &
LOADER_PID=$!

sleep 2

echo "[1/11] initial list-users includes only user 100..."
LIST_1="$(./build/knockd list-users 2>/tmp/knock_admin_list_1.err || true)"
if ! grep -q '^100,' <<<"$LIST_1"; then
    fail_with_logs "expected initial user 100 to be present"
fi
if grep -q '^200,' <<<"$LIST_1"; then
    fail_with_logs "user 200 should not exist initially"
fi
echo "ok: initial map contents correct"

echo "[2/11] register-user adds user 200 without restart..."
./build/knockd register-user --user-id 200 --hmac-key "$KEY_USER200" >/tmp/knock_admin_register_200.log 2>&1
if ! grep -q 'registered' /tmp/knock_admin_register_200.log; then
    cat /tmp/knock_admin_register_200.log >&2
    fail_with_logs "register-user did not report success"
fi
echo "ok: user 200 registered live"

echo "[3/11] list-users now contains user 200..."
LIST_2="$(./build/knockd list-users 2>/tmp/knock_admin_list_2.err || true)"
if ! grep -q '^200,' <<<"$LIST_2"; then
    fail_with_logs "user 200 missing after registration"
fi
echo "ok: user 200 visible live"

echo "[4/11] user 200 can authenticate immediately..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 200 \
    --hmac-key "$KEY_USER200" \
    >/tmp/knock_admin_user200_ok.log 2>&1
SESSION_200_A="$(sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' /tmp/knock_admin_user200_ok.log | head -n1)"
if [[ -z "$SESSION_200_A" ]]; then
    fail_with_logs "unable to parse session id for user 200 auth"
fi
send_bind_knock "$SESSION_200_A" "$FLOW_SRC_PORT" 999100 "$KEY_USER200" /tmp/knock_admin_user200_bind.log
sleep 1
if ! run_connect_test "$FLOW_SRC_PORT"; then
    fail_with_logs "user 200 was not authorized after live registration"
fi
echo "ok: live-registered user can authenticate"

sleep 3

echo "[5/11] duplicate register-user fails cleanly..."
if ./build/knockd register-user --user-id 200 --hmac-key "$KEY_USER200" >/tmp/knock_admin_register_dup.log 2>&1; then
    fail_with_logs "duplicate register-user unexpectedly succeeded"
fi
if ! grep -q 'already exists' /tmp/knock_admin_register_dup.log; then
    cat /tmp/knock_admin_register_dup.log >&2
    fail_with_logs "duplicate register failure reason missing"
fi
echo "ok: duplicate registration rejected"

echo "[6/11] rotate-user-key for unknown user fails..."
if ./build/knockd rotate-user-key --user-id 999 --hmac-key "$KEY_USER200_V2" --grace-ms 1000 >/tmp/knock_admin_rotate_missing.log 2>&1; then
    fail_with_logs "rotate unknown user unexpectedly succeeded"
fi
if ! grep -q 'not found' /tmp/knock_admin_rotate_missing.log; then
    cat /tmp/knock_admin_rotate_missing.log >&2
    fail_with_logs "rotate missing-user failure reason missing"
fi
echo "ok: rotate missing user rejected"

echo "[7/11] revoke-user for unknown user fails..."
if ./build/knockd revoke-user --user-id 999 >/tmp/knock_admin_revoke_missing.log 2>&1; then
    fail_with_logs "revoke unknown user unexpectedly succeeded"
fi
echo "ok: revoke missing user rejected"

echo "[8/11] rotate existing user 200 key and authenticate with new key..."
./build/knockd rotate-user-key --user-id 200 --hmac-key "$KEY_USER200_V2" --grace-ms 1000 >/tmp/knock_admin_rotate_200.log 2>&1
if ! grep -q 'rotated' /tmp/knock_admin_rotate_200.log; then
    cat /tmp/knock_admin_rotate_200.log >&2
    fail_with_logs "rotate existing user failed"
fi
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 200 \
    --hmac-key "$KEY_USER200_V2" \
    >/tmp/knock_admin_user200_v2.log 2>&1
SESSION_200_B="$(sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' /tmp/knock_admin_user200_v2.log | head -n1)"
if [[ -z "$SESSION_200_B" ]]; then
    fail_with_logs "unable to parse session id for user 200 rotated auth"
fi
send_bind_knock "$SESSION_200_B" "$FLOW_SRC_PORT" 999101 "$KEY_USER200_V2" /tmp/knock_admin_user200_v2_bind.log
sleep 1
if ! run_connect_test "$FLOW_SRC_PORT"; then
    fail_with_logs "user 200 new key did not authenticate"
fi
echo "ok: rotated key works"

sleep 3

echo "[9/11] revoke existing user 200 succeeds..."
./build/knockd revoke-user --user-id 200 >/tmp/knock_admin_revoke_200.log 2>&1
if ! grep -q 'revoked' /tmp/knock_admin_revoke_200.log; then
    cat /tmp/knock_admin_revoke_200.log >&2
    fail_with_logs "revoke existing user failed"
fi
echo "ok: user 200 revoked"

echo "[10/11] revoked user 200 can no longer authenticate..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 200 \
    --hmac-key "$KEY_USER200_V2" \
    >/tmp/knock_admin_user200_revoked.log 2>&1
sleep 1
if run_connect_test "$FLOW_SRC_PORT"; then
    fail_with_logs "revoked user 200 still gained access"
fi
echo "ok: revoked user blocked"

echo "[11/11] admin feature tests passed"
echo "pass: per-user admin live updates and negative operations"

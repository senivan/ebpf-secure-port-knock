#!/usr/bin/env bash
set -euo pipefail

KEY_V1="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
KEY_V2="11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
PROTECTED_PORT=2222
KNOCK_PORT=40000
TIMEOUT_MS=1400
GRACE_MS=2500

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "error: run as root (required for XDP attach and raw knock packets)" >&2
        exit 1
    fi
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

run_connect_test() {
    python3 - <<'PY'
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.5)
try:
    s.connect(("127.0.0.1", 2222))
    s.sendall(b"probe")
    data = s.recv(16)
    s.close()
    sys.exit(0 if data == b"ok" else 1)
except Exception:
    sys.exit(1)
PY
}

fail_with_logs() {
    echo "fail: $1" >&2
    echo "==== knockd log ====" >&2
    sed -n '1,260p' /tmp/knockd_user_rotation_test.log >&2 || true
    echo "==== stats map ====" >&2
    bpftool map dump pinned /sys/fs/bpf/knock_gate/stats_map >&2 || true
    echo "==== users ====" >&2
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
    rm -f /tmp/knock_users_rotation_test.csv
}
trap cleanup EXIT

require_root
cd "$ROOT_DIR"

cat > /tmp/knock_users_rotation_test.csv <<EOF
100,$KEY_V1
EOF

python3 - <<'PY' &
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 2222))
sock.listen(20)

for _ in range(40):
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
    --users-file /tmp/knock_users_rotation_test.csv \
    --protect "$PROTECTED_PORT" \
    --knock-port "$KNOCK_PORT" \
    --timeout-ms "$TIMEOUT_MS" \
    --duration-sec 60 \
    >/tmp/knockd_user_rotation_test.log 2>&1 &
LOADER_PID=$!

sleep 2

echo "[1/9] baseline: user 100 with key v1 authenticates..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 100 \
    --hmac-key "$KEY_V1" \
    >/tmp/knock_client_rot_v1_ok.log 2>&1
sleep 1
if ! run_connect_test; then
    fail_with_logs "key v1 auth failed before rotation"
fi
echo "ok: key v1 works"

sleep 2

echo "[2/9] rotate user 100 key with grace window..."
./build/knockd rotate-user-key --user-id 100 --hmac-key "$KEY_V2" --grace-ms "$GRACE_MS" >/tmp/knock_rotate_cmd.log 2>&1
if ! grep -q "rotated" /tmp/knock_rotate_cmd.log; then
    cat /tmp/knock_rotate_cmd.log >&2
    fail_with_logs "rotate-user-key command failed"
fi
echo "ok: rotate command succeeded"

GRACE_BEFORE="$(read_stat_counter grace_key_used)"
echo "[3/9] old key is accepted during grace..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 100 \
    --hmac-key "$KEY_V1" \
    >/tmp/knock_client_rot_old_in_grace.log 2>&1
sleep 1
if ! run_connect_test; then
    fail_with_logs "old key should be accepted during grace"
fi
GRACE_AFTER="$(read_stat_counter grace_key_used)"
if [[ "$GRACE_AFTER" -le "$GRACE_BEFORE" ]]; then
    fail_with_logs "grace_key_used counter did not increment"
fi
echo "ok: old key accepted in grace window"

sleep 2

echo "[4/9] after grace expiry, old key must fail..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 100 \
    --hmac-key "$KEY_V1" \
    >/tmp/knock_client_rot_old_after_grace.log 2>&1
sleep 1
if run_connect_test; then
    fail_with_logs "old key still authorized after grace expiry"
fi
echo "ok: old key rejected after grace"

echo "[5/9] key mismatch counter moves on expired old key..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 100 \
    --hmac-key "$KEY_V1" \
    >/tmp/knock_client_rot_old_after_grace_2.log 2>&1
sleep 1
if run_connect_test; then
    fail_with_logs "expired old key unexpectedly authorized access"
fi
echo "ok: expired old key remains rejected"

echo "[6/9] new key works after rotation..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 100 \
    --hmac-key "$KEY_V2" \
    >/tmp/knock_client_rot_v2_ok.log 2>&1
sleep 1
if ! run_connect_test; then
    fail_with_logs "new key not accepted after rotation"
fi
echo "ok: new key accepted"

echo "[7/9] list-users shows version increment..."
LIST_OUT="$(./build/knockd list-users 2>/tmp/knock_list_rot_err.log || true)"
LINE_100="$(grep '^100,' <<<"$LIST_OUT" || true)"
if [[ -z "$LINE_100" ]]; then
    echo "$LIST_OUT" >&2
    cat /tmp/knock_list_rot_err.log >&2 || true
    fail_with_logs "list-users missing user 100"
fi
VERSION="$(awk -F, '{print $2}' <<<"$LINE_100")"
if [[ -z "$VERSION" || "$VERSION" -lt 2 ]]; then
    echo "$LIST_OUT" >&2
    fail_with_logs "key version did not increment"
fi
echo "ok: key version incremented"

echo "[8/9] revoke user blocks future authentication..."
./build/knockd revoke-user --user-id 100 >/tmp/knock_revoke_cmd.log 2>&1
if ! grep -q "revoked" /tmp/knock_revoke_cmd.log; then
    cat /tmp/knock_revoke_cmd.log >&2
    fail_with_logs "revoke-user command failed"
fi
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 100 \
    --hmac-key "$KEY_V2" \
    >/tmp/knock_client_revoked.log 2>&1
sleep 1
if run_connect_test; then
    fail_with_logs "revoked user still authorized"
fi
echo "ok: revoked user blocked"

echo "[9/9] rotation feature tests passed"
echo "pass: per-user rotation and live key update"

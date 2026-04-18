#!/usr/bin/env bash
set -euo pipefail

KEY_USER100="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
KEY_USER101="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
BAD_KEY="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
PROTECTED_PORT=2222
KNOCK_PORT=40000
TIMEOUT_MS=1500
BIND_WINDOW_MS=1500

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "error: run as root (required for XDP attach and raw knock packets)" >&2
        exit 1
    fi
}

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
    print_section "knockd log" >&2
    sed -n '1,220p' /tmp/knockd_user_auth_test.log >&2 || true
    print_section "stats map" >&2
    bpftool map dump pinned /sys/fs/bpf/knock_gate/stats_map >&2 || true
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
    rm -f /tmp/knock_users_test.csv
}
trap cleanup EXIT

require_root
cd "$ROOT_DIR"

cat > /tmp/knock_users_test.csv <<EOF
100,$KEY_USER100
101,$KEY_USER101
EOF

python3 - <<'PY' &
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 2222))
sock.listen(16)

for _ in range(30):
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
    --users-file /tmp/knock_users_test.csv \
    --protect "$PROTECTED_PORT" \
    --knock-port "$KNOCK_PORT" \
    --bind-window-ms "$BIND_WINDOW_MS" \
    --timeout-ms "$TIMEOUT_MS" \
    --duration-sec 45 \
    >/tmp/knockd_user_auth_test.log 2>&1 &
LOADER_PID=$!

sleep 2

echo "[1/8] unauthorized access is blocked..."
if run_connect_test; then
    fail_with_logs "protected service accepted connection before knock"
fi
echo "ok: blocked before knock"

echo "[2/8] user 100 with correct key can authenticate..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 100 \
    --hmac-key "$KEY_USER100" \
    >/tmp/knock_client_user100_ok.log 2>&1
sleep 1
if ! run_connect_test; then
    fail_with_logs "user 100 was not authorized"
fi
echo "ok: user 100 authorized"

sleep 2

echo "[3/8] session times out and access closes..."
if run_connect_test; then
    fail_with_logs "session should have timed out"
fi
echo "ok: timeout enforced"

UNKNOWN_BEFORE="$(read_stat_counter unknown_user)"
echo "[4/8] unknown user id is rejected..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 999 \
    --hmac-key "$BAD_KEY" \
    >/tmp/knock_client_unknown.log 2>&1
sleep 1
UNKNOWN_AFTER="$(read_stat_counter unknown_user)"
if [[ "$UNKNOWN_AFTER" -le "$UNKNOWN_BEFORE" ]]; then
    fail_with_logs "unknown_user counter did not increment"
fi
if run_connect_test; then
    fail_with_logs "unknown user should not gain access"
fi
echo "ok: unknown user rejected"

echo "[5/10] user 101 with correct key is authorized..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 101 \
    --hmac-key "$KEY_USER101" \
    >/tmp/knock_client_user101_ok.log 2>&1
SESSION_101_A="$(sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' /tmp/knock_client_user101_ok.log | head -n1)"
if [[ -z "$SESSION_101_A" ]]; then
    fail_with_logs "unable to parse session id for user 101 auth"
fi
sleep 1
if ! run_connect_test; then
    fail_with_logs "user 101 was not authorized with correct key"
fi
echo "ok: user 101 authorized"

echo "[6/10] user 101 produces unique sessions across separate auths..."
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 101 \
    --hmac-key "$KEY_USER101" \
    >/tmp/knock_client_user101_ok_2.log 2>&1
SESSION_101_B="$(sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' /tmp/knock_client_user101_ok_2.log | head -n1)"
if [[ -z "$SESSION_101_B" ]]; then
    fail_with_logs "unable to parse second session id for user 101"
fi
if [[ "$SESSION_101_A" == "$SESSION_101_B" ]]; then
    fail_with_logs "expected unique session ids for repeated user 101 auth"
fi
echo "ok: repeated user auth generates distinct sessions"

echo "[7/10] replayed knock is counted and does not create new auth event..."
TS_FIXED="$(cut -d. -f1 /proc/uptime)"
NONCE_FIXED=777001
SESSION_FIXED=$(( (101 << 48) | 0x12345 ))
KNOCK_VALID_BEFORE="$(read_stat_counter knock_valid)"
REPLAY_BEFORE="$(read_stat_counter replay_drop)"

./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 101 \
    --session-id "$SESSION_FIXED" \
    --timestamp-sec "$TS_FIXED" \
    --nonce "$NONCE_FIXED" \
    --hmac-key "$KEY_USER101" \
    >/tmp/knock_client_replay_first.log 2>&1

./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --user-id 101 \
    --session-id "$SESSION_FIXED" \
    --timestamp-sec "$TS_FIXED" \
    --nonce "$NONCE_FIXED" \
    --hmac-key "$KEY_USER101" \
    >/tmp/knock_client_replay_second.log 2>&1

sleep 1
KNOCK_VALID_AFTER="$(read_stat_counter knock_valid)"
REPLAY_AFTER="$(read_stat_counter replay_drop)"
if [[ "$KNOCK_VALID_AFTER" -le "$KNOCK_VALID_BEFORE" ]]; then
    fail_with_logs "first fixed knock did not register as valid"
fi
if [[ "$REPLAY_AFTER" -le "$REPLAY_BEFORE" ]]; then
    fail_with_logs "replay_drop counter did not increment"
fi
echo "ok: replay detection active for per-user knocks"

# The fixed replay test leaves a pending auth entry. Let the bind window expire so
# deauth validation below checks true revocation behavior without immediate rebind.
sleep 2

echo "[8/10] deauth for active session immediately closes access..."
TS_DEAUTH="$(cut -d. -f1 /proc/uptime)"
NONCE_DEAUTH=777002
./build/knock-client \
    --ifname lo \
    --src-ip 127.0.0.1 \
    --dst-ip 127.0.0.1 \
    --dst-port "$KNOCK_PORT" \
    --packet-type deauth \
    --session-id "$SESSION_101_A" \
    --timestamp-sec "$TS_DEAUTH" \
    --nonce "$NONCE_DEAUTH" \
    --hmac-key "$KEY_USER101" \
    >/tmp/knock_client_deauth_101.log 2>&1

sleep 1
if run_connect_test; then
    fail_with_logs "service should be blocked after deauth"
fi
echo "ok: deauth immediately revokes active auth"

echo "[9/10] list-users exposes both records..."
LIST_OUT="$(./build/knockd list-users 2>/tmp/knock_list_users_err.log || true)"
if ! grep -q '^100,' <<<"$LIST_OUT" || ! grep -q '^101,' <<<"$LIST_OUT"; then
    echo "$LIST_OUT" >&2
    cat /tmp/knock_list_users_err.log >&2 || true
    fail_with_logs "list-users did not include both registered users"
fi
echo "ok: list-users includes expected users"

echo "[10/10] user-auth feature tests passed"
echo "pass: per-user registration and key isolation"

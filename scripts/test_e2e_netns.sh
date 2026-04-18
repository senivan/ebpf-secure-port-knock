#!/usr/bin/env bash
set -euo pipefail

KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PROTECTED_PORT=2222
KNOCK_PORT=40000
TIMEOUT_MS=3000

CLIENT_NS="knockns-client"
ATTACKER_NS="knockns-attacker"
BR_IF="br-knock"
EDGE_BR_IF="edge-br"
EDGE_IF="edge-if"
CLIENT_BR_IF="client-br"
CLIENT_NS_IF="client-ns"
ATTACKER_BR_IF="attacker-br"
ATTACKER_NS_IF="attacker-ns"

EDGE_IP="10.200.0.1"
CLIENT_IP="10.200.0.2"
ATTACKER_IP="10.200.0.3"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "error: run as root (required for netns, XDP attach, raw packets)" >&2
        exit 1
    fi
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

    ip netns del "$CLIENT_NS" >/dev/null 2>&1 || true
    ip netns del "$ATTACKER_NS" >/dev/null 2>&1 || true

    ip link del "$EDGE_BR_IF" >/dev/null 2>&1 || true
    ip link del "$CLIENT_BR_IF" >/dev/null 2>&1 || true
    ip link del "$ATTACKER_BR_IF" >/dev/null 2>&1 || true
    ip link del "$BR_IF" >/dev/null 2>&1 || true
}

setup_topology() {
    ip link add "$BR_IF" type bridge
    ip link set "$BR_IF" up

    ip link add "$EDGE_BR_IF" type veth peer name "$EDGE_IF"
    ip link set "$EDGE_BR_IF" master "$BR_IF"
    ip link set "$EDGE_BR_IF" up
    ip addr add "$EDGE_IP/24" dev "$EDGE_IF"
    ip link set "$EDGE_IF" up

    ip netns add "$CLIENT_NS"
    ip link add "$CLIENT_BR_IF" type veth peer name "$CLIENT_NS_IF"
    ip link set "$CLIENT_BR_IF" master "$BR_IF"
    ip link set "$CLIENT_BR_IF" up
    ip link set "$CLIENT_NS_IF" netns "$CLIENT_NS"
    ip -n "$CLIENT_NS" link set lo up
    ip -n "$CLIENT_NS" addr add "$CLIENT_IP/24" dev "$CLIENT_NS_IF"
    ip -n "$CLIENT_NS" link set "$CLIENT_NS_IF" up

    ip netns add "$ATTACKER_NS"
    ip link add "$ATTACKER_BR_IF" type veth peer name "$ATTACKER_NS_IF"
    ip link set "$ATTACKER_BR_IF" master "$BR_IF"
    ip link set "$ATTACKER_BR_IF" up
    ip link set "$ATTACKER_NS_IF" netns "$ATTACKER_NS"
    ip -n "$ATTACKER_NS" link set lo up
    ip -n "$ATTACKER_NS" addr add "$ATTACKER_IP/24" dev "$ATTACKER_NS_IF"
    ip -n "$ATTACKER_NS" link set "$ATTACKER_NS_IF" up
}

start_listener() {
    python3 - <<'PY' &
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("10.200.0.1", 2222))
sock.listen(16)

while True:
    conn, _ = sock.accept()
    try:
        _ = conn.recv(4096)
        conn.sendall(b"ok")
    finally:
        conn.close()
PY
    LISTENER_PID=$!
}

run_connect_test() {
    local ns="$1"
    local msg="$2"

    ip netns exec "$ns" python3 - <<PY
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.5)
try:
    s.connect(("10.200.0.1", 2222))
    s.sendall(${msg@Q}.encode())
    data = s.recv(16)
    s.close()
    sys.exit(0 if data == b"ok" else 1)
except Exception:
    sys.exit(1)
PY
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

require_root
trap cleanup EXIT
cd "$ROOT_DIR"
cleanup
setup_topology
start_listener

./build/knockd \
  --ifname "$EDGE_IF" \
  --hmac-key "$KEY" \
  --protect "$PROTECTED_PORT" \
  --knock-port "$KNOCK_PORT" \
  --timeout-ms "$TIMEOUT_MS" \
  --duration-sec 45 \
  >/tmp/knockd_netns_test.log 2>&1 &
LOADER_PID=$!

sleep 2

echo "[1/11] attacker cannot access protected port..."
if run_connect_test "$ATTACKER_NS" "attacker-pre"; then
    echo "fail: attacker unexpectedly reached protected service" >&2
    exit 1
else
    echo "ok: attacker blocked"
fi

echo "[2/11] client cannot access before knock..."
if run_connect_test "$CLIENT_NS" "client-pre"; then
    echo "fail: client unexpectedly reached service before knock" >&2
    exit 1
else
    echo "ok: client blocked before knock"
fi

echo "[3/11] client sends signed auth..."
TS="$(cut -d. -f1 /proc/uptime)"
NONCE=314159
ip netns exec "$CLIENT_NS" "$ROOT_DIR/build/knock-client" \
  --ifname "$CLIENT_NS_IF" \
  --src-ip "$CLIENT_IP" \
  --dst-ip "$EDGE_IP" \
  --dst-port "$KNOCK_PORT" \
  --timestamp-sec "$TS" \
  --nonce "$NONCE" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_netns_test.log 2>&1

SESSION_ID="$(sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' /tmp/knock_client_netns_test.log | head -n1)"
if [[ -z "$SESSION_ID" ]]; then
    echo "fail: unable to parse session_id from netns auth output" >&2
    exit 1
fi

sleep 1

echo "[4/11] client now reaches protected port..."
if run_connect_test "$CLIENT_NS" "client-post"; then
    echo "ok: client authorized"
else
    echo "fail: client could not reach service after valid knock" >&2
    exit 1
fi

echo "[5/11] attacker remains blocked..."
if run_connect_test "$ATTACKER_NS" "attacker-post"; then
    echo "fail: attacker gained access without authorization" >&2
    exit 1
else
    echo "ok: attacker still blocked"
fi

DEAUTH_MISS_BEFORE_BAD="$(read_stat_counter deauth_miss)"

BAD_SESSION_ID="$(python3 - <<PY
sid = int("$SESSION_ID")
print((sid + 1) & ((1 << 64) - 1))
PY
)"

echo "[6/11] client sends signed deauth with wrong session id..."
TS_DEAUTH_BAD="$(cut -d. -f1 /proc/uptime)"
NONCE_DEAUTH_BAD=314158
ip netns exec "$CLIENT_NS" "$ROOT_DIR/build/knock-client" \
    --ifname "$CLIENT_NS_IF" \
    --src-ip "$CLIENT_IP" \
    --dst-ip "$EDGE_IP" \
    --dst-port "$KNOCK_PORT" \
    --packet-type deauth \
    --session-id "$BAD_SESSION_ID" \
    --timestamp-sec "$TS_DEAUTH_BAD" \
    --nonce "$NONCE_DEAUTH_BAD" \
    --hmac-key "$KEY" \
    >/tmp/knock_client_netns_deauth_bad_test.log 2>&1

sleep 1

echo "[7/11] wrong-session deauth must be ignored by the kernel..."
DEAUTH_MISS_AFTER_BAD="$(read_stat_counter deauth_miss)"
if [[ "$DEAUTH_MISS_AFTER_BAD" -le "$DEAUTH_MISS_BEFORE_BAD" ]]; then
    echo "fail: wrong-session deauth did not increment deauth_miss" >&2
        exit 1
fi
echo "ok: wrong-session deauth ignored"

echo "[8/11] client sends signed deauth for current session..."
TS_DEAUTH="$(cut -d. -f1 /proc/uptime)"
NONCE_DEAUTH=314160
ip netns exec "$CLIENT_NS" "$ROOT_DIR/build/knock-client" \
  --ifname "$CLIENT_NS_IF" \
  --src-ip "$CLIENT_IP" \
  --dst-ip "$EDGE_IP" \
  --dst-port "$KNOCK_PORT" \
  --packet-type deauth \
  --session-id "$SESSION_ID" \
  --timestamp-sec "$TS_DEAUTH" \
  --nonce "$NONCE_DEAUTH" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_netns_deauth_test.log 2>&1

sleep 1

echo "[9/11] deauth immediately blocks client..."
if run_connect_test "$CLIENT_NS" "client-deauth"; then
    echo "fail: client still authorized after deauth" >&2
    exit 1
else
    echo "ok: client blocked after deauth"
fi

echo "[10/11] client reauthenticates for timeout fallback check..."
TS2="$(cut -d. -f1 /proc/uptime)"
NONCE2=314161
ip netns exec "$CLIENT_NS" "$ROOT_DIR/build/knock-client" \
  --ifname "$CLIENT_NS_IF" \
  --src-ip "$CLIENT_IP" \
  --dst-ip "$EDGE_IP" \
  --dst-port "$KNOCK_PORT" \
  --timestamp-sec "$TS2" \
  --nonce "$NONCE2" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_netns_reauth_test.log 2>&1

sleep 1
if ! run_connect_test "$CLIENT_NS" "client-reauth"; then
    echo "fail: client could not reach service after reauth" >&2
    exit 1
fi

echo "[11/11] timeout expires and client is blocked again..."
sleep 4
if run_connect_test "$CLIENT_NS" "client-timeout"; then
    echo "fail: client still authorized after timeout" >&2
    exit 1
else
    echo "ok: client blocked after timeout"
fi

echo "pass: netns e2e scenario passed"

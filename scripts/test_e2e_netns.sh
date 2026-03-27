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

echo "[1/6] attacker cannot access protected port..."
if run_connect_test "$ATTACKER_NS" "attacker-pre"; then
    echo "fail: attacker unexpectedly reached protected service" >&2
    exit 1
else
    echo "ok: attacker blocked"
fi

echo "[2/6] client cannot access before knock..."
if run_connect_test "$CLIENT_NS" "client-pre"; then
    echo "fail: client unexpectedly reached service before knock" >&2
    exit 1
else
    echo "ok: client blocked before knock"
fi

echo "[3/6] client sends signed knock..."
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

sleep 1

echo "[4/6] client now reaches protected port..."
if run_connect_test "$CLIENT_NS" "client-post"; then
    echo "ok: client authorized"
else
    echo "fail: client could not reach service after valid knock" >&2
    exit 1
fi

echo "[5/6] attacker remains blocked..."
if run_connect_test "$ATTACKER_NS" "attacker-post"; then
    echo "fail: attacker gained access without authorization" >&2
    exit 1
else
    echo "ok: attacker still blocked"
fi

echo "[6/6] timeout expires and client is blocked again..."
sleep 4
if run_connect_test "$CLIENT_NS" "client-timeout"; then
    echo "fail: client still authorized after timeout" >&2
    exit 1
else
    echo "ok: client blocked after timeout"
fi

echo "pass: netns e2e scenario passed"

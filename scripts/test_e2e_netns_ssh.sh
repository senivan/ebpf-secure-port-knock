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
SSH_TEST_DIR="/etc/ssh/knock-ssh-test-$$"
SSH_HOST_KEY="$SSH_TEST_DIR/ssh_host_ed25519_key"
SSH_CLIENT_KEY="$SSH_TEST_DIR/client_ed25519"
SSH_CFG="$SSH_TEST_DIR/sshd_config"
SSH_LOG="$SSH_TEST_DIR/sshd.log"
SSH_TEST_USER="${SSH_TEST_USER:-}"
SSH_USER_HOME=""
SSH_USER_DIR=""
SSH_USER_AUTH_KEYS=""
SSH_USER_AUTH_KEYS_BACKUP="$SSH_TEST_DIR/original_authorized_keys"
SSH_USER_AUTH_KEYS_EXISTED=0

discover_ssh_user() {
    if [[ -n "$SSH_TEST_USER" ]]; then
        return
    fi

    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        SSH_TEST_USER="${SUDO_USER}"
        return
    fi

    SSH_TEST_USER="$(awk -F: '$3 >= 1000 && $1 != "nobody" { print $1; exit }' /etc/passwd)"
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command not found: $1" >&2
        exit 1
    fi
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "error: run as root (required for netns, XDP attach, and ssh service setup)" >&2
        exit 1
    fi
}

cleanup() {
    set +e

    if [[ -n "${LOADER_PID:-}" ]]; then
        kill "$LOADER_PID" >/dev/null 2>&1 || true
        wait "$LOADER_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${SSHD_PID:-}" ]]; then
        kill "$SSHD_PID" >/dev/null 2>&1 || true
        wait "$SSHD_PID" >/dev/null 2>&1 || true
    fi

    ip netns del "$CLIENT_NS" >/dev/null 2>&1 || true
    ip netns del "$ATTACKER_NS" >/dev/null 2>&1 || true

    ip link del "$EDGE_BR_IF" >/dev/null 2>&1 || true
    ip link del "$CLIENT_BR_IF" >/dev/null 2>&1 || true
    ip link del "$ATTACKER_BR_IF" >/dev/null 2>&1 || true
    ip link del "$BR_IF" >/dev/null 2>&1 || true

    if [[ -n "$SSH_USER_AUTH_KEYS" ]]; then
        if [[ "$SSH_USER_AUTH_KEYS_EXISTED" -eq 1 && -f "$SSH_USER_AUTH_KEYS_BACKUP" ]]; then
            cp "$SSH_USER_AUTH_KEYS_BACKUP" "$SSH_USER_AUTH_KEYS"
            chown "$SSH_TEST_USER":"$SSH_TEST_USER" "$SSH_USER_AUTH_KEYS" >/dev/null 2>&1 || true
            chmod 600 "$SSH_USER_AUTH_KEYS" >/dev/null 2>&1 || true
        elif [[ "$SSH_USER_AUTH_KEYS_EXISTED" -eq 0 ]]; then
            rm -f "$SSH_USER_AUTH_KEYS"
        fi
    fi

    rm -rf "$SSH_TEST_DIR"
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

setup_sshd() {
    mkdir -p "$SSH_TEST_DIR"

    ssh-keygen -t ed25519 -f "$SSH_HOST_KEY" -N '' >/dev/null
    ssh-keygen -t ed25519 -f "$SSH_CLIENT_KEY" -N '' >/dev/null

    SSH_USER_HOME="$(getent passwd "$SSH_TEST_USER" | cut -d: -f6)"
    if [[ -z "$SSH_USER_HOME" ]]; then
        echo "error: could not determine home directory for $SSH_TEST_USER" >&2
        exit 1
    fi
    SSH_USER_DIR="$SSH_USER_HOME/.ssh"
    SSH_USER_AUTH_KEYS="$SSH_USER_DIR/authorized_keys"

    mkdir -p "$SSH_USER_DIR"
    chown "$SSH_TEST_USER":"$SSH_TEST_USER" "$SSH_USER_DIR" >/dev/null 2>&1 || true
    chmod 700 "$SSH_USER_DIR" >/dev/null 2>&1 || true

    if [[ -f "$SSH_USER_AUTH_KEYS" ]]; then
        SSH_USER_AUTH_KEYS_EXISTED=1
        cp "$SSH_USER_AUTH_KEYS" "$SSH_USER_AUTH_KEYS_BACKUP"
    else
        SSH_USER_AUTH_KEYS_EXISTED=0
    fi

    cat "$SSH_CLIENT_KEY.pub" > "$SSH_USER_AUTH_KEYS"
    chown "$SSH_TEST_USER":"$SSH_TEST_USER" "$SSH_USER_AUTH_KEYS" >/dev/null 2>&1 || true
    chmod 600 "$SSH_USER_AUTH_KEYS" >/dev/null 2>&1 || true

    cat > "$SSH_CFG" <<EOF
Port $PROTECTED_PORT
ListenAddress $EDGE_IP
AddressFamily inet
HostKey $SSH_HOST_KEY
PidFile $SSH_TEST_DIR/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers $SSH_TEST_USER
UsePAM no
StrictModes no
LogLevel ERROR
EOF

    /usr/sbin/sshd -D -f "$SSH_CFG" -E "$SSH_LOG" &
    SSHD_PID=$!
    sleep 1
}

run_ssh_test() {
    local ns="$1"
    local marker="$2"

    ip netns exec "$ns" ssh \
        -o BatchMode=yes \
        -o IdentitiesOnly=yes \
        -o PreferredAuthentications=publickey \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=2 \
        -i "$SSH_CLIENT_KEY" \
        -p "$PROTECTED_PORT" \
        "$SSH_TEST_USER"@"$EDGE_IP" \
        "echo $marker" >/dev/null 2>&1
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
require_cmd ip
require_cmd ssh
require_cmd ssh-keygen
if [[ ! -x /usr/sbin/sshd ]]; then
    echo "error: /usr/sbin/sshd is required for SSH functional test" >&2
    exit 1
fi

discover_ssh_user
if [[ -z "$SSH_TEST_USER" ]]; then
    echo "error: could not discover a non-root local user for SSH test" >&2
    echo "hint: run with SSH_TEST_USER=<username> make test-ssh" >&2
    exit 1
fi
if ! id "$SSH_TEST_USER" >/dev/null 2>&1; then
    echo "error: SSH test user does not exist: $SSH_TEST_USER" >&2
    exit 1
fi

trap cleanup EXIT
cd "$ROOT_DIR"
cleanup
setup_topology
setup_sshd

./build/knockd \
  --ifname "$EDGE_IF" \
  --hmac-key "$KEY" \
  --protect "$PROTECTED_PORT" \
  --knock-port "$KNOCK_PORT" \
  --timeout-ms "$TIMEOUT_MS" \
  --duration-sec 45 \
  >/tmp/knockd_netns_ssh_test.log 2>&1 &
LOADER_PID=$!

sleep 2

echo "[1/11] attacker cannot SSH before knock..."
if run_ssh_test "$ATTACKER_NS" "attacker-pre"; then
    echo "fail: attacker unexpectedly reached SSH before authorization" >&2
    exit 1
else
    echo "ok: attacker blocked"
fi

echo "[2/11] client cannot SSH before knock..."
if run_ssh_test "$CLIENT_NS" "client-pre"; then
    echo "fail: client unexpectedly reached SSH before knock" >&2
    exit 1
else
    echo "ok: client blocked before knock"
fi

echo "[3/11] client sends signed auth..."
TS="$(cut -d. -f1 /proc/uptime)"
NONCE=271828
ip netns exec "$CLIENT_NS" "$ROOT_DIR/build/knock-client" \
  --ifname "$CLIENT_NS_IF" \
  --src-ip "$CLIENT_IP" \
  --dst-ip "$EDGE_IP" \
  --dst-port "$KNOCK_PORT" \
  --timestamp-sec "$TS" \
  --nonce "$NONCE" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_netns_ssh_test.log 2>&1

SESSION_ID="$(sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' /tmp/knock_client_netns_ssh_test.log | head -n1)"
if [[ -z "$SESSION_ID" ]]; then
        echo "fail: unable to parse session_id from SSH auth output" >&2
        exit 1
fi

sleep 1

echo "[4/11] client can SSH after valid auth..."
if run_ssh_test "$CLIENT_NS" "client-post"; then
    echo "ok: client authorized"
else
    echo "fail: client could not SSH after valid knock" >&2
    sed -n '1,120p' /tmp/knockd_netns_ssh_test.log >&2 || true
    sed -n '1,120p' "$SSH_LOG" >&2 || true
    exit 1
fi

echo "[5/11] attacker remains blocked..."
if run_ssh_test "$ATTACKER_NS" "attacker-post"; then
    echo "fail: attacker gained SSH access without authorization" >&2
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
NONCE_DEAUTH_BAD=271827
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
    >/tmp/knock_client_netns_ssh_deauth_bad_test.log 2>&1

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
NONCE_DEAUTH=271829
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
  >/tmp/knock_client_netns_ssh_deauth_test.log 2>&1

sleep 1

echo "[9/11] deauth immediately closes SSH access..."
if run_ssh_test "$CLIENT_NS" "client-deauth"; then
    echo "fail: client still has SSH after deauth" >&2
    exit 1
else
    echo "ok: client blocked after deauth"
fi

echo "[10/11] client reauthenticates for timeout fallback check..."
TS2="$(cut -d. -f1 /proc/uptime)"
NONCE2=271830
ip netns exec "$CLIENT_NS" "$ROOT_DIR/build/knock-client" \
  --ifname "$CLIENT_NS_IF" \
  --src-ip "$CLIENT_IP" \
  --dst-ip "$EDGE_IP" \
  --dst-port "$KNOCK_PORT" \
  --timestamp-sec "$TS2" \
  --nonce "$NONCE2" \
  --hmac-key "$KEY" \
  >/tmp/knock_client_netns_ssh_reauth_test.log 2>&1

sleep 1
if ! run_ssh_test "$CLIENT_NS" "client-reauth"; then
    echo "fail: client could not SSH after reauth" >&2
    exit 1
fi

echo "[11/11] authorization timeout closes SSH access again..."
sleep 4
if run_ssh_test "$CLIENT_NS" "client-timeout"; then
    echo "fail: client still has SSH after timeout" >&2
    exit 1
else
    echo "ok: client blocked after timeout"
fi

echo "pass: netns SSH functional scenario passed"

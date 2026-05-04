#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
    knock_ssh.sh --ifname <iface> --src-ip <ip> --dst-ip <ip> --ssh-target <user@host> --hmac-key <64-hex> [options] [-- ssh-options...]

Required:
  --ifname <iface>          Interface used to send the knock packets
  --src-ip <ip>             Source IP for the knock and SSH socket bind
  --dst-ip <ip>             Destination IP for the knock packets
  --ssh-target <target>     SSH target, for example user@192.0.2.20
  --hmac-key <64-hex>       Shared key used by the client and daemon

Options:
  --user-id <u16>           User ID to encode into the auth knock (default: 0)
  --knock-port <port>       Knock port (default: 40000)
  --ssh-port <port>         Protected SSH port (default: 22)
  --ssh-src-port <port>     Fixed local source port for SSH (default: 55411)
  --knock-client <path>     knock-client binary path (default: ./build/knock-client)
  --ssh-auth <mode>         SSH auth mode: password or publickey (default: password)
  --renew-interval-sec <n>  Seconds between keepalive renewals (default: 1)
  --ssh-arg <arg>           Additional ssh option; may be repeated
  -h, --help                Show this help

Example:
  ./scripts/knock_ssh.sh \
    --ifname eth0 \
    --src-ip 192.0.2.10 \
    --dst-ip 192.0.2.20 \
    --ssh-target user@192.0.2.20 \
    --user-id 100 \
    --hmac-key <64hex>
EOF
}

fail() {
    echo "error: $1" >&2
    exit 1
}

ifname=""
src_ip=""
dst_ip=""
ssh_target=""
hmac_key=""
user_id="0"
knock_port="40000"
ssh_port="22"
ssh_src_port="55411"
knock_client="./build/knock-client"
ssh_auth="password"
renew_interval_sec="1"
ssh_args=()

while [[ $# -gt 0 ]]; do
    case "$1" in
    --ifname)
        [[ $# -ge 2 ]] || fail "--ifname requires a value"
        ifname="$2"
        shift 2
        ;;
    --src-ip)
        [[ $# -ge 2 ]] || fail "--src-ip requires a value"
        src_ip="$2"
        shift 2
        ;;
    --dst-ip)
        [[ $# -ge 2 ]] || fail "--dst-ip requires a value"
        dst_ip="$2"
        shift 2
        ;;
    --ssh-target)
        [[ $# -ge 2 ]] || fail "--ssh-target requires a value"
        ssh_target="$2"
        shift 2
        ;;
    --hmac-key)
        [[ $# -ge 2 ]] || fail "--hmac-key requires a value"
        hmac_key="$2"
        shift 2
        ;;
    --user-id)
        [[ $# -ge 2 ]] || fail "--user-id requires a value"
        user_id="$2"
        shift 2
        ;;
    --knock-port)
        [[ $# -ge 2 ]] || fail "--knock-port requires a value"
        knock_port="$2"
        shift 2
        ;;
    --ssh-port)
        [[ $# -ge 2 ]] || fail "--ssh-port requires a value"
        ssh_port="$2"
        shift 2
        ;;
    --ssh-src-port)
        [[ $# -ge 2 ]] || fail "--ssh-src-port requires a value"
        ssh_src_port="$2"
        shift 2
        ;;
    --knock-client)
        [[ $# -ge 2 ]] || fail "--knock-client requires a value"
        knock_client="$2"
        shift 2
        ;;
    --ssh-auth)
        [[ $# -ge 2 ]] || fail "--ssh-auth requires a value"
        ssh_auth="$2"
        shift 2
        ;;
    --renew-interval-sec)
        [[ $# -ge 2 ]] || fail "--renew-interval-sec requires a value"
        renew_interval_sec="$2"
        shift 2
        ;;
    --ssh-arg)
        [[ $# -ge 2 ]] || fail "--ssh-arg requires a value"
        ssh_args+=("$2")
        shift 2
        ;;
    --help|-h)
        usage
        exit 0
        ;;
    --)
        shift
        while [[ $# -gt 0 ]]; do
            ssh_args+=("$1")
            shift
        done
        break
        ;;
    *)
        fail "unknown argument: $1"
        ;;
    esac
done

if [[ -z "$ifname" || -z "$src_ip" || -z "$dst_ip" || -z "$ssh_target" || -z "$hmac_key" ]]; then
    usage >&2
    exit 1
fi

if [[ "$ssh_auth" != "password" && "$ssh_auth" != "publickey" ]]; then
    fail "--ssh-auth must be password or publickey"
fi

case "$renew_interval_sec" in
    ''|*[!0-9]*) fail "--renew-interval-sec must be a positive integer" ;;
esac
if [[ "$renew_interval_sec" -lt 1 ]]; then
    fail "--renew-interval-sec must be at least 1"
fi

command -v ssh >/dev/null 2>&1 || fail "ssh is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
[[ -x "$knock_client" ]] || fail "knock client not found: $knock_client"

tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

proxy_helper="$tmp_dir/ssh_proxy_bind.py"
cat > "$proxy_helper" <<'PY'
#!/usr/bin/env python3
import os
import select
import socket
import sys

if len(sys.argv) != 5:
    sys.exit(2)

host = sys.argv[1]
port = int(sys.argv[2])
src_ip = sys.argv[3]
src_port = int(sys.argv[4])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((src_ip, src_port))
sock.connect((host, port))

stdin_fd = sys.stdin.fileno()
stdout_fd = sys.stdout.fileno()
sock_fd = sock.fileno()

while True:
    read_fds = [sock_fd, stdin_fd]
    ready, _, _ = select.select(read_fds, [], [])

    if sock_fd in ready:
        data = sock.recv(32768)
        if not data:
            break
        os.write(stdout_fd, data)

    if stdin_fd in ready:
        data = os.read(stdin_fd, 32768)
        if not data:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            continue
        sock.sendall(data)

sock.close()
PY
chmod 700 "$proxy_helper"

auth_output="$("$knock_client" \
    --ifname "$ifname" \
    --src-ip "$src_ip" \
    --dst-ip "$dst_ip" \
    --dst-port "$knock_port" \
    --user-id "$user_id" \
    --hmac-key "$hmac_key")"

session_id="$(printf '%s\n' "$auth_output" | sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' | head -n1)"
if [[ -z "$session_id" ]]; then
    fail "could not parse session_id from knock-client output"
fi

"$knock_client" \
    --ifname "$ifname" \
    --src-ip "$src_ip" \
    --dst-ip "$dst_ip" \
    --dst-port "$knock_port" \
    --packet-type bind \
    --session-id "$session_id" \
    --src-port "$ssh_src_port" \
    --bind-port "$ssh_port" \
    --hmac-key "$hmac_key" >/dev/null

proxy_command="python3 $proxy_helper %h %p $src_ip $ssh_src_port"

renew_nonce() {
    python3 - <<'PY'
import os
print(int.from_bytes(os.urandom(4), 'big'))
PY
}

renew_loop() {
    while true; do
        sleep "$renew_interval_sec"
        "$knock_client" \
            --ifname "$ifname" \
            --src-ip "$src_ip" \
            --dst-ip "$dst_ip" \
            --dst-port "$knock_port" \
            --packet-type renew \
            --session-id "$session_id" \
            --nonce "$(renew_nonce)" \
            --hmac-key "$hmac_key" >/dev/null 2>&1 || true
    done
}

ssh_cmd=(ssh
    -o ConnectTimeout=2
    -o "ProxyCommand=$proxy_command"
    -p "$ssh_port")

if [[ "$ssh_auth" == "publickey" ]]; then
    ssh_cmd+=(-o BatchMode=yes -o IdentitiesOnly=yes -o PreferredAuthentications=publickey)
else
    ssh_cmd+=(-o BatchMode=no -o PreferredAuthentications=password,keyboard-interactive,publickey)
fi

renew_loop &
renew_pid=$!

cleanup_processes() {
    if [[ -n "${renew_pid:-}" ]]; then
        kill "$renew_pid" >/dev/null 2>&1 || true
        wait "$renew_pid" >/dev/null 2>&1 || true
    fi
    rm -rf "$tmp_dir"
}
trap cleanup_processes EXIT INT TERM

set +e
"${ssh_cmd[@]}" \
    "${ssh_args[@]}" \
    "$ssh_target"
ssh_rc=$?
set -e

cleanup_processes
trap - EXIT INT TERM
exit "$ssh_rc"

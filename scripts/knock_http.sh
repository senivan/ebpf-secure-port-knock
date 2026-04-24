#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  knock_http.sh --ifname <iface> --src-ip <ip> --dst-ip <ip> --url <http(s)://...> --hmac-key <64-hex> [options] [-- curl-options...]

Required:
  --ifname <iface>          Interface used to send the knock packets
  --src-ip <ip>             Source IP for knock and HTTP connection
  --dst-ip <ip>             Destination IP for the knock packets
  --url <url>               Target URL for curl request
  --hmac-key <64-hex>       Shared key used by client and daemon

Options:
  --user-id <u16>           User ID encoded into auth knock (default: 0)
  --knock-port <port>       Knock port (default: 40000)
  --http-port <port>        Protected HTTP service port (default: inferred from URL)
  --http-src-port <port>    Fixed local source port for curl (default: 55421)
  --renew-interval-sec <n>  Seconds between keepalive renewals (default: 1)
  --knock-client <path>     knock-client binary path (default: ./build/knock-client)
  --curl-bin <path>         curl binary path (default: curl)
  --curl-arg <arg>          Additional curl option; may be repeated
  -h, --help                Show this help

Example:
  ./scripts/knock_http.sh \
    --ifname eth0 \
    --src-ip 192.0.2.10 \
    --dst-ip 192.0.2.20 \
    --url https://192.0.2.20/health \
    --user-id 100 \
    --hmac-key <64hex>
EOF
}

fail() {
    echo "error: $1" >&2
    exit 1
}

infer_http_port() {
    local in_url="$1"

    if [[ "$in_url" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*://[^/:]+:([0-9]+)(/|$) ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    if [[ "$in_url" =~ ^https:// ]]; then
        echo "443"
    else
        echo "80"
    fi
}

renew_nonce() {
    python3 - <<'PY'
import os
print(int.from_bytes(os.urandom(4), 'big'))
PY
}

ifname=""
src_ip=""
dst_ip=""
url=""
hmac_key=""
user_id="0"
knock_port="40000"
http_port=""
http_src_port="55421"
renew_interval_sec="1"
knock_client="./build/knock-client"
curl_bin="curl"
curl_args=()

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
    --url)
        [[ $# -ge 2 ]] || fail "--url requires a value"
        url="$2"
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
    --http-port)
        [[ $# -ge 2 ]] || fail "--http-port requires a value"
        http_port="$2"
        shift 2
        ;;
    --http-src-port)
        [[ $# -ge 2 ]] || fail "--http-src-port requires a value"
        http_src_port="$2"
        shift 2
        ;;
    --renew-interval-sec)
        [[ $# -ge 2 ]] || fail "--renew-interval-sec requires a value"
        renew_interval_sec="$2"
        shift 2
        ;;
    --knock-client)
        [[ $# -ge 2 ]] || fail "--knock-client requires a value"
        knock_client="$2"
        shift 2
        ;;
    --curl-bin)
        [[ $# -ge 2 ]] || fail "--curl-bin requires a value"
        curl_bin="$2"
        shift 2
        ;;
    --curl-arg)
        [[ $# -ge 2 ]] || fail "--curl-arg requires a value"
        curl_args+=("$2")
        shift 2
        ;;
    --help|-h)
        usage
        exit 0
        ;;
    --)
        shift
        while [[ $# -gt 0 ]]; do
            curl_args+=("$1")
            shift
        done
        break
        ;;
    *)
        fail "unknown argument: $1"
        ;;
    esac
done

if [[ -z "$ifname" || -z "$src_ip" || -z "$dst_ip" || -z "$url" || -z "$hmac_key" ]]; then
    usage >&2
    exit 1
fi

if [[ -z "$http_port" ]]; then
    http_port="$(infer_http_port "$url")"
fi

case "$renew_interval_sec" in
    ''|*[!0-9]*) fail "--renew-interval-sec must be a positive integer" ;;
esac
if [[ "$renew_interval_sec" -lt 1 ]]; then
    fail "--renew-interval-sec must be at least 1"
fi

command -v "$curl_bin" >/dev/null 2>&1 || fail "curl binary not found: $curl_bin"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
[[ -x "$knock_client" ]] || fail "knock client not found: $knock_client"

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
    --src-port "$http_src_port" \
    --bind-port "$http_port" \
    --hmac-key "$hmac_key" >/dev/null

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

renew_loop &
renew_pid=$!

cleanup() {
    if [[ -n "${renew_pid:-}" ]]; then
        kill "$renew_pid" >/dev/null 2>&1 || true
        wait "$renew_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

curl_cmd=("$curl_bin"
    --silent
    --show-error
    --fail
    --interface "$src_ip"
    --local-port "$http_src_port")

set +e
"${curl_cmd[@]}" "${curl_args[@]}" "$url"
curl_rc=$?
set -e

cleanup
trap - EXIT INT TERM
exit "$curl_rc"

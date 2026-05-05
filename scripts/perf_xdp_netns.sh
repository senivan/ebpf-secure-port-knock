#!/usr/bin/env bash
set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PROTECTED_PORT=2222
UNPROTECTED_PORT=8080
KNOCK_PORT=40000
PIN_DIR="/sys/fs/bpf/knock_gate"
STATS_MAP="$PIN_DIR/stats_map"

CLIENT_NS="knockperf-client"
ATTACKER_NS="knockperf-attacker"
BR_IF="br-knockperf"
EDGE_BR_IF="perf-edge-br"
EDGE_IF="perf-edge-if"
CLIENT_BR_IF="perf-client-br"
CLIENT_NS_IF="perf-client-ns"
ATTACKER_BR_IF="perf-atk-br"
ATTACKER_NS_IF="perf-atk-ns"

EDGE_IP="10.210.0.1"
CLIENT_IP="10.210.0.2"
ATTACKER_IP="10.210.0.3"

TRIALS=3
MEASURE_SEC=30
WARMUP_SEC=5
COOLDOWN_SEC=3
QUICK=0
OUT_DIR=""
LOADER_PID=""
SAMPLER_PID=""
CURRENT_USERS_FILE=""

usage() {
    cat >&2 <<EOF
Usage: $0 [options]

Options:
  --quick                 Run a short smoke benchmark: 1 trial, 3 second measurements
  --trials <n>            Trials per scenario (default: $TRIALS)
  --measure-sec <n>       Measurement seconds per trial (default: $MEASURE_SEC)
  --warmup-sec <n>        Warmup seconds before each measured trial (default: $WARMUP_SEC)
  --cooldown-sec <n>      Cooldown seconds after each measured trial (default: $COOLDOWN_SEC)
  --out-dir <path>        Artifact directory (default: artifacts/perf-<timestamp>)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)
            QUICK=1
            TRIALS=1
            MEASURE_SEC=3
            WARMUP_SEC=1
            COOLDOWN_SEC=1
            shift
            ;;
        --trials)
            TRIALS="$2"
            shift 2
            ;;
        --measure-sec)
            MEASURE_SEC="$2"
            shift 2
            ;;
        --warmup-sec)
            WARMUP_SEC="$2"
            shift 2
            ;;
        --cooldown-sec)
            COOLDOWN_SEC="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: run as root (required for netns, raw packets, XDP attach, and bpftool map reads)" >&2
    exit 1
fi

cd "$ROOT_DIR" || exit 1
if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="artifacts/perf-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
mkdir -p "$OUT_DIR"/raw "$OUT_DIR"/stats

RESULTS_CSV="$OUT_DIR/results.csv"
TIMESERIES_CSV="$OUT_DIR/stats_timeseries.csv"
STATUS_LOG="$OUT_DIR/status.log"
BUILD_LOG="$OUT_DIR/build.log"
ENV_JSON="$OUT_DIR/environment.json"
PACKET_BLAST_BIN="$OUT_DIR/packet-blast"

log() {
    printf '[%(%Y-%m-%dT%H:%M:%S%z)T] %s\n' -1 "$*" | tee -a "$STATUS_LOG"
}

cleanup() {
    set +e
    if [[ -n "$SAMPLER_PID" ]]; then
        kill "$SAMPLER_PID" >/dev/null 2>&1 || true
        wait "$SAMPLER_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$LOADER_PID" ]]; then
        kill "$LOADER_PID" >/dev/null 2>&1 || true
        wait "$LOADER_PID" >/dev/null 2>&1 || true
    fi
    ip netns del "$CLIENT_NS" >/dev/null 2>&1 || true
    ip netns del "$ATTACKER_NS" >/dev/null 2>&1 || true
    ip link del "$EDGE_BR_IF" >/dev/null 2>&1 || true
    ip link del "$CLIENT_BR_IF" >/dev/null 2>&1 || true
    ip link del "$ATTACKER_BR_IF" >/dev/null 2>&1 || true
    ip link del "$BR_IF" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command_text() {
    printf '%q ' "$@"
}

setup_topology() {
    cleanup
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

write_environment() {
    python3 - "$ENV_JSON" "$OUT_DIR" <<'PY'
import json
import os
import platform
import shutil
import subprocess
import sys

def run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

env = {
    "date": run(["date", "-Is"]),
    "kernel": platform.release(),
    "machine": platform.machine(),
    "cpu_model": next((line.split(":", 1)[1].strip() for line in open("/proc/cpuinfo", errors="ignore") if line.startswith("model name")), ""),
    "cpu_count": os.cpu_count(),
    "git_commit": run(["git", "rev-parse", "HEAD"]),
    "git_status_short": run(["git", "status", "--short"]),
    "clang": run(["clang", "--version"]).splitlines()[0] if shutil.which("clang") else "",
    "bpftool": run(["bpftool", "version"]).splitlines()[0] if shutil.which("bpftool") else "",
    "perf": run(["perf", "--version"]) if shutil.which("perf") else "",
    "out_dir": sys.argv[2],
}
open(sys.argv[1], "w").write(json.dumps(env, indent=2, sort_keys=True) + "\n")
PY
}

build_tools() {
    log "building project and packet generator"
    {
        make all &&
        cc -O2 -Wall -Wextra -Iinclude -Isrc/user tools/perf/packet_blast.c src/user/net_checksum.c -o "$PACKET_BLAST_BIN"
    } >"$BUILD_LOG" 2>&1
}

stats_json_to_csv_values() {
    local json_file="$1"
    python3 - "$json_file" <<'PY'
import json
import sys

fields = [
    "knock_seen", "knock_short", "knock_valid", "knock_deauth", "replay_drop",
    "bind_drop", "session_timeout_drop", "deauth_miss", "unknown_user",
    "key_mismatch", "grace_key_used", "knock_rate_drop", "session_limit_drop",
    "map_update_fail", "protected_drop", "protected_pass",
]
try:
    data = json.load(open(sys.argv[1]))
    first = data[0] if data else {}
    value = first.get("formatted", {}).get("value", first.get("value", {}))
except Exception:
    value = {}
print(",".join(str(int(value.get(field, 0))) for field in fields))
PY
}

capture_stats() {
    local file="$1"
    if [[ -e "$STATS_MAP" ]]; then
        bpftool -j map dump pinned "$STATS_MAP" >"$file" 2>"$file.err" || echo '[]' >"$file"
    else
        echo '[]' >"$file"
    fi
}

stats_delta_csv_values() {
    local before="$1"
    local after="$2"
    python3 - "$before" "$after" <<'PY'
import json
import sys

fields = [
    "knock_seen", "knock_short", "knock_valid", "knock_deauth", "replay_drop",
    "bind_drop", "session_timeout_drop", "deauth_miss", "unknown_user",
    "key_mismatch", "grace_key_used", "knock_rate_drop", "session_limit_drop",
    "map_update_fail", "protected_drop", "protected_pass",
]

def load(path):
    try:
        data = json.load(open(path))
        first = data[0] if data else {}
        return first.get("formatted", {}).get("value", first.get("value", {}))
    except Exception:
        return {}

b = load(sys.argv[1])
a = load(sys.argv[2])
print(",".join(str(int(a.get(field, 0)) - int(b.get(field, 0))) for field in fields))
PY
}

start_sampler() {
    {
        echo "timestamp,scenario,trial,knock_seen,knock_short,knock_valid,knock_deauth,replay_drop,bind_drop,session_timeout_drop,deauth_miss,unknown_user,key_mismatch,grace_key_used,knock_rate_drop,session_limit_drop,map_update_fail,protected_drop,protected_pass"
        while true; do
            local tmp="$OUT_DIR/stats/sample.json"
            capture_stats "$tmp"
            printf '%s,%s,%s,%s\n' "$(date +%s)" "${CURRENT_SCENARIO:-idle}" "${CURRENT_TRIAL:-0}" "$(stats_json_to_csv_values "$tmp")"
            sleep 1
        done
    } >>"$TIMESERIES_CSV" &
    SAMPLER_PID=$!
}

generate_users_file() {
    local count="$1"
    local file="$OUT_DIR/users_${count}.csv"
    local i
    : >"$file"
    for i in $(seq 0 "$((count - 1))"); do
        printf '%s,%s\n' "$i" "$KEY" >>"$file"
    done
    CURRENT_USERS_FILE="$file"
}

stop_daemon() {
    if [[ -n "$LOADER_PID" ]]; then
        kill "$LOADER_PID" >/dev/null 2>&1 || true
        wait "$LOADER_PID" >/dev/null 2>&1 || true
        LOADER_PID=""
    fi
}

start_daemon() {
    local user_count="$1"
    stop_daemon
    if [[ "$user_count" -eq 1 ]]; then
        ./build/knockd daemon \
            --ifname "$EDGE_IF" \
            --hmac-key "$KEY" \
            --protect "$PROTECTED_PORT" \
            --knock-port "$KNOCK_PORT" \
            --timeout-ms 60000 \
            --bind-window-ms 10000 \
            --duration-sec 0 \
            >>"$OUT_DIR/knockd.log" 2>&1 &
    else
        generate_users_file "$user_count"
        ./build/knockd daemon \
            --ifname "$EDGE_IF" \
            --users-file "$CURRENT_USERS_FILE" \
            --protect "$PROTECTED_PORT" \
            --knock-port "$KNOCK_PORT" \
            --timeout-ms 60000 \
            --bind-window-ms 10000 \
            --duration-sec 0 \
            >>"$OUT_DIR/knockd.log" 2>&1 &
    fi
    LOADER_PID=$!
    sleep 2
    capture_stats "$OUT_DIR/stats/daemon_start_${user_count}.json"
}

run_valid_bind() {
    local src_port="$1"
    local auth_log="$OUT_DIR/raw/auth_${src_port}.log"
    local bind_log="$OUT_DIR/raw/bind_${src_port}.log"
    local session_id

    ip netns exec "$CLIENT_NS" "$ROOT_DIR/build/knock-client" \
        --ifname "$CLIENT_NS_IF" \
        --src-ip "$CLIENT_IP" \
        --dst-ip "$EDGE_IP" \
        --dst-port "$KNOCK_PORT" \
        --user-id 0 \
        --nonce "$((100000 + src_port))" \
        --hmac-key "$KEY" \
        >"$auth_log" 2>&1
    session_id="$(sed -n 's/.*session_id=\([0-9][0-9]*\).*/\1/p' "$auth_log" | head -n1)"
    if [[ -z "$session_id" ]]; then
        log "failed to parse session_id for src port $src_port"
        return 1
    fi
    ip netns exec "$CLIENT_NS" "$ROOT_DIR/build/knock-client" \
        --ifname "$CLIENT_NS_IF" \
        --src-ip "$CLIENT_IP" \
        --dst-ip "$EDGE_IP" \
        --dst-port "$KNOCK_PORT" \
        --packet-type bind \
        --session-id "$session_id" \
        --src-port "$src_port" \
        --bind-port "$PROTECTED_PORT" \
        --nonce "$((200000 + src_port))" \
        --hmac-key "$KEY" \
        >"$bind_log" 2>&1
}

parse_perf_stat() {
    local file="$1"
    python3 - "$file" <<'PY'
import re
import sys

wanted = {
    "task-clock": "perf_task_clock_ms",
    "cycles": "perf_cycles",
    "instructions": "perf_instructions",
    "context-switches": "perf_context_switches",
    "cpu-migrations": "perf_cpu_migrations",
}
values = {v: "" for v in wanted.values()}
try:
    for line in open(sys.argv[1], errors="ignore"):
        parts = line.strip().split(",")
        if len(parts) < 3:
            continue
        raw = parts[0].strip().replace(",", "")
        event = parts[2].strip()
        for needle, key in wanted.items():
            if needle in event and raw and raw != "<not supported>" and raw != "<not counted>":
                values[key] = re.sub(r"[^0-9.]", "", raw)
except FileNotFoundError:
    pass
print(",".join(values[k] for k in ["perf_task_clock_ms", "perf_cycles", "perf_instructions", "perf_context_switches", "perf_cpu_migrations"]))
PY
}

run_blast_once() {
    local scenario="$1"
    local trial="$2"
    local dst_port="$3"
    local payload="$4"
    local src_port="$5"
    local src_span="$6"
    local src_ip_span="$7"
    local target_pps="${8:-0}"
    local before="$OUT_DIR/stats/${scenario}_${trial}_before.json"
    local after="$OUT_DIR/stats/${scenario}_${trial}_after.json"
    local raw="$OUT_DIR/raw/${scenario}_${trial}.json"
    local err="$OUT_DIR/raw/${scenario}_${trial}.err"
    local perf_file="$OUT_DIR/perf-stat-${scenario}-${trial}.txt"
    local status="ok"
    local rc=0
    local json_values
    local delta_values
    local perf_values

    CURRENT_SCENARIO="$scenario"
    CURRENT_TRIAL="$trial"
    log "scenario=$scenario trial=$trial warmup=${WARMUP_SEC}s measure=${MEASURE_SEC}s"

    if [[ "$WARMUP_SEC" -gt 0 ]]; then
        ip netns exec "$CLIENT_NS" "$PACKET_BLAST_BIN" \
            --ifname "$CLIENT_NS_IF" --src-ip "$CLIENT_IP" --dst-ip "$EDGE_IP" \
            --dst-port "$dst_port" --src-port "$src_port" --src-port-span "$src_span" \
            --src-ip-span "$src_ip_span" \
            --duration-sec "$WARMUP_SEC" --target-pps "$target_pps" \
            --payload "$payload" --hmac-key "$KEY" --user-id 0 \
            --label "${scenario}_warmup" \
            >"$OUT_DIR/raw/${scenario}_${trial}_warmup.json" 2>"$OUT_DIR/raw/${scenario}_${trial}_warmup.err" || true
    fi

    capture_stats "$before"
    if command -v perf >/dev/null 2>&1; then
        perf stat -x, -o "$perf_file" \
            -e task-clock,cycles,instructions,context-switches,cpu-migrations \
            -- ip netns exec "$CLIENT_NS" "$PACKET_BLAST_BIN" \
                --ifname "$CLIENT_NS_IF" --src-ip "$CLIENT_IP" --dst-ip "$EDGE_IP" \
                --dst-port "$dst_port" --src-port "$src_port" --src-port-span "$src_span" \
                --src-ip-span "$src_ip_span" \
                --duration-sec "$MEASURE_SEC" --target-pps "$target_pps" \
                --payload "$payload" --hmac-key "$KEY" --user-id 0 \
                --label "$scenario" \
                >"$raw" 2>"$err"
        rc=$?
        if [[ "$rc" -eq 255 || ! -s "$raw" ]]; then
            log "perf stat unavailable for $scenario trial $trial; rerunning without perf"
            ip netns exec "$CLIENT_NS" "$PACKET_BLAST_BIN" \
                --ifname "$CLIENT_NS_IF" --src-ip "$CLIENT_IP" --dst-ip "$EDGE_IP" \
                --dst-port "$dst_port" --src-port "$src_port" --src-port-span "$src_span" \
                --src-ip-span "$src_ip_span" \
                --duration-sec "$MEASURE_SEC" --target-pps "$target_pps" \
                --payload "$payload" --hmac-key "$KEY" --user-id 0 \
                --label "$scenario" \
                >"$raw" 2>"$err"
            rc=$?
        fi
    else
        ip netns exec "$CLIENT_NS" "$PACKET_BLAST_BIN" \
            --ifname "$CLIENT_NS_IF" --src-ip "$CLIENT_IP" --dst-ip "$EDGE_IP" \
            --dst-port "$dst_port" --src-port "$src_port" --src-port-span "$src_span" \
            --src-ip-span "$src_ip_span" \
            --duration-sec "$MEASURE_SEC" --target-pps "$target_pps" \
            --payload "$payload" --hmac-key "$KEY" --user-id 0 \
            --label "$scenario" \
            >"$raw" 2>"$err"
        rc=$?
    fi
    capture_stats "$after"

    if [[ "$rc" -ne 0 ]]; then
        status="rc_${rc}"
    fi
    json_values="$(python3 - "$raw" <<'PY'
import json
import sys
try:
    line = open(sys.argv[1]).read().strip().splitlines()[-1]
    data = json.loads(line)
except Exception:
    data = {}
print(",".join(str(data.get(k, "")) for k in ["sent", "errors", "elapsed_sec", "pps", "mbps", "frame_len"]))
PY
)"
    delta_values="$(stats_delta_csv_values "$before" "$after")"
    perf_values="$(parse_perf_stat "$perf_file")"
    printf '%s,%s,%s,%s,%s,%s\n' "$scenario" "$trial" "$status" "$json_values" "$delta_values" "$perf_values" >>"$RESULTS_CSV"

    if [[ "$COOLDOWN_SEC" -gt 0 ]]; then
        sleep "$COOLDOWN_SEC"
    fi
}

run_scenario_trials() {
    local scenario="$1"
    local dst_port="$2"
    local payload="$3"
    local src_port="${4:-50000}"
    local src_span="${5:-1}"
    local src_ip_span="${6:-1}"
    local target_pps="${7:-0}"
    local t

    for t in $(seq 1 "$TRIALS"); do
        run_blast_once "$scenario" "$t" "$dst_port" "$payload" "$src_port" "$src_span" "$src_ip_span" "$target_pps"
    done
}

write_results_header() {
    echo "scenario,trial,status,sent,errors,elapsed_sec,pps,mbps,frame_len,delta_knock_seen,delta_knock_short,delta_knock_valid,delta_knock_deauth,delta_replay_drop,delta_bind_drop,delta_session_timeout_drop,delta_deauth_miss,delta_unknown_user,delta_key_mismatch,delta_grace_key_used,delta_knock_rate_drop,delta_session_limit_drop,delta_map_update_fail,delta_protected_drop,delta_protected_pass,perf_task_clock_ms,perf_cycles,perf_instructions,perf_context_switches,perf_cpu_migrations" >"$RESULTS_CSV"
}

main() {
    write_environment
    write_results_header
    build_tools || {
        log "build failed; see $BUILD_LOG"
        exit 1
    }
    setup_topology

    log "running baseline without XDP"
    run_scenario_trials "baseline_no_xdp" "$PROTECTED_PORT" "empty" 50000 256

    log "starting daemon with one user"
    start_daemon 1
    start_sampler

    run_scenario_trials "xdp_unprotected_pass" "$UNPROTECTED_PORT" "empty" 50000 256 256
    run_scenario_trials "protected_unauthorized_drop" "$PROTECTED_PORT" "empty" 50000 256 256
    run_scenario_trials "knock_invalid_user_or_key" "$KNOCK_PORT" "invalid-knock" 50000 256 256

    log "restarting daemon before authorized session tests"
    start_daemon 1
    log "setting up authorized flow"
    run_valid_bind 50100 || log "authorized bind setup failed; authorized scenario may show drops"
    run_scenario_trials "authorized_protected_pass" "$PROTECTED_PORT" "empty" 50100 1

    run_scenario_trials "replay_drop" "$KNOCK_PORT" "valid-knock-fixed" 51000 1 1 20
    run_scenario_trials "source_rate_limit" "$KNOCK_PORT" "valid-knock" 51100 1

    log "restarting daemon before active-session pressure tests"
    start_daemon 1
    log "creating active sessions for session pressure"
    for port in $(seq 52000 52031); do
        run_valid_bind "$port" || true
    done
    run_scenario_trials "active_session_pressure_32" "$PROTECTED_PORT" "empty" 52000 32

    for users in 128 1024; do
        log "restarting daemon with $users users"
        start_daemon "$users"
        run_scenario_trials "user_scale_${users}" "$KNOCK_PORT" "valid-knock" 53000 256 4096
    done

    CURRENT_SCENARIO="render"
    CURRENT_TRIAL="0"
    log "rendering report"
    python3 tools/perf/render_perf_report.py "$OUT_DIR" >>"$STATUS_LOG" 2>&1 || {
        log "report rendering failed"
        exit 1
    }
    log "complete: $OUT_DIR/summary.md"
}

main "$@"

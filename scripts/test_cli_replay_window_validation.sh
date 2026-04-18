#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -x ./build/knockd ]]; then
    make all >/tmp/knock_build.log 2>&1
fi

set +e
output="$(./build/knockd daemon --replay-window-ms 29999 2>&1)"
status=$?
set -e

if [[ "$status" -eq 0 ]]; then
    echo "error: daemon accepted a replay window below the clock-skew minimum" >&2
    exit 1
fi

if ! grep -q "must be at least" <<<"$output"; then
    echo "error: expected replay-window validation message not found" >&2
    echo "$output" >&2
    exit 1
fi

echo "ok: sub-skew replay window is rejected"
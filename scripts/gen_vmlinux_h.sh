#!/usr/bin/env bash
set -euo pipefail

OUT_FILE="${1:-include/vmlinux.h}"

if ! command -v bpftool >/dev/null 2>&1; then
    echo "error: bpftool is required to generate vmlinux.h" >&2
    echo "hint: install linux-tools and make sure bpftool is in PATH" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUT_FILE"

echo "generated $OUT_FILE"

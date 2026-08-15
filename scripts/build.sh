#!/usr/bin/env bash
# Memory-safe build wrapper.
#
# A naive `cmake --build build -j$(nproc)` compiles every translation unit in
# parallel; on a 12-core laptop the heavy units (httplib's single header is
# parsed by several files) can exhaust RAM and freeze the machine before the
# OOM killer reacts. This script sizes the job count from the available RAM —
# roughly one compiler per 2 GiB, capped at the core count — so a first build
# is bounded even on small machines.
#
# Usage:
#   ./scripts/build.sh            # configure + build, RAM-aware parallelism
#   ./scripts/build.sh -j8        # explicit job count
#   JOBS=8 ./scripts/build.sh     # same via environment
set -euo pipefail
cd "$(dirname "$0")/.."

mem_mb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 1024)
jobs=$((mem_mb / 2048))
[ "$jobs" -lt 1 ] && jobs=1
cores=$(nproc 2>/dev/null || echo 1)
[ "$jobs" -gt "$cores" ] && jobs=$cores

if [ -n "${JOBS:-}" ]; then
    jobs=$JOBS
fi
for arg in "$@"; do
    case "$arg" in
        -j*) jobs=${arg#-j} ;;
        *) ;;
    esac
done

echo "==> building with $jobs parallel job(s) (RAM-aware default; use -jN or JOBS=N to override)"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j "$jobs"
echo "==> done: ./build/ghost_recover"

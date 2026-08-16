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
#   ./scripts/build.sh --sanitize # ASan/UBSan build (jobs halved: the
#                                 # instrumented compiles need ~2 GiB each)
set -euo pipefail
cd "$(dirname "$0")/.."

sanitize=0
for arg in "$@"; do
    case "$arg" in
        --sanitize) sanitize=1 ;;
        -j*) jobs_override=${arg#-j} ;;
    esac
done

mem_mb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 1024)
jobs=$((mem_mb / 2048))
[ "$jobs" -lt 1 ] && jobs=1
if [ "$sanitize" -eq 1 ]; then
    jobs=$((jobs / 2))
    [ "$jobs" -lt 1 ] && jobs=1
fi
cores=$(nproc 2>/dev/null || echo 1)
[ "$jobs" -gt "$cores" ] && jobs=$cores

if [ -n "${JOBS:-}" ]; then
    jobs=$JOBS
fi
if [ -n "${jobs_override:-}" ]; then
    jobs=$jobs_override
fi

extra=()
if [ "$sanitize" -eq 1 ]; then
    extra+=(-DGHOST_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug)
fi
echo "==> building with $jobs parallel job(s) (RAM-aware default; use -jN or JOBS=N to override)"
if [ "$sanitize" -eq 1 ]; then
    cmake -S . -B build-san -DCMAKE_BUILD_TYPE=Debug -DGHOST_SANITIZE=ON
    cmake --build build-san -j "$jobs"
    echo "==> done: ./build-san/ghost_recover (sanitizer build; keep ./build/ for the normal binary)"
else
    # GHOST_SANITIZE=OFF explicitly: a previous --sanitize run leaves the flag
    # in the build/ cache, and a rebuild would otherwise silently stay ASan.
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DGHOST_SANITIZE=OFF
    cmake --build build -j "$jobs"
    echo "==> done: ./build/ghost_recover"
fi
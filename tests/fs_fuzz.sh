#!/usr/bin/env bash
# Filesystem-driver mutation fuzzer.
#
# Mutates the real fixture images (tests/build-fixtures.sh output) with
# random byte flips, garbage stomps and superblock-area wipes, then runs the
# engine's scan path against each under ASan. A crash (sanitizer abort,
# signal) or a hang (>15 s per run) is a failure; a clean rejection is not.
#
# The sanitizer build is required:  scripts/build.sh --sanitize
#
# Usage:
#   tests/fs_fuzz.sh [iterations]          # random mutations (default 100)
#   tests/fs_fuzz.sh --sb [runs]           # targeted superblock-area stomps
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
BIN="${GHOST_SAN_BIN:-$ROOT/build-san/ghost_recover}"
FIX="${GHOST_FIXTURES:-${XDG_CACHE_HOME:-$HOME/.cache}/ghost-recover/fixtures}/img"
WORK="$(mktemp -d /tmp/ghost-fs-fuzz.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[ -x "$BIN" ] || { echo "error: $BIN not built (run scripts/build.sh --sanitize)" >&2; exit 2; }
[ -d "$FIX" ] || { echo "error: fixtures not found at $FIX" >&2; exit 2; }

MODE=random
case "${1:-}" in
  --sb) MODE=sb; N="${2:-192}" ;;
  "")   N="${1:-100}" ;;
  *)    N="$1" ;;
esac

IMGS=(squashfs cramfs jffs2 iso9660 udf minix hfs ext2 ext4 ext4-deleted \
      fat32 fat32-deleted ntfs exfat ufs ufs2 xfs btrfs disk-mbr disk-gpt)
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
SAN="$(gcc -print-file-name=libasan.so)"

mutate() { # <src> <dst>
  cp "$1" "$2"
  local size off len k m
  size=$(stat -c%s "$2")
  if [ "$MODE" = sb ]; then
    # Stomp a header zone: offset 0/1024/4096/8192 covers every superblock
    # copy the drivers look for.
    local zones=(0 1024 4096 8192)
    off=$((RANDOM % 4))
    off=${zones[$off]}
    [ "$off" -ge "$size" ] && return 0
    len=$((RANDOM % 2048 + 512))
    [ $((off + len)) -gt "$size" ] && len=$((size - off))
    case $((RANDOM % 3)) in
      0) dd if=/dev/zero of="$2" bs=1 count=$len seek=$off conv=notrunc status=none ;;
      1) yes $'\377' | dd of="$2" bs=1 count=$len seek=$off conv=notrunc status=none ;;
      *) dd if=/dev/urandom of="$2" bs=1 count=$len seek=$off conv=notrunc status=none ;;
    esac
    return 0
  fi
  k=$((RANDOM % 16 + 1))
  for ((m = 0; m < k; m++)); do
    off=$((RANDOM * 32768 + RANDOM)); off=$((off % size))
    if [ $((RANDOM % 4)) -eq 0 ]; then
      dd if=/dev/urandom of="$2" bs=1 count=64 seek=$off conv=notrunc status=none
    else
      printf "$(printf '\\x%02x' $((RANDOM % 256)))" \
        | dd of="$2" bs=1 count=1 seek=$off conv=notrunc status=none
    fi
  done
}

fails=0
for ((it = 0; it < N; it++)); do
  name=${IMGS[$((RANDOM % ${#IMGS[@]}))]}
  src="$FIX/$name.img"
  [ -f "$src" ] || continue
  dst="$WORK/fuzz.img"
  mutate "$src" "$dst"
  timeout 15 env LD_PRELOAD="$SAN" "$BIN" scan "$dst" --max-files 300 \
    --out "$WORK/out" >/dev/null 2>"$WORK/err"
  rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 1 ]; then
    echo "FAIL it=$it img=$name mode=$MODE rc=$rc"
    grep -m2 -E "ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error" "$WORK/err"
    cp "$dst" "$WORK/../ghost-fs-fuzz-fail-$name-$it.img"
    fails=$((fails + 1))
  fi
done
echo "fs fuzz ($MODE): $fails failures in $N runs"
[ "$fails" -eq 0 ]

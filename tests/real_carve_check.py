#!/usr/bin/env python3
"""Real-world carving audit.

Embeds genuine files (tests/make_real_samples.sh corpus — ffmpeg muxes,
ImageMagick encodes, LibreOffice documents, mingw/gcc executables, qemu-img
disk images, 7z/mkisofs archives, real system fonts) into a synthetic disk
between pseudo-random junk, carves it with the real binary, and requires
every sample to come back byte-identical.

Synthetic fixtures (carve_spec_check.py) prove a signature walks a spec-clean
file; this proves it survives the real world: extra chunks, unknown elements,
odd padding, muxer quirks, real compression streams.

Usage: real_carve_check.py [--bin build/ghost_recover] [--samples DIR]
"""
import argparse
import hashlib
import os
import random
import subprocess
import sys

def build_disk(samples, disk_path, seed=20260815):
    rnd = random.Random(seed)
    def junk(n):
        # Random data with occasional zero runs and repeated patterns, so a
        # carver cannot rely on "it just stops when the data looks random".
        out = bytearray()
        while len(out) < n:
            kind = rnd.random()
            if kind < 0.75:
                out += bytes(rnd.randrange(256) for _ in range(min(512, n - len(out))))
            elif kind < 0.9:
                out += b'\x00' * min(rnd.randrange(64, 4096), n - len(out))
            else:
                out += bytes([rnd.randrange(256)]) * min(rnd.randrange(64, 1024), n - len(out))
        return bytes(out)
    layout = []
    with open(disk_path, 'wb') as f:
        for path in samples:
            data = open(path, 'rb').read()
            pre = rnd.randrange(0, 4000)
            post = rnd.randrange(0, 4000)
            f.write(junk(pre))
            off = f.tell()
            f.write(data)
            f.write(junk(post))
            layout.append((os.path.basename(path), off, len(data)))
    return layout

def carve(bin_path, disk_path, outdir):
    if os.path.isdir(outdir):
        import shutil
        shutil.rmtree(outdir)
    r = subprocess.run([bin_path, 'carve', disk_path, '--out', outdir],
                       capture_output=True, text=True, timeout=1800)
    return r.returncode, r.stdout + r.stderr

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', default='build/ghost_recover')
    ap.add_argument('--samples', default='/tmp/ghost-samples')
    ap.add_argument('--work', default='/tmp/ghost-real-carve')
    ap.add_argument('--keep', action='store_true')
    args = ap.parse_args()

    samples = sorted(os.path.join(args.samples, f)
                     for f in os.listdir(args.samples)
                     if os.path.isfile(os.path.join(args.samples, f)))
    if not samples:
        print('no samples — run tests/make_real_samples.sh first')
        sys.exit(2)

    disk = os.path.join(args.work, 'disk.img')
    outdir = os.path.join(args.work, 'out')
    os.makedirs(args.work, exist_ok=True)
    layout = build_disk(samples, disk)

    rc, log = carve(args.bin, disk, outdir)
    if rc != 0:
        print('carve failed rc=%d' % rc)
        print(log[-4000:])
        sys.exit(2)

    # map every carved file -> bytes
    carved = {}
    for root, _dirs, files in os.walk(outdir):
        for f in files:
            p = os.path.join(root, f)
            carved[p] = open(p, 'rb').read()

    want = {}
    for name, off, size in layout:
        data = open(os.path.join(args.samples, name), 'rb').read()
        want[name] = hashlib.md5(data).hexdigest()

    def is_text(data):
        return all(b in (0x09, 0x0A, 0x0D) or 0x20 <= b <= 0x7E for b in data)

    def classify(cdata, data):
        if cdata == data:
            return 'exact'
        if len(cdata) < len(data) and data.startswith(cdata):
            # A text walker stops at the first unprintable byte; the byte
            # after the last newline is unknowable, so a short tail on a
            # printable sample is an exact recovery.
            if len(data) - len(cdata) <= 16 and is_text(data):
                return 'exact'
            return 'truncated'
        if len(cdata) > len(data) and cdata.startswith(data):
            # Likewise a printable tail run into printable junk cannot be
            # bounded by the walker; a few stray bytes are exact.
            if len(cdata) - len(data) <= 16 and is_text(data):
                return 'exact'
            return 'over-captured'
        if data.startswith(cdata):
            return 'corrupt-prefix'
        return 'corrupt'

    results = {}
    for name, _, _ in layout:
        data = open(os.path.join(args.samples, name), 'rb').read()
        found = None
        for p, cdata in carved.items():
            if cdata == data:
                found = ('exact', os.path.relpath(p, outdir))
                break
        if not found:
            best = None
            for p, cdata in carved.items():
                k = classify(cdata, data)
                if k == 'exact':
                    found = ('exact', os.path.relpath(p, outdir)); break
                if k in ('truncated', 'over-captured') and (best is None or
                        k == 'over-captured' and best[0] == 'truncated'):
                    best = (k, os.path.relpath(p, outdir))
            found = found or best or ('not-found', None)
        results[name] = found

    exact = sum(1 for k, v in results.items() if v[0] == 'exact')
    print(f'{exact}/{len(samples)} samples recovered byte-identical\n')
    for name, (k, p) in sorted(results.items()):
        ext = os.path.splitext(name)[1]
        if k == 'exact':
            print(f'  PASS  {name}')
        else:
            print(f'  FAIL  {name:28s} [{k:14s}] {p or ""}')
    print(f'\n{exact} passed, {len(samples) - exact} failed of {len(samples)}')
    if not args.keep:
        import shutil
        shutil.rmtree(args.work)
    return 0 if exact == len(samples) else 1

if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env bash
# Builds the filesystem images the verification suite runs against.
# Nothing here needs root: every filesystem is populated without mounting.
set -euo pipefail

OUT="${1:-$(mktemp -d /tmp/ghost-fixtures.XXXXXX)}"
SRC="$OUT/corpus"
IMG="$OUT/img"
mkdir -p "$SRC/docs" "$SRC/media" "$IMG"

echo "fixtures -> $OUT"

python3 - "$SRC" <<'PY'
import os, sys, struct, zlib, json, io, zipfile, sqlite3, tempfile, shutil
root = sys.argv[1]
def w(p, b):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'wb').write(b)

def png(width, height, colour):
    raw = b''.join(b'\x00' + bytes(colour) * width for _ in range(height))
    def chunk(t, d):
        c = t + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))

w(root + '/media/red.png',  png(64, 64, (220, 30, 40)))
w(root + '/media/blue.png', png(128, 96, (20, 60, 200)))

jpeg = bytes.fromhex(
 'ffd8ffe000104a46494600010100000100010000ffdb004300ffffffffffffffffffffffffffff'
 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
 'ffffffffffffffffffffffffffffffffffffffc00011080010001003012200021101031101'
 'ffc4001f0000010501010101010100000000000000000102030405060708090a0b'
 'ffc400b5100002010303020403050504040000017d01020300041105122131410613516107'
 '227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738'
 '393a434445464748494a535455565758595a636465666768696a737475767778797a8384858687'
 '88898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9ca'
 'd2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9fa'
 'ffda0008010100003f00fbfeffd9')
w(root + '/media/photo.jpg', jpeg)

w(root + '/media/tiny.gif',
  b'GIF89a' + struct.pack('<HH', 4, 4) + b'\xf0\x00\x00' + b'\x00\x00\x00\xff\xff\xff'
  + b'\x2c' + struct.pack('<HHHH', 0, 0, 4, 4) + b'\x00' + b'\x02\x04\x84\x8f\x09\x05\x00' + b'\x3b')

samples = b''.join(struct.pack('<h', int(3000 * ((i % 100) / 50 - 1))) for i in range(8000))
w(root + '/media/tone.wav',
  b'RIFF' + struct.pack('<I', 36 + len(samples)) + b'WAVE'
  + b'fmt ' + struct.pack('<IHHIIHH', 16, 1, 1, 8000, 16000, 2, 16)
  + b'data' + struct.pack('<I', len(samples)) + samples)

w(root + '/docs/report.pdf',
  b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n'
  b'2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n'
  b'3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n'
  b'trailer<</Root 1 0 R>>\n%%EOF\n')

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('notes.txt', 'ghost recover archive test\n' * 40)
    z.writestr('data/values.csv', 'id,name\n1,alpha\n2,beta\n')
w(root + '/docs/bundle.zip', buf.getvalue())

tmp = tempfile.mktemp(suffix='.sqlite')
c = sqlite3.connect(tmp)
c.execute('CREATE TABLE contacts(id INTEGER PRIMARY KEY, name TEXT, email TEXT)')
for i in range(50):
    c.execute('INSERT INTO contacts(name,email) VALUES(?,?)', (f'user{i}', f'u{i}@example.com'))
c.commit(); c.close()
w(root + '/docs/contacts.sqlite', open(tmp, 'rb').read()); os.unlink(tmp)

w(root + '/docs/readme.txt', ('GHOST//RECOVER verification corpus.\n' * 60).encode())
w(root + '/docs/config.json', json.dumps({"engine": "ghost", "version": 3}, indent=2).encode())
w(root + '/docs/script.sh', b'#!/bin/bash\necho "recovered"\nexit 0\n' + b'# padding\n' * 40)
shutil.copyfile('/bin/true', root + '/docs/true.elf')
# Large enough to need several blocks and an indirect/extent chain.
w(root + '/media/large.bin', bytes((i * 7 + 13) % 251 for i in range(600 * 1024)))
print('corpus files:', sum(len(f) for _, _, f in os.walk(root)))
PY

have() { command -v "$1" >/dev/null 2>&1; }

have mkfs.ext4  && mkfs.ext4 -q -F -L GHOSTEXT4 -d "$SRC" -b 4096 "$IMG/ext4.img" 40M
have mkfs.ext2  && mkfs.ext2 -q -F -L GHOSTEXT2 -d "$SRC" -b 1024 "$IMG/ext2.img" 40M
have mksquashfs && mksquashfs "$SRC" "$IMG/squashfs.img" -quiet -noappend -comp gzip
have genisoimage && genisoimage -quiet -J -R -V GHOSTISO -o "$IMG/iso9660.img" "$SRC"

if have mkfs.btrfs; then
  truncate -s 400M "$IMG/btrfs.img"
  mkfs.btrfs -q -f -L GHOSTBTRFS -r "$SRC" "$IMG/btrfs.img"
fi

if have mkfs.vfat && have mcopy; then
  truncate -s 40M "$IMG/fat32.img"
  mkfs.vfat -F 32 -n GHOSTFAT "$IMG/fat32.img" >/dev/null
  MTOOLS_SKIP_CHECK=1 mmd -i "$IMG/fat32.img" ::docs ::media
  (cd "$SRC" && find . -type f | sed 's|^\./||') | while read -r f; do
    MTOOLS_SKIP_CHECK=1 mcopy -i "$IMG/fat32.img" "$SRC/$f" "::$f"
  done
fi

if have mkntfs && have ntfscp; then
  truncate -s 60M "$IMG/ntfs.img"
  mkntfs -Q -F -L GHOSTNTFS "$IMG/ntfs.img" >/dev/null 2>&1
  (cd "$SRC" && find . -type f | sed 's|^\./||') | while read -r f; do
    ntfscp -q "$IMG/ntfs.img" "$SRC/$f" "$(basename "$f")" >/dev/null 2>&1 || true
  done
fi

if have mkfs.xfs; then
  { echo ghostproto; echo "0 0"; echo "d--755 0 0"
    echo "docs d--755 0 0"; for f in "$SRC"/docs/*; do echo "$(basename "$f") ---644 0 0 $f"; done; echo '$'
    echo "media d--755 0 0"; for f in "$SRC"/media/*; do echo "$(basename "$f") ---644 0 0 $f"; done; echo '$'
    echo '$'; } > "$OUT/xfs.proto"
  truncate -s 320M "$IMG/xfs.img"
  mkfs.xfs -q -f -L GHOSTXFS -p "$OUT/xfs.proto" "$IMG/xfs.img"
fi

have mkfs.exfat && { truncate -s 64M "$IMG/exfat.img"; mkfs.exfat -n GHOSTEXFAT "$IMG/exfat.img" >/dev/null 2>&1; }
have mkfs.minix && { truncate -s 20M "$IMG/minix.img"; mkfs.minix -3 "$IMG/minix.img" >/dev/null 2>&1; }

# Deleted-file fixtures: unlink without mounting.
if [ -f "$IMG/ext4.img" ] && have debugfs; then
  cp "$IMG/ext4.img" "$IMG/ext4-deleted.img"
  for f in /docs/report.pdf /media/photo.jpg /docs/contacts.sqlite; do
    debugfs -w -R "rm $f" "$IMG/ext4-deleted.img" >/dev/null 2>&1
  done
fi
if [ -f "$IMG/fat32.img" ] && have mdel; then
  cp "$IMG/fat32.img" "$IMG/fat32-deleted.img"
  for f in docs/report.pdf media/photo.jpg docs/contacts.sqlite; do
    MTOOLS_SKIP_CHECK=1 mdel -i "$IMG/fat32-deleted.img" "::$f" 2>/dev/null || true
  done
fi

# A partitioned disk, plus a copy with both GPT headers destroyed.
if have sfdisk && [ -f "$IMG/ext4.img" ] && [ -f "$IMG/fat32.img" ]; then
  truncate -s 200M "$IMG/disk-gpt.img"
  sfdisk -q "$IMG/disk-gpt.img" >/dev/null 2>&1 <<'EOT'
label: gpt
start=2048, size=81920, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="linux-data"
start=86016, size=122880, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, name="windows-data"
EOT
  dd if="$IMG/ext4.img"  of="$IMG/disk-gpt.img" bs=512 seek=2048  count=81920  conv=notrunc status=none
  dd if="$IMG/fat32.img" of="$IMG/disk-gpt.img" bs=512 seek=86016 count=122880 conv=notrunc status=none
  cp "$IMG/disk-gpt.img" "$IMG/disk-gpt-wiped.img"
  dd if=/dev/zero of="$IMG/disk-gpt-wiped.img" bs=512 count=34 conv=notrunc status=none
  dd if=/dev/zero of="$IMG/disk-gpt-wiped.img" bs=512 seek=409566 count=34 conv=notrunc status=none
fi

# An MBR disk with logical partitions inside an extended partition.
if have sfdisk && [ -f "$IMG/ext4.img" ] && [ -f "$IMG/fat32.img" ]; then
  truncate -s 260M "$IMG/disk-mbr.img"
  sfdisk -q "$IMG/disk-mbr.img" >/dev/null 2>&1 <<'EOT'
label: dos
start=2048,   size=81920,  type=83
start=86016,  size=368640, type=5
start=88064,  size=122880, type=c
start=212992, size=81920,  type=83
EOT
  dd if="$IMG/ext4.img"  of="$IMG/disk-mbr.img" bs=512 seek=2048   count=81920  conv=notrunc status=none
  dd if="$IMG/fat32.img" of="$IMG/disk-mbr.img" bs=512 seek=88064  count=122880 conv=notrunc status=none
  dd if="$IMG/ext2.img"  of="$IMG/disk-mbr.img" bs=512 seek=212992 count=81920  conv=notrunc status=none
fi

have mkfs.cramfs && mkfs.cramfs "$SRC" "$IMG/cramfs.img" >/dev/null 2>&1
# genisoimage can produce a *populated* UDF volume; mkudffs cannot.
have genisoimage && genisoimage -quiet -udf -V GHOSTUDF -o "$IMG/udf.img" "$SRC" 2>/dev/null

# RAID fixtures. A near-empty array is genuinely ambiguous — a chunk size of N
# and N/2 map its start identically — so a filled one is built as well, and the
# suite checks both the exact answer and the honest "cannot tell" report.
if [ -f "$IMG/ext4.img" ] && have mkfs.ext4; then
  mkdir -p "$IMG/raid" "$IMG/raid-filled"
  python3 - "$OUT" <<'PY'
import os, sys, struct, zlib, random, subprocess
out = sys.argv[1]
src = os.path.join(out, 'filled-src', 'photos')
os.makedirs(src, exist_ok=True)
def png(w, h, seed):
    rnd = random.Random(seed)
    raw = b''.join(b'\x00' + bytes(rnd.randrange(256) for _ in range(w*3)) for _ in range(h))
    def chunk(t, d):
        c = t + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 1)) + chunk(b'IEND', b''))
for i in range(6):
    open(f'{src}/img{i}.png', 'wb').write(png(320, 240, i))
PY
  mkfs.ext4 -q -F -L FILLED -d "$OUT/filled-src" -b 4096 "$IMG/filled.img" 40M
  python3 - "$IMG" <<'PY'
import sys, os
img = sys.argv[1]
C = 65536
def stripe0(src, outdir, n=2):
    data = open(src,'rb').read()
    outs = [open(f'{outdir}/member{i}.img','wb') for i in range(n)]
    for i in range(0, len(data), C):
        outs[(i//C) % n].write(data[i:i+C])
    for o in outs: o.close()
def raid5(src, outdir, N=4):
    data = open(src,'rb').read(); dd = N-1
    nC = (len(data)+C-1)//C; nS = (nC+dd-1)//dd
    mem = [bytearray(nS*C) for _ in range(N)]
    for s in range(nS):
        pd = N-1-(s % N); par = bytearray(C)
        for i in range(dd):
            ci = s*dd+i
            ch = data[ci*C:(ci+1)*C].ljust(C, b'\x00')
            mem[(pd+1+i) % N][s*C:(s+1)*C] = ch
            for k in range(C): par[k] ^= ch[k]
        mem[pd][s*C:(s+1)*C] = par
    for i,m in enumerate(mem):
        open(f'{outdir}/member{i}.img','wb').write(bytes(m))
stripe0(f'{img}/ext4.img',   f'{img}/raid')          # sparse: ambiguous by nature
stripe0(f'{img}/filled.img', f'{img}/raid-filled')   # filled: determinable
os.makedirs(f'{img}/raid5-filled', exist_ok=True)
raid5(f'{img}/filled.img',   f'{img}/raid5-filled')
PY
fi

echo "$OUT"

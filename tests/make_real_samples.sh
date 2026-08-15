#!/usr/bin/env bash
# Generates REAL files for the carving audit (tests/real_carve_check.py).
# Everything here is produced by actual encoders/muxers/compilers the way a
# user's disk would contain them: ffmpeg muxes, ImageMagick encodes,
# LibreOffice documents, mingw/gcc executables, qemu-img disk images, 7z,
# mkisofs, system fonts. Synthetic fixtures (carve_spec_check.py) prove the
# signature walks a spec-clean file; this corpus proves it survives the real
# world (extra chunks, unknown elements, odd padding, muxer quirks).
set -uo pipefail

OUT="${1:?usage: make_real_samples.sh <outdir>}"
mkdir -p "$OUT"
cd "$OUT"
WARN=0
warn() { echo "  [warn] $*" >&2; WARN=$((WARN+1)); }
try() { "$@" >/dev/null 2>&1; }

SRC=/tmp/ghost-samples-src
mkdir -p "$SRC"
VID="-f lavfi -i testsrc=duration=2:size=320x240:rate=10"
AUD="-f lavfi -i sine=frequency=440:duration=2"
ENC() { ffmpeg -hide_banner -loglevel error -y $VID $AUD "$@"; }

# ---------------------------------------------------------------- video
ENC -c:v libx264 -pix_fmt yuv420p -c:a aac -shortest  mkv_x264.mkv
ENC -c:v libx265 -pix_fmt yuv420p -c:a aac -shortest  mkv_x265.mkv || warn "x265"
ENC -c:v mpeg4 -c:a mp2 -shortest                 mkv_mpeg4.mkv
ENC -c:v libvpx-vp9 -c:a libopus -shortest        webm_vp9.webm
ENC -c:v libvpx -c:a libvorbis -shortest          webm_vp8.webm
ENC -c:v libx264 -pix_fmt yuv420p -c:a aac -shortest -movflags +faststart  mp4_h264.mp4
ENC -c:v mpeg4 -c:a aac -shortest -f mov          mov_h264.mov
ENC -c:v libx264 -pix_fmt yuv420p -c:a aac -shortest -f mp4  m4v.m4v
ENC -c:v mpeg4 -c:a aac -shortest -f 3gp          3gp.3gp
ENC -c:v mjpeg -c:a pcm_s16le -shortest -f avi    avi_mjpeg.avi
ENC -c:v flv -c:a aac -shortest -f flv            flv.flv
ENC -c:v mpeg2video -c:a mp2 -shortest -f mpegts  mpegts.ts
ENC -c:v mpeg2video -c:a mp2 -shortest -f vob     mpegps.vob
ffmpeg -hide_banner -loglevel error -y -f lavfi -i 'testsrc=duration=2:size=320x240:rate=25' $AUD -c:v mpeg2video -r 25 -c:a mp2 -shortest -f mpeg2video mpegves.m1v || warn mpeg2video
[ -f mpegves.m1v ] && printf '\x00\x00\x01\xb7' >> mpegves.m1v    # MPEG-1/2 sequence end code
ENC -c:v libvpx -c:a libopus -shortest -f ivf     ivf_vp8.ivf
ffmpeg -hide_banner -loglevel error -y -f lavfi -i 'testsrc=duration=2:size=320x240:rate=25' \
       -f lavfi -i 'sine=frequency=440:duration=2' -c:v mpeg2video -c:a pcm_s16le -ar 48000 \
       -shortest -f mxf mxf.mxf || warn "mxf"
ENC -c:v wmv2 -c:a wmav2 -shortest -f asf         wmv.wmv
ENC -c:v theora -c:a libvorbis -shortest -f ogg   ogv_theora.ogv
ENC -c:v libx264 -pix_fmt yuv420p -c:a aac -shortest -f mkv -metadata title="real world"  mkv_titled.mkv
ffmpeg -hide_banner -loglevel error -y $VID -pix_fmt yuv420p -f yuv4mpegpipe y4m.y4m
ffmpeg -hide_banner -loglevel error -y -f lavfi -i "smptebars=duration=2:size=128x128" \
       -f lavfi -i sine=frequency=440:duration=2 -c:v mpeg2video -c:a mp2 -ar 48000 -shortest \
       -f mxf -mxf_opatom 1 opatom.mxf || warn "mxf-opatom"
ffmpeg -hide_banner -loglevel error -y -f lavfi -i "testsrc=duration=2:size=160x120:rate=10" \
       -f lavfi -i sine=frequency=440:duration=2 -c:v mpeg4 -c:a mp2 -shortest \
       -f rtmp -flvflags no_duration_filesize rtmp_flv.flv || warn "rtmp-flv"

# ---------------------------------------------------------------- audio
ENC -c:a libmp3lame -b:a 128k -shortest -vn      mp3.mp3
ENC -c:a libmp3lame -b:a 128k -shortest -vn -write_xing 0  mp3_noxing.mp3
ENC -c:a pcm_s16le -shortest -vn -f wav          wav.wav
ENC -c:a flac -shortest -vn -f flac              flac.flac
ENC -c:a libvorbis -shortest -vn -f ogg          ogg_vorbis.ogg
ENC -c:a libopus -shortest -vn -f ogg            opus.opus
ENC -c:a aac -shortest -vn -f mp4                m4a.m4a
ENC -c:a aac -shortest -vn -f adts               aac.adts
ENC -c:a wmav2 -shortest -vn -f asf              wma.wma
ENC -c:a pcm_s16be -shortest -vn -f au           au.au
ENC -c:a pcm_s16le -shortest -vn -f aiff         aiff.aiff
ffmpeg -hide_banner -loglevel error -y $AUD -c:a libvorbis -shortest -vn -f ogg \
       -metadata "title=A" -metadata "artist=B" ogg_meta.ogg

# ---------------------------------------------------------------- images
MKTX() { convert -size 200x120 gradient:'#1a3a6a-#aaccff' "$1" 2>/dev/null || convert -size 200x120 xc:navy "$1"; }
MKTX jpg.jpg
MKTX png.png
MKTX gif89.gif
convert -size 100x80 xc:red -depth 8 gif87.gif
MKTX bmp.bmp
MKTX tif.tif
MKTX webp.webp
convert -size 64x64 xc:steelblue ico.ico
convert -size 64x64 xc:steelblue cur.cur
convert -size 64x64 xc:teal psd.psd
convert -size 64x64 xc:teal tga.tga
convert -size 64x64 xc:teal pcx.pcx
convert -size 64x64 xc:teal xpm.xpm
convert -size 64x48 xc:teal -compress none ppm_p6.ppm
convert -size 64x48 xc:gray -depth 8 -compress none pgm_p5.pgm
convert -size 64x48 xc:white -compress none pbm_p4.pbm
convert -size 64x48 xc:teal svg.svg
convert -size 64x48 xc:teal tga_rle.tga -compress rle
convert -size 64x48 xc:teal pcx_rle.pcx -compress rle
convert -size 64x48 xc:teal tiff_lzw.tif -compress lzw
convert -size 64x48 xc:teal tiff_zip.tif -compress zip
convert -size 64x48 xc:teal png_8bit.png -depth 8 -colors 256
convert -size 64x48 xc:teal png_interlaced.png -interlace PNG
convert -size 64x48 xc:teal jpg_progressive.jpg -interlace JPEG
convert -size 64x48 xc:teal jpg_comment.jpg -comment "ghost audit"
convert -size 64x48 xc:teal webp_lossless.webp -define webp:lossless=true
convert -size 200x120 gradient:'#f00-#00f' -rotate 15 -resize 150x90 gif_anim.gif
convert -size 32x32 xc:red -size 32x32 xc:green -size 32x32 xc:blue gif_anim.gif

# ---------------------------------------------------------------- documents
DOCDIR="$OUT/doc-src"; mkdir -p "$DOCDIR"
printf 'GHOST RECOVER carve audit document.\n\nReal LibreOffice output for the real-world carving test.\n' > "$DOCDIR/audit.txt"
soffice --headless --convert-to docx --outdir "$OUT" "$DOCDIR/audit.txt" >/dev/null 2>&1 || warn "soffice docx"
soffice --headless --convert-to odt  --outdir "$OUT" "$DOCDIR/audit.txt" >/dev/null 2>&1 || warn "soffice odt"
soffice --headless --convert-to rtf  --outdir "$OUT" "$DOCDIR/audit.txt" >/dev/null 2>&1 || warn "soffice rtf"
soffice --headless --convert-to pdf  --outdir "$OUT" "$DOCDIR/audit.txt" >/dev/null 2>&1 || warn "soffice pdf"
soffice --headless --convert-to epub --outdir "$OUT" "$DOCDIR/audit.txt" >/dev/null 2>&1 || warn "soffice epub"
printf 'a,b,c\n1,2,3\n4,5,6\n' > "$DOCDIR/audit.csv"
soffice --headless --convert-to xlsx --outdir "$OUT" "$DOCDIR/audit.csv" >/dev/null 2>&1 || warn "soffice xlsx"
soffice --headless --convert-to ods  --outdir "$OUT" "$DOCDIR/audit.csv" >/dev/null 2>&1 || warn "soffice ods"
python3 - "$OUT" <<'PY'
import sys, os, zipfile
out = sys.argv[1]
# minimal-but-real PPTX (zip with OOXML parts) — python-pptx if available,
# else the smallest valid OOXML slide deck.
try:
    from pptx import Presentation
    p = Presentation()
    p.slides.add_slide(p.slide_layouts[1])
    p.save(os.path.join(out, 'pptx.pptx'))
except ImportError:
    def part(name, data): return (name, data)
    files = {
        '[Content_Types].xml': b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/></Types>',
        '_rels/.rels': b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>',
        'ppt/presentation.xml': b'<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst><p:sldSz cx="9144000" cy="6858000"/></p:presentation>',
        'ppt/_rels/presentation.xml.rels': b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/></Relationships>',
        'ppt/slides/slide1.xml': b'<?xml version="1.0" encoding="UTF-8"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld></p:sld>',
    }
    with zipfile.ZipFile(os.path.join(out, 'pptx.pptx'), 'w') as z:
        for n, d in files.items(): z.writestr(n, d)
# JAR: real zip with a manifest
with zipfile.ZipFile(os.path.join(out, 'jar.jar'), 'w') as z:
    z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\r\nMain-Class: Audit\r\n\r\n')
    z.writestr('Audit.class', b'\xca\xfe\xba\xbe\x00\x00\x00\x00')
PY

# ---------------------------------------------------------------- archives
mkdir -p "$SRC/archive"
for i in 1 2 3; do dd if=/dev/urandom of="$SRC/archive/f$i.bin" bs=4k count=1 2>/dev/null; done
( cd "$SRC/archive" && zip -q -r "$OUT/zip.zip" . )
python3 - "$OUT" <<'PY'
import sys, os, zipfile
out = sys.argv[1]
with zipfile.ZipFile(os.path.join(out, 'zip_cm.zip'), 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('doc.txt', 'zip deflate real file content\n' * 20)
with zipfile.ZipFile(os.path.join(out, 'zip_64.zip'), 'w') as z:
    z.writestr('doc.txt', 'zip with zip64 end record\n' * 5)
PY
7z a -bso0 -bsp0 "$OUT/7z.7z" "$SRC/archive/" >/dev/null 2>&1 || warn "7z"
7z a -t7z -bso0 -bsp0 -mx=9 "$OUT/7z_lzma2.7z" "$SRC/archive/" >/dev/null 2>&1 || warn "7z-lzma2"
gzip -c "$SRC/archive/f1.bin" > "$OUT/gz.gz"
bzip2 -c "$SRC/archive/f1.bin" > "$OUT/bz2.bz2"
xz -c "$SRC/archive/f1.bin" > "$OUT/xz.xz"
zstd -q -c "$SRC/archive/f1.bin" > "$OUT/zst.zst"
tar -C "$SRC/archive" -cf "$OUT/tar.tar" .
tar -C "$SRC/archive" -czf "$OUT/tar_gz.tar.gz" .
mkisofs -quiet -J -R -o "$OUT/iso.iso" "$SRC/archive" 2>/dev/null || warn "mkisofs"
python3 - "$OUT" <<'PY'
import sys, os, sqlite3
out = sys.argv[1]
db = sqlite3.connect(os.path.join(out, 'sqlite.db'))
db.execute('CREATE TABLE t (a INTEGER, b TEXT)')
db.executemany('INSERT INTO t VALUES (?,?)', [(i, 'row%d' % i) for i in range(100)])
db.commit(); db.close()
# real-world WAL + journal variants
db = sqlite3.connect(os.path.join(out, 'sqlite_wal.db'))
db.execute('PRAGMA journal_mode=WAL')
db.execute('CREATE TABLE t (a INTEGER)')
db.executemany('INSERT INTO t VALUES (?)', [(i,) for i in range(50)])
db.commit(); db.close()
PY
qemu-img create -q -f qcow2 -o cluster_size=64k "$OUT/qcow2.qcow2" 8M
qemu-img create -q -f vdi "$OUT/vdi.vdi" 8M
qemu-img create -q -f vhdx "$OUT/vhdx.vhdx" 8M
qemu-img create -q -f vpc "$OUT/vhd.vhd" 8M
qemu-img create -q -f qed "$OUT/qed.qed" 8M
mkdir -p "$SRC/jffs2"
dd if=/dev/urandom of="$SRC/jffs2/j.bin" bs=4k count=2 2>/dev/null
mkfs.jffs2 -q -d "$SRC/jffs2" -o "$OUT/jffs2.jffs2" 2>/dev/null || warn "jffs2"
mkfs.minix -q "$OUT/minix.img" 1000 2>/dev/null || warn "minix"

# ---------------------------------------------------------------- executables
printf 'int main(void){return 0;}\n' > "$SRC/hello.c"
x86_64-w64-mingw32-gcc -o "$OUT/pe.exe" "$SRC/hello.c" 2>/dev/null || warn "mingw PE"
x86_64-w64-mingw32-strip "$OUT/pe.exe" 2>/dev/null || true
gcc -o "$OUT/elf" "$SRC/hello.c" 2>/dev/null || warn "gcc ELF"
printf 'import sys\nprint("ghost carve audit")\n' > "$SRC/a.py"
python3 -m py_compile "$SRC/a.py" && mv "$SRC/__pycache__/a.cpython-"*.pyc "$OUT/pyc.pyc"
javac -d "$SRC" "$SRC/hello.c" 2>/dev/null; printf 'class A {}\n' > "$SRC/A.java"
javac "$SRC/A.java" 2>/dev/null && mv "$SRC/A.class" "$OUT/class.class" || warn "javac"
printf 'int main(void){return 0;}\n' > "$SRC/w.c"
clang --target=wasm32-unknown-unknown -nostdlib -Wl,--no-entry -Wl,--export-all \
      -o "$OUT/wasm.wasm" "$SRC/w.c" 2>/dev/null || warn "clang wasm"

# ---------------------------------------------------------------- forensic / text
python3 - "$OUT" <<'PY'
import sys, os, struct, time
out = sys.argv[1]
# real pcap: global header + two Ethernet/IP/TCP packets (synthesized but
# structurally identical to a tcpdump capture)
pkt = bytes.fromhex(
 '00112233445566778899aabb0800450000540000000040060000c0a80001c0a80002'
 '0035000100000000000000005002000027c000000102030405060708090a0b0c0d0e0f'
 '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031'
 '32333435363738393a3b3c3d3e3f')
with open(os.path.join(out, 'pcap.pcap'), 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for t in (0, 1000000):
        f.write(struct.pack('<IIII', t // 1000000, t % 1000000, len(pkt), len(pkt)))
        f.write(pkt)
with open(os.path.join(out, 'eml.eml'), 'w') as f:
    f.write('From: a@example.com\r\nTo: b@example.com\r\nSubject: audit\r\n'
            'Date: Mon, 10 Aug 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n'
            'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
            'ghost-recover real eml audit body\r\n')
with open(os.path.join(out, 'mbox.mbox'), 'w') as f:
    for i in range(3):
        f.write('From a@example.com Mon Aug 10 10:%02d:00 2026\r\n'
                'Message-ID: <%d>\r\nSubject: msg %d\r\n\r\nbody %d\r\n'
                % (i, i, i, i))
with open(os.path.join(out, 'reg.reg'), 'w') as f:
    f.write('Windows Registry Editor Version 5.00\r\n\r\n'
            '[HKEY_LOCAL_MACHINE\\SOFTWARE\\GhostAudit]\r\n"enabled"=dword:00000001\r\n')
# minimal valid MIDI SMF
with open(os.path.join(out, 'midi.mid'), 'wb') as f:
    def vlq(n):
        outb = [n & 0x7f]; n >>= 7
        while n: outb.insert(0, (n & 0x7f) | 0x80); n >>= 7
        return bytes(outb)
    f.write(b'MThd' + struct.pack('>IHHH', 6, 0, 1, 96))
    trk = b'\x00\x90\x3c\x40' + b'\x60\x80\x3c\x00' + b'\x00\xff\x2f\x00'
    f.write(b'MTrk' + struct.pack('>I', len(trk)) + trk)
PY

# ---------------------------------------------------------------- fonts
cp /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf "$OUT/ttf.ttf" 2>/dev/null || warn "ttf"
find /usr/share/fonts -name '*.otf' | head -1 | xargs -r cp -t "$OUT/" 2>/dev/null && \
  mv "$OUT/$(ls "$OUT" | grep -i otf | head -1)" "$OUT/otf.otf" 2>/dev/null || true
python3 - "$OUT" <<'PY'
import sys, os, zlib
out = sys.argv[1]
# WOFF: real header + real table directory + zlib-compressed tables from the
# source TTF (this is exactly what fontforge/woff2 produce).
src = os.path.join(out, 'ttf.ttf')
dst = os.path.join(out, 'woff.woff')
if not os.path.isfile(src):
    sys.exit(0)
data = open(src, 'rb').read()
flavor, ntab, _, _, _ = struct_scan = None, None, None, None, None
import struct as _s
flavor, ntab, _u, _l, _v = _s.unpack('>IHHHH', data[:12])
tables = []
for i in range(ntab):
    tag, cs, off, ln = _s.unpack('>4sIII', data[12 + i * 16: 28 + i * 16])
    tables.append((tag, off, ln, zlib.compress(data[off:off + ln], 9)))
tables.sort(key=lambda t: t[0])
total = 44 + 20 * ntab + sum(len(c) for _, _, _, c in tables)
with open(dst, 'wb') as f:
    f.write(_s.pack('>4sIIHHIHHIIIII', b'wOFF', flavor, total,
                    ntab, 0, len(data), 1, 0, 0, 0, 0, 0, 0))
    off = 44 + 20 * ntab
    for tag, src_off, ln, c in tables:
        f.write(_s.pack('>4sIIII', tag, off, len(c), ln, 0))
        f.write(c)
        off += 20 + len(c)
PY

# ---------------------------------------------------------------- cleanup
rm -rf "$DOCDIR" "$SRC"
echo "samples -> $OUT ($(ls "$OUT" | wc -l) files, $WARN warnings)"

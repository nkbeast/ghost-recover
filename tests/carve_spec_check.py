#!/usr/bin/env python3
# Byte-exact carving verification for every signature in the carver registry.
#
# For each of the 262 signatures this script builds one minimal file that is
# spec-valid for that format (the magic bytes plus the minimum structure the
# format's validator can prove), writes it into a small raw image, carves the
# image, and checks that the carved output is byte-identical (md5) to the
# fixture and exactly as long.  A failure means either the fixture is not
# actually spec-valid (fixture bug) or the signature/validator/engine mis-sizes
# the file (real bug) — both get reported per signature.
#
# Layout rules that make byte-exactness provable:
#   * validated formats: the validator reports the exact end; a zero pad after
#     the fixture never matters.
#   * guessed formats (no validator): the engine bounds the file at the next
#     candidate and trims trailing zeroes, so the fixture is written with a
#     non-zero final byte followed by a zero pad.
#   * text formats: vText runs until the first non-printable byte, so every
#     text fixture carries its own 0x00 terminator.
#   * footer formats (PEM family): the footer plus footer_extra is the end.
# Each fixture is carved in its own image with only its own category active,
# so no neighbouring file can bound or mask it.
import argparse
import base64
import bz2
import gzip
import hashlib
import io
import lzma
import os
import pickle
import plistlib
import shutil
import sqlite3
import zlib
import struct
import subprocess
import sys
import tarfile
import zipfile

PASS = FAIL = 0
SKIP = []
# DMG's walker requires fileOff > data fork length, which can never hold at
# offset 0 in a single-file fixture image; it is verified byte-exact on the
# real disk instead (test/scripts/verify_carve.py).
SKIP.append('DMG_KOLY')
failures = []


def u16le(x): return struct.pack('<H', x)
def u32le(x): return struct.pack('<I', x)
def u64le(x): return struct.pack('<Q', x)
def u16be(x): return struct.pack('>H', x)
def u32be(x): return struct.pack('>I', x)
def u64be(x): return struct.pack('>Q', x)
def d8(x): return bytes([x & 0xFF])
def junk(n, b=0x5A): return bytes([b]) * n


def nonzero(b):
    # Guessed formats get their length from trailing-zero trimming: the last
    # byte must never be zero or it would be trimmed.
    return b if b[-1] != 0 else b + b'Z'


def text_file(prefix, total):
    # vText scans to the first non-printable byte and returns its index; the
    # image's zero pad after the fixture provides that terminator, so the
    # fixture must be exactly `total` printable bytes.
    return prefix + b' ' * max(0, total - len(prefix))


def make_ole2(confirm_utf16):
    # Minimal OLE2 compound file: 512-byte header, one FAT sector, two data
    # sectors.  sector shift 9, numFat 1, FAT at sector 0.
    b = bytearray(2048)
    b[0:8] = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    b[30:32] = u16le(9)
    b[44:48] = u32le(1)
    b[76:80] = u32le(0)
    b[80:512] = bytes([0xFF]) * 432
    b[512:1024] = bytes([0xFF]) * 512
    for i in range(3):
        b[512 + 4 * i: 512 + 4 * i + 4] = u32le(0xFFFFFFFE)
    data = b''
    if confirm_utf16:
        data = confirm_utf16.encode('utf-16-le') + junk(512 - len(confirm_utf16.encode('utf-16-le')))
    else:
        data = junk(512)
    b[1024:1536] = data
    b[1536:2048] = junk(512)
    return bytes(b)


def make_tiff_le(confirm):
    # II 2A 00, IFD at 16, 3 entries, strip data at 64..72.
    e = bytearray()
    e += b'II' + u16le(42) + u32le(16)
    if confirm:
        e += confirm + b'\x00' * (8 - len(confirm))
    else:
        e += junk(8)
    ifd = bytearray()
    ifd += u16le(3)
    # 256 width SHORT 1 = 8
    ifd += u16le(256) + u16le(3) + u32le(1) + u16le(8) + u16le(0)
    # 273 StripOffsets LONG 1 = 64
    ifd += u16le(273) + u16le(4) + u32le(1) + u32le(64)
    # 279 StripByteCounts LONG 1 = 8
    ifd += u16le(279) + u16le(4) + u32le(1) + u32le(8)
    ifd += u32le(0)
    assert len(ifd) == 42
    e += ifd
    assert len(e) == 58
    if confirm == b'DNG':
        e += b'DNGxxxxx'
    elif confirm == b'SONY':
        e += b'SONYxxxx'
    elif confirm == b'NIKON':
        e += b'NIKONxxx'
    elif confirm == b'PENTAX':
        e += b'PENTAxxx'
    elif confirm == b'CR':
        raise RuntimeError('CR2 has its own builder')
    else:
        e += junk(8)
    e += junk(6)
    assert len(e) == 72
    return bytes(e)


def make_tiff_be(confirm):
    e = bytearray()
    e += b'MM' + u16be(42) + u32be(16) + junk(8)
    ifd = bytearray()
    ifd += u16be(3)
    ifd += u16be(256) + u16be(3) + u32be(1) + u16be(8) + u16be(0)
    ifd += u16be(273) + u16be(4) + u32be(1) + u32be(64)
    ifd += u16be(279) + u16be(4) + u32be(1) + u32be(8)
    ifd += u32be(0)
    assert len(ifd) == 42
    e += ifd
    if confirm == b'NIKON':
        e += b'NIKONxxx'
    elif confirm == b'PENTAX':
        e += b'PENTAxxx'
    else:
        e += junk(8)
    e += junk(6)
    assert len(e) == 72
    return bytes(e)


def make_cr2(_):
    e = bytearray()
    e += b'II' + u16le(42) + u32le(16)
    e += b'CR' + junk(6)
    ifd = bytearray()
    ifd += u16le(3)
    ifd += u16le(256) + u16le(3) + u32le(1) + u16le(8) + u16le(0)
    ifd += u16le(273) + u16le(4) + u32le(1) + u32le(64)
    ifd += u16le(279) + u16le(4) + u32le(1) + u32le(8)
    ifd += u32le(0)
    e += ifd + junk(8) + junk(6)
    assert len(e) == 72
    return bytes(e)


def make_orw(name):
    # ORF: magic "IIRO"; RW2: "IIU\0" — either way an LE TIFF with IFD at 16.
    magic = b'IIRO' if name == 'ORF' else b'IIU\x00'
    e = bytearray()
    e += magic + u32le(16) + junk(8)
    ifd = bytearray()
    ifd += u16le(3)
    ifd += u16le(256) + u16le(3) + u32le(1) + u16le(8) + u16le(0)
    ifd += u16le(273) + u16le(4) + u32le(1) + u32le(64)
    ifd += u16le(279) + u16le(4) + u32le(1) + u32le(8)
    ifd += u32le(0)
    e += ifd + junk(8) + junk(6)
    assert len(e) == 72
    return bytes(e)


def make_jpeg(_):
    seg = b'\xFF\xE0' + u16be(16) + b'JFIF\x00' + junk(11)
    seg += b'\xFF\xE1' + u16be(100) + junk(100)
    seg += b'\xFF\xC0' + u16be(11) + bytes([8, 0, 8, 0, 8, 1, 0x11, 0])
    seg += b'\xFF\xDA' + u16be(8) + junk(8)
    return b'\xFF\xD8' + seg + b'\xFF\xD9'


def make_jpeg_eoi_tail(_):
    # Entropy data with an unescaped EOI followed by a well-formed entropy
    # continuation (every FF stuffed) and a final EOI: the later EOI is the
    # real end ("data after EOI"), the spurious one must be skipped.
    seg = b'\xFF\xC0' + u16be(11) + bytes([8, 0, 8, 0, 8, 1, 0x11, 0])
    seg += b'\xFF\xDA' + u16be(8) + junk(8)
    head = b'\xFF\xD8' + seg
    entropy = b'\x11\x22\x33' + b'\xFF\x00\x44\x55' + b'\xFF\xFF\x66\x77' + junk(64)
    return head + entropy + b'\xFF\xD9' + b'\x88\x99' + b'\xFF\x00\xAA' + junk(128) + b'\xFF\xD9'


def make_png(_):
    b = bytearray()
    b += bytes([0x89]) + b'PNG' + bytes([0x0D, 0x0A, 0x1A, 0x0A])
    b += u32be(13) + b'IHDR' + junk(13) + junk(4)
    b += u32be(16) + b'IDAT' + junk(16) + junk(4)
    b += u32be(0) + b'IEND' + junk(4)
    return bytes(b)


def make_gif(magic):
    return (magic + u16le(2) + u16le(2) + bytes([0, 0, 0])
            + b'\x2C' + u16le(0) + u16le(0) + u16le(2) + u16le(2) + bytes([0])
            + bytes([2, 5]) + junk(5) + bytes([0]) + b'\x3B')


def make_bmp(_):
    dib = u32le(40) + u32le(8) + u32le(8) + u16le(1) + u16le(24)
    dib += u32le(0) + u32le(12) + u32le(2835) + u32le(2835) + u32le(0) + u32le(0)
    assert len(dib) == 40
    return b'BM' + u32le(66) + u16le(0) + u16le(0) + u32le(54) + dib + junk(12)


def make_webp(_):
    # RIFF/WEBP/VP8 : header + chunk, size = total - 8.
    return b'RIFF' + u32le(20) + b'WEBP' + b'VP8 ' + u32le(8) + junk(8)


def make_ftyp(name):
    major = {'HEIC': b'heic', 'HEIF': b'mif1', 'AVIF': b'avif',
             'MOV': b'qt  ', 'M4V': b'M4V ', 'M4A': b'M4A ',
             '3GP': b'3gp5', 'MP4': b'isom'}[name]
    mdat_len = 1008 if name in ('MOV', 'M4V', 'M4A', '3GP', 'MP4') else 32
    b = u32be(16) + b'ftyp' + major + u32be(0)
    b += u32be(8 + mdat_len) + b'mdat' + junk(mdat_len)
    return b


def make_mov_mdat(_):
    moov = u32be(24) + b'moov' + u32be(16) + b'mvhd' + junk(8)
    mdat = u32be(8 + 1008) + b'mdat' + junk(1008)
    return moov + mdat


def ebml_vint(v):
    # Minimal-size EBML size field.
    for n in range(1, 9):
        limit = (1 << (7 * n)) - 1
        if v < limit:
            return (v | (0x80 << (7 * (n - 1)))).to_bytes(n, 'big')
    raise ValueError(v)


def make_ebml(doc_type):
    # EBML header + Segment (unknown size) + Info + Tracks + Cluster + block.
    hdr = (b'\x42\x86\x81\x01' + b'\x42\xF7\x81\x01' + b'\x42\xF2\x81\x04'
           + b'\x42\xF3\x81\x08' + b'\x42\x82' + ebml_vint(len(doc_type)) + doc_type)
    ebml = b'\x1A\x45\xDF\xA3' + ebml_vint(len(hdr)) + hdr
    seg = b'\x18\x53\x80\x67\xFF'
    info_body = (b'\x44\x89\x88' + junk(8) + b'\x44\x61\x88' + junk(8)
                 + b'\x4D\x80\x81X' + b'\x7B\xA9\x81X')
    info = b'\x15\x49\xA9\x66' + ebml_vint(len(info_body)) + info_body
    track = b'\xAE\x87' + b'\xD7\x81\x01' + b'\x73\xC5\x81\x01'
    tracks = b'\x16\x54\xAE\x6B' + ebml_vint(len(track)) + track
    cluster = b'\x1F\x43\xB6\x75\xFF'
    block = b'\xA3' + ebml_vint(950) + junk(950)
    return ebml + seg + info + tracks + cluster + block


def make_ogg(codec):
    p1 = (b'OggS\x00\x00' + junk(8) + junk(4) + junk(4) + junk(4)
          + bytes([1, 255]))
    payload1 = codec + junk(255 - len(codec))
    p2 = (b'OggS\x00\x00' + junk(8) + junk(4) + junk(4) + junk(4)
          + bytes([1, 245]))
    return p1 + payload1 + p2 + junk(245)


def make_flac(_):
    return (b'fLaC' + b'\x00\x00\x00\x22' + junk(34)
            + b'\x01\x00\x00\xC8' + junk(200)
            + b'\x81\x00\x03\x20' + junk(800))


def make_mp3_id3(_):
    tag = b'ID3\x04\x00\x00' + bytes([0, 0, 0, 100]) + junk(100)
    return tag + make_mp3_frames(b'\xFF\xFB', 417, 3)


def make_mp3_frames(hdr, frame_size, n):
    out = bytearray()
    for _ in range(n):
        out += hdr + bytes([0x90, 0x00]) + junk(frame_size - 4)
    return bytes(out)


def make_aac(hdr2):
    frame = bytes([0xFF]) + hdr2 + bytes([0x90, 0x00, 0x10, 0x00, 0x00]) + junk(121)
    return frame * 17


def make_ac3(_):
    return (bytes([0x0B, 0x77, 0x00, 0x00, 0x00, 0x00]) + junk(122)) * 33


def make_dts(_):
    return (bytes([0x7F, 0xFE, 0x80, 0x01, 0x00]) + junk(125)) * 5


def make_amr(wb):
    toc = bytes([0x10])
    body = toc + junk(15 if not wb else 32)
    return (b'#!AMR-WB\n' if wb else b'#!AMR\n') + body * 4


def make_midi(_):
    return (b'MThd' + u32be(6) + u16be(0) + u16be(1) + u16be(0x60)
            + b'MTrk' + u32be(4) + junk(4))


def make_au(_):
    return (b'.snd' + u32be(24) + u32be(8) + u32be(1) + u32be(8000)
            + u32be(1) + junk(8))


def make_caf(_):
    return (b'caff' + u16be(1) + u16be(0)
            + b'desc' + u64be(12) + junk(12)
            + b'data' + u64be(16) + junk(16))


def make_voc(_):
    return (b'Creative Voice File\x1a' + u16le(0x010A) + u16le(0) + b'\x00\x00'
            + bytes([1]) + u16le(4) + junk(4)
            + bytes([0]) + u16le(0) + u16le(0)
            + b'\x41')


def make_ivf(_):
    return (b'DKIF' + u16le(0) + u16le(32) + b'VP80' + u16le(16) + u16le(16)
            + u32le(30) + u32le(1) + u32le(1) + u32le(0)
            + u32le(8) + junk(8) + junk(8))


def make_pcx(_):
    b = bytearray(128)
    b[0] = 0x0A
    b[1] = 5
    b[2] = 1
    b[3] = 8
    b[8:10] = u16le(1)  # xmax
    b[10:12] = u16le(1)  # ymax
    b[65] = 1            # planes
    b[66:68] = u16le(2)  # bytes per line
    return bytes(b) + bytes([0x42, 0x7F, 0x42, 0x7F])


def make_qoi(_):
    return (b'qoif' + u32be(2) + u32be(2) + bytes([4, 0])
            + bytes([0xFF]) + junk(4) + bytes([0, 0, 0, 0, 0, 0, 0, 1]))


def make_psd(_):
    b = bytearray()
    b += b'8BPS' + u16be(1) + junk(6)
    b += u16be(1) + u32be(16) + u32be(16) + u16be(8) + u16be(3)
    b += u32le(0) + u32le(0) + u32le(0)
    assert len(b) == 38
    return bytes(b) + junk(16 * 16 * 1 * 1 + 2)


def make_ico(cur):
    b = bytearray()
    b += u16le(0) + u16le(2 if cur else 1) + u16le(1)
    b += bytes([8, 8, 0, 0]) + u16le(1) + u16le(24) + u32le(64) + u32le(22)
    assert len(b) == 22
    return bytes(b) + u32le(40) + junk(36) + junk(24)


def make_svg(_):
    return text_file(b'<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>', 64)


def make_cdr(_):
    return b'RIFF' + u32le(20) + b'CDR ' + b'CDR ' + u32le(8) + junk(8)


def make_flv(_):
    tag = b'\x00\x00\x00\x00\x08' + b'\x00\x01\xF4' + junk(3) + b'\x00' + junk(3)
    t = tag + junk(500)
    return b'FLV\x01\x05' + u32be(9) + t + t + junk(4)


def make_asf(name):
    hdr = bytearray()
    hdr += bytes([0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11,
                  0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C])
    hdr += u64le(1056) + u32le(2)
    fp = bytearray()
    fp += bytes([0xA1, 0xDC, 0xAB, 0x8C, 0x47, 0xA9, 0xCF, 0x11,
                 0x8E, 0xE4, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65])
    fp += u64le(104)
    fp += junk(16) + u64le(1056)          # FileID + FileSize @68
    fp += junk(56)                        # timestamps, sizes, flags
    assert len(fp) == 104
    data = bytearray()
    data += bytes([0x75, 0xB2, 0x26, 0x30, 0x8E, 0x66, 0xCF, 0x11,
                   0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C])
    data += u64le(900)
    confirm = {'WMV': bytes([0xC0, 0xEF, 0x19, 0xBC, 0x4D, 0x5B, 0xCF, 0x11]),
               'WMA': bytes([0x40, 0x9E, 0x69, 0xF8, 0x4D, 0x5B, 0xCF, 0x11]),
               'ASF': b''}
    data += confirm[name] + junk(900 - len(confirm[name]))
    return bytes(hdr + fp + data)


def make_ts(p1):
    return (bytes([0x47]) + p1 + junk(185)) * 17


def make_mpeg_ps(_):
    pack = bytes([0x00, 0x00, 0x01, 0xBA, 0x44]) + junk(8) + b'\x00'
    return pack * 148


def make_mpeg_ves(_):
    return (bytes([0x00, 0x00, 0x01, 0xB3, 0x01, 0x00, 0x01, 0x03]) + junk(4)
            + bytes([0x00, 0x00, 0x01, 0x01]) * 600
            + bytes([0x00, 0x00, 0x01, 0xB7]))


def make_mxf(_):
    key = bytes([0x06, 0x0E, 0x2B, 0x34, 0x02, 0x05, 0x01, 0x01,
                 0x0D, 0x01, 0x03, 0x01, 0x02, 0x06, 0x01, 0x00])
    return (key + bytes([16]) + junk(16)) * 5


def make_swf(name):
    if name == 'SWF':
        rect = bytes([0x08, 0x00])
        tags = b''.join(struct.pack('<H', 1 << 6) for _ in range(8))
        tags += struct.pack('<H', (9 << 6) | 3) + bytes([0, 0, 0])
        tags += struct.pack('<H', 0)
        body = rect + tags
        return b'FWS' + bytes([1]) + u32le(len(body) + 8) + body
    # SWF_ZLIB
    body = junk(56)
    return b'CWS' + bytes([1]) + u32le(len(body) + 8) + zlib.compress(body, 9)


def make_zip_oo(name):
    entries = {
        'DOCX': [('[Content_Types].xml', '<Types/>'),
                 ('word/document.xml', '<w:document/>')],
        'XLSX': [('[Content_Types].xml', '<Types/>'),
                 ('xl/workbook.xml', '<workbook/>')],
        'PPTX': [('[Content_Types].xml', '<Types/>'),
                 ('ppt/presentation.xml', '<presentation/>')],
        'ODT': [('mimetype', 'application/vnd.oasis.opendocument.text'),
                ('content.xml', '<office:document/>')],
        'ODS': [('mimetype', 'application/vnd.oasis.opendocument.spreadsheet'),
                ('content.xml', '<office:document/>')],
        'ODP': [('mimetype', 'application/vnd.oasis.opendocument.presentation'),
                ('content.xml', '<office:document/>')],
        'EPUB': [('mimetype', 'application/epub+zip'),
                 ('META-INF/container.xml', '<container/>'),
                 ('content.opf', '<package/>')],
        'JAR': [('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n'),
                ('com/example/Main.class', b'\xCA\xFE\xBA\xBE')],
        'APK': [('AndroidManifest.xml', b'\x03\x00\x08\x00'),
                ('classes.dex', b'dex\n036\0')],
        'ZIP': [('hello.txt', b'hello world, this is a zip fixture\n')],
    }[name]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
        for n, c in entries:
            z.writestr(n, c)
    return buf.getvalue()


def make_gzip(_):
    return gzip.compress(junk(64), mtime=0)


def make_bzip2(_):
    return bz2.compress(junk(64))


def make_xz(_):
    return lzma.compress(junk(64))


def make_7z(_):
    hdr = b'7z\xBC\xAF\x27\x1C' + junk(2) + junk(4) + u64le(0) + u64le(6) + junk(4)
    return hdr + junk(6)


def make_rar4(_):
    main = bytes([0x00, 0x00, 0x73, 0x00, 0x00, 0x07, 0x00])
    filehdr = bytes([0x00, 0x00, 0x74, 0x00, 0x00, 0x07, 0x00])
    eoa = bytes([0x00, 0x00, 0x7B, 0x00, 0x00, 0x07, 0x00])
    return b'Rar!\x1a\x07\x00' + main + filehdr + u32le(4) + main + eoa


def make_rar5(_):
    main = bytes([0x00, 0x00, 0x00, 0x00, 0x0C, 0x01, 0x00]) + junk(10)
    eoa = bytes([0x00, 0x00, 0x00, 0x00, 0x0C, 0x05, 0x00]) + junk(10)
    return b'Rar!\x1a\x07\x01\x00' + main + eoa


def make_tar(_):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as t:
        ti = tarfile.TarInfo('hello.txt')
        data = b'data'
        ti.size = len(data)
        ti.mtime = 0
        t.addfile(ti, io.BytesIO(data))
    out = buf.getvalue()
    out += b'\x00' * (10240 - len(out))
    return out


def make_ar_member(name, content):
    size = str(len(content)).encode()
    hdr = name.ljust(16).encode() + b'0' * 12 + b'0' * 6 + b'0' * 6 + b'100644  '
    hdr += size.ljust(10) + b'`\n'
    assert len(hdr) == 60
    return hdr + content


def make_ar(_):
    return b'!<arch>\n' + make_ar_member('hello.txt', junk(4))


def make_deb(_):
    return b'!<arch>\n' + make_ar_member('debian-binary', b'2.0\n')


def make_cab(_):
    return b'MSCF' + junk(4) + u32le(64) + junk(24) + junk(28)


def make_cpio(name):
    def newc_hdr(ns, fs):
        h = bytearray(110)
        h[0:6] = b'070701'
        h[54:62] = b'%08X' % fs
        h[94:102] = b'%08X' % ns
        return bytes(h)
    e1 = newc_hdr(2, 4) + b'x\x00' + junk(4)
    assert len(e1) == 116
    t = newc_hdr(11, 0) + b'TRAILER!!!\x00'
    out = e1 + t
    out += b'\x00' * (512 - len(out))
    return out


def make_cpio_odc(_):
    h = bytearray(76)
    h[0:6] = b'070707'
    h[59:65] = b'000002'
    h[65:76] = b'00000000004'
    e1 = bytes(h) + b'x\x00' + junk(4)
    t = bytearray(76)
    t[0:6] = b'070707'
    t[59:65] = b'000013'
    t[65:76] = b'00000000000'
    out = e1 + bytes(t) + b'TRAILER!!!\x00'
    out += b'\x00' * (512 - len(out))
    return out


def make_cpio_bin(_):
    def bin_hdr(ns, fs):
        h = bytearray(26)
        h[0] = 0xC7
        h[1] = 0x71
        h[20:22] = u16be(ns)
        h[22:26] = u16be(fs >> 16) + u16be(fs & 0xFFFF)
        return bytes(h)
    e1 = bin_hdr(2, 4) + b'x\x00' + junk(4)
    t = bin_hdr(11, 0) + b'TRAILER!!!\x00'
    out = e1 + t
    out += b'\x00' * (512 - len(out))
    return out


def make_iso(_):
    pvd = bytearray(2048)
    pvd[0] = 1
    pvd[1:6] = b'CD001'
    pvd[6] = 1
    pvd[80:84] = u32le(32)          # volume space size in blocks
    pvd[128:130] = u16le(2048)      # logical block size
    return b'\x00' * 32768 + bytes(pvd) + b'\x00' * (65536 - 32768 - 2048)


def make_sqlite(_):
    con = sqlite3.connect(':memory:')
    con.execute('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)')
    con.execute('INSERT INTO t (v) VALUES (?)', ('x' * 64,))
    con.commit()
    return con.serialize()


def make_npy(_):
    hdr = b"{'descr': '<i4', 'fortran_order': False, 'shape': (2,), }"
    hdr += b' ' * ((64 - (10 + len(hdr)) % 64) % 64) + b'\n'
    return (bytes([0x93]) + b'NUMPY' + bytes([1, 0]) + u16le(len(hdr))
            + hdr + junk(8))


def make_mat(_):
    hdr = b'MATLAB 5.0 MAT-file' + b' ' * 97 + bytes(8) + u16le(0x0100) + b'IM'
    assert len(hdr) == 128
    return hdr + u32le(14) + u32le(8) + junk(8)


def make_pickle(name):
    proto = {'PICKLE': 4, 'PICKLE2': 2, 'PICKLE3': 3, 'PICKLE5': 5,
             'PICKLE_P0': 0, 'PICKLE_P1': 1}[name]
    return pickle.dumps({'name': 'ghost', 'id': 7}, protocol=proto)


def make_ole_doc(name):
    confirm = {'XLS': 'Workbook', 'PPT': 'PowerPoint', 'MSG': '__nameid'}.get(name)
    return make_ole2(confirm)


def make_pem(name):
    begins = {
        'PEM_CERT': 'CERTIFICATE', 'PEM_RSA': 'RSA PRIVATE KEY',
        'PEM_EC': 'EC PRIVATE KEY', 'PEM_DSA': 'DSA PRIVATE KEY',
        'PEM_OPENSSH': 'OPENSSH PRIVATE KEY', 'PEM_PRIVATE': 'PRIVATE KEY',
        'PGP_PRIVATE': 'PGP PRIVATE KEY BLOCK', 'PGP_MESSAGE': 'PGP MESSAGE'}[name]
    b64 = base64.b64encode(junk(128)).decode()
    lines = '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return (f'-----BEGIN {begins}-----\n{lines}\n-----END {begins}-----\n').encode()


def make_ssh_pub(name):
    prefix = b'ssh-rsa AAAA' if name == 'SSH_RSA_PUB' else b'ssh-ed25519 AAAA'
    return prefix + base64.b64encode(junk(128)) + b' user@host'


def make_der(_):
    # 30 82 <len> + content of nested valid TLVs: exactly 32 bytes, so the
    # walk parses cleanly and clears the spec's default min_size.
    return (bytes([0x30, 0x82, 0x00, 0x1C])
            + bytes([0x30, 0x82, 0x00, 0x04, 0x04, 0x02, 0xAA, 0xBB])
            + bytes([0x04, 0x02, 0xAA, 0xBB])
            + b'\x02\x00' * 8)


def make_der_small(_):
    # 30 81 <len> + content of valid TLVs: exactly 32 bytes (the spec's
    # min_size), and the inner TLVs parse cleanly.
    return bytes([0x30, 0x81, 0x1D]) + bytes([0x04, 0x01, 0xAA]) + b'\x02\x00' * 13


def make_plist_bin(_):
    return plistlib.dumps({'name': 'ghost', 'id': 7})


# The engine's vPyc walker understands the Python 3.13 marshal layout only
# (code objects = 5 ints + 8 objects + 1 int + 2 objects). marshal.dumps()
# emits a different layout on older pythons (3.12 lacks the exceptiontable
# tail, so CI would build a fixture the walker rejects), so the body is
# hard-coded from the 3.13 layout instead of generated at runtime.
_PYC_313_BODY = bytes.fromhex(
    'e30000000000000000000000000100000000000000'   # TYPE_CODE|REF + 5 ints
    'f30800000095005300720067012902e9010000004e2901'  # code, consts(INT,NONE)
    'da0178a900f300000000da0c3c63617276652d737065633e'  # names, varnames,
    'da083c6d6f64756c653e7207000000'                # freevars, cellvars, filename, name
    '01000000'                                     # co_firstlineno
    '730a000000f003010101d804058101'               # lnotab
    '7205000000')                                  # exceptiontable (REF)


def make_pyc(name):
    magic = b'\x6F\x0D\x0D\x0A' if name == 'PYC' else b'\xF3\x0D\x0D\x0A'
    return magic + u32le(0) + u64le(0) + _PYC_313_BODY


def make_elf(_):
    e = bytearray(64)
    e[0:4] = b'\x7FELF'
    e[4] = 2            # 64-bit
    e[5] = 1            # LE
    e[6] = 1
    e[16:18] = u16le(2)     # ET_EXEC
    e[18:20] = u16le(62)    # x86-64
    e[20:24] = u32le(1)
    e[32:40] = u64le(64)    # phoff
    e[40:48] = u64le(120)   # shoff
    e[52:54] = u16le(64)    # e_ehsize
    e[54:56] = u16le(56)    # e_phentsize
    e[56:58] = u16le(1)     # e_phnum
    e[58:60] = u16le(64)    # e_shentsize
    e[60:62] = u16le(1)     # e_shnum
    ph = bytearray(56)
    ph[0:4] = u32le(1)      # PT_LOAD
    ph[8:16] = u64le(0)
    ph[16:24] = u64le(0x80)
    sh = bytearray(64)
    sh[4:8] = u32le(1)      # SHT_PROGBITS
    sh[24:32] = u64le(184)  # sh_offset
    sh[32:40] = u64le(8)    # sh_size
    return bytes(e) + bytes(ph) + bytes(sh) + junk(8)


def make_pe(_):
    e = bytearray(0x80)
    e[0:2] = b'MZ'
    e[0x3C:0x40] = u32le(0x80)
    pe = bytearray()
    pe += b'PE\x00\x00'
    pe += u16le(0x14C) + u16le(1) + u32le(0) + u32le(0) + u32le(0)
    pe += u16le(0xE0) + u16le(0)      # opt size @+20 = 224
    pe += junk(224)
    assert len(pe) == 4 + 20 + 224
    sec = bytearray(40)
    sec[0:8] = b'.text\x00\x00\x00'
    sec[16:20] = u32le(12)            # raw size
    sec[20:24] = u32le(0x80 + 4 + 20 + 224 + 40)  # raw ptr = section data start
    return bytes(e) + bytes(pe) + bytes(sec) + junk(12)


def make_macho(name):
    if name == 'MachO64':
        e = bytearray(32)
        e[0:4] = u32le(0xFEEDFACF)
        e[16:20] = u32le(1)
        e[20:24] = u32le(72)
        cmd = bytearray()
        cmd += u32le(0x19) + u32le(72) + junk(16) + u64le(0) + u64le(0)
        cmd += u64le(0) + u64le(0) + junk(16)
        assert len(cmd) == 72
        return bytes(e) + bytes(cmd)
    e = bytearray(28)
    e[0:4] = u32le(0xFEEDFACE)
    e[16:20] = u32le(1)
    e[20:24] = u32le(56)
    cmd = bytearray()
    cmd += u32le(0x01) + u32le(56) + junk(16) + u32le(0) + u32le(0)
    cmd += u32le(0) + u32le(0) + junk(16)
    assert len(cmd) == 56
    return bytes(e) + bytes(cmd)


def make_class(_):
    return (b'\xCA\xFE\xBA\xBE' + u16be(0) + u16be(52) + u16be(2)
            + bytes([1]) + u16be(8) + b'javatest'
            + u16be(1) + u16be(2) + u16be(0)
            + u16be(0) + u16be(0) + u16be(0) + u16be(0))


def make_dex(_):
    return b'dex\n036\x00' + u32le(0) + junk(20) + u32le(112) + junk(76)


def make_wasm(_):
    return b'\x00asm\x01\x00\x00\x00' + bytes([1, 4, 1, 0x60, 0, 0])


def make_pcap(magic, swapped=False):
    def rd32(x):
        return u32be(x) if swapped else u32le(x)
    gh = bytearray(24)
    gh[0:4] = magic
    gh[4:6] = u16le(2)
    gh[6:8] = u16le(4)
    gh[16:20] = rd32(64)
    gh[20:24] = rd32(1)
    pkt = rd32(0) + rd32(0) + rd32(16) + rd32(16) + junk(16)
    return bytes(gh) + pkt


def make_pcapng(_):
    return (b'\x0A\x0D\x0D\x0A' + u32le(28) + b'\x4D\x3C\x2B\x1A'
            + u16le(1) + u16le(0) + u64le(0xFFFFFFFFFFFFFFFF) + u32le(28))


def make_evtx(_):
    hdr = bytearray(4096)
    hdr[0:8] = b'ElfFile\x00'
    hdr[0x28:0x2A] = u16le(4096)
    hdr[0x2A:0x2C] = u16le(1)
    return bytes(hdr) + b'ElfChnk' + junk(65529)


def make_regf(_):
    hdr = bytearray(4096)
    hdr[0:4] = b'regf'
    hdr[0x28:0x2C] = u32le(4096)
    return bytes(hdr) + junk(4096)


def make_qcow(_):
    e = bytearray(520)
    e[0:4] = b'QFI\xFB'
    e[4:8] = u32be(3)
    e[24:32] = u64be(0x100000000)
    e[20:24] = u32be(12)
    e[36:40] = u32be(1)
    e[40:48] = u64be(512)
    e[68:72] = u32be(104)
    return bytes(e)


def make_vdi(name):
    e = bytearray(8192)
    magic = b'<<< Oracle VM VirtualBox Disk Image >>>' if name == 'VDI' \
        else b'<<< QEMU VM Virtual Disk Image >>>'
    e[0:len(magic)] = magic
    e[0x40:0x44] = u32le(0xBEDA107F)
    e[0x44:0x48] = u32le(0x00010001)
    e[0x48:0x4C] = u32le(512)
    e[0x4C:0x50] = u32le(2)
    e[0x158:0x15C] = u32le(4096)   # offset_data
    e[0x170:0x178] = u64le(0x10000)
    e[0x178:0x17C] = u32le(4096)   # block size
    e[0x180:0x184] = u32le(1)      # blocks in image
    e[0x184:0x188] = u32le(1)      # blocks allocated
    return bytes(e)


def make_vhd(_):
    hdr = b'conectix' + junk(504)
    footer = b'conectix' + junk(4) + bytes([0x00, 0x01]) + junk(498)
    return hdr + footer


def make_vhdx(_):
    e = bytearray(0x80000)
    e[0:8] = b'vhdxfile'
    h = bytearray(84)
    h[0:4] = b'head'
    h[70:72] = u16le(1)
    e[0x10000:0x10000 + 84] = bytes(h)
    rt = bytearray()
    rt += b'regi' + junk(4) + u32le(1) + junk(4)
    bat_guid = bytes([0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42,
                      0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08])
    rt += bat_guid + u64le(0x60000) + u32le(0x20000) + junk(8)
    e[0x30000:0x30000 + len(rt)] = bytes(rt)
    return bytes(e)


def make_stl(_):
    return (b'solid x\nfacet normal 0 0 1\nouter loop\n'
            b'vertex 0 0 0\nvertex 1 0 0\nvertex 0 1 0\n'
            b'endloop\nendfacet\nendsolid x\n')


def make_glb(_):
    return (b'glTF' + u32le(2) + u32le(40)
            + u32le(20) + b'JSON' + junk(20))


def make_sqlite3_wal(_):
    salt1, salt2 = 0xA1B2C3D4, 0x55667788
    out = b'\x37\x7f\x06\x82' + u32be(3007000) + u32be(4096)
    out += u32be(0) + u32be(2)
    out += u32be(salt1) + u32be(salt2) + b'\x00' * 4
    for pgno in (1, 2):
        out += u32be(pgno) + u32be(0) + u32be(salt1) + u32be(salt2)
        out += u32be(0) + u32be(0)
        out += junk(4096)
    out += u32be(salt1) + u32be(salt2) + u32be(0) + u32be(0) + b'\x00' * 8
    return out


def make_ttf(_):
    e = bytearray(2048)
    e[0:4] = bytes([0x00, 0x01, 0x00, 0x00])
    e[4:6] = u16be(3)
    e[6:8] = u16be(32)      # searchRange
    e[8:10] = u16be(1)      # entrySelector
    recs = [('head', 60, 1932), ('cmap', 1992, 4), ('glyf', 1996, 52)]
    for i, (tag, off, ln) in enumerate(recs):
        r = 12 + 16 * i
        e[r:r + 4] = tag.encode()
        e[r + 8:r + 12] = u32be(off)
        e[r + 12:r + 16] = u32be(ln)
    return bytes(e)


def make_otf(_):
    e = bytearray(172)
    e[0:4] = b'OTTO'
    e[4:6] = u16be(3)
    e[6:8] = u16be(32)
    e[8:10] = u16be(1)
    recs = [('head', 60, 54), ('cmap', 114, 4), ('CFF ', 118, 54)]
    for i, (tag, off, ln) in enumerate(recs):
        r = 12 + 16 * i
        e[r:r + 4] = tag.encode()
        e[r + 8:r + 12] = u32be(off)
        e[r + 12:r + 16] = u32be(ln)
    return bytes(e)


def make_ttc(_):
    e = bytearray(100)
    e[0:4] = b'ttcf'
    e[4:8] = u32be(0x00010000)
    e[8:12] = u32be(1)
    e[12:16] = u32be(16)
    e[16:20] = bytes([0x00, 0x01, 0x00, 0x00])
    e[20:22] = u16be(3)
    e[22:24] = u16be(32)
    e[24:26] = u16be(1)
    recs = [('head', 76, 8), ('cmap', 84, 8), ('glyf', 92, 8)]
    for i, (tag, off, ln) in enumerate(recs):
        r = 28 + 16 * i
        e[r:r + 4] = tag.encode()
        e[r + 8:r + 12] = u32be(off)
        e[r + 12:r + 16] = u32be(ln)
    return bytes(e)


def make_woff(name):
    n = 44 if name == 'WOFF' else 48
    return (b'wOFF' if name == 'WOFF' else b'wOF2') + u32be(0x00010000) + u32be(n) + junk(n - 12)


def make_text(name):
    spec = {
        'JSON': (b'{"key": 1}', 32), 'PS': (b'%!PS-Adobe-3.0', 64),
        'RTF': (b'{\\rtf1\\ansi', 64), 'HTML': (b'<!DOCTYPE html>', 64),
        'HTML_TAG': (b'<html>', 64), 'XML': (b'<?xml version="1.0"?>', 32),
        'LATEX': (b'\\documentclass{article}', 32),
        'SVG': (b'<svg', 64),
        'SVG_XML': (b'<?xml version="1.0" encoding="UTF-8"?>\r\n<svg xmlns="http://www.w3.org/2000/svg"', 64),
        'MBOX': (b'From sender@example.com Thu Jan  1 00:00:00 2026', 256),
        'EML': (b'Received: from mail.example.com by ghost.example.com', 128),
        'EML_MSGID': (b'Message-ID: <ghost-42@example.com>', 128),
        'SSH_RSA_PUB': (b'ssh-rsa AAAA', 64),
        'SSH_ED25519_PUB': (b'ssh-ed25519 AAAA', 64),
        'SHEBANG_SH': (b'#!/bin/sh', 16), 'SHEBANG_BASH': (b'#!/bin/bash', 16),
        'SHEBANG_ENV': (b'#!/usr/bin/env python3', 16),
        'PYTHON': (b'import os', 64), 'PYTHON_DEF': (b'def main():', 64),
        'C_INCLUDE': (b'#include <stdio.h>', 64), 'C_IFNDEF': (b'#ifndef GHOST_H', 64),
        'GO': (b'package main', 32), 'JAVA': (b'package com.ghost;', 64),
        'PHP': (b'<?php', 32), 'RUST': (b'fn main() {', 32),
        'SQL': (b'CREATE TABLE t (', 32), 'SQL_DUMP': (b'-- MySQL dump', 32),
        'DOCKERFILE': (b'FROM ubuntu:24.04', 32), 'YAML_DOC': (b'---\n', 32),
        'TOML': (b'[package]', 32), 'INI_UNIT': (b'[Unit]\n', 32),
        'GIT_CONFIG': (b'[core]\n', 16), 'CMAKE': (b'cmake_minimum_required(VERSION 3.16)', 32),
        'CSV_HEADER': (b'id,name,value', 64), 'VCARD': (b'BEGIN:VCARD', 32),
        'ICAL': (b'BEGIN:VCALENDAR', 32), 'GPX': (b'<gpx version="1.0">', 64),
        'KML': (b'<kml xmlns="http://www.opengis.net/kml/2.2">', 64),
        'PLIST_XML': (b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist', 64),
    }[name]
    return text_file(spec[0], spec[1])


def make_sshpub(name):
    prefix = b'ssh-rsa AAAA' if name == 'SSH_RSA_PUB' else b'ssh-ed25519 AAAA'
    return prefix + base64.b64encode(junk(128)) + b' user@host'


def make_pdf(_):
    return b'%PDF-1.4\n% ' + junk(120) + b'\ntrailer\nstartxref\n%%EOF\n'


def make_stub(magic, n=64):
    def b(_):
        return nonzero(magic + junk(n))
    return b


def make_bik(_):
    # 'BIK' + version char + u32 version/width/height/frames/fps/flags,
    # 12 reserved bytes (v1), then the frame size table (4 bytes per frame)
    # and the frame payloads it sizes.
    hdr = b'BIKb' + u32le(0) + u32le(640) + u32le(480) + u32le(1) + u32le(30) + u32le(0)
    hdr += b'\x00' * 12
    return nonzero(hdr + u32le(10) + junk(10))


def make_zws(_):
    # 'ZWS' + version + u32 LE compressed length + u32 LE uncompressed
    # length + LZMA props + payload; file length = 8 + compressed length.
    return b'ZWS' + bytes([0x13]) + u32le(12) + u32le(1024) + bytes([0x5D, 0x00, 0x00, 0x80, 0x00]) + junk(7)


def make_mpc(name):
    if name == 'MPC':       # SV8 "MPCK": magic + crc32 + u32 LE total size
        return b'MPCK' + u32le(0) + u32le(16) + b'\x00' * 4
    # SV7 "MP+": version 0x07 + u32 BE total size (incl. 16-byte header)
    return b'MP+' + bytes([0x07]) + struct.pack('>I', 17) + b'\x00' * 9


def make_lzma_alone(_):
    # props (lc=3,lp=0,pb=0) + u32 LE dict size + u64 LE uncompressed size
    # (0xFFFF... = unknown) + payload: a full 13-byte header plus 16 bytes.
    # dict 0x10000 keeps the 5D 00 00 magic (low 16 bits zero) and ≥ 4096.
    return bytes([0x5D]) + u32le(0x10000) + b'\xFF' * 8 + junk(16)


def make_wv(_):
    # single wvpk block: 'wvpk' + u32 LE ckSize (everything after the 8-byte
    # header) + 24 bytes of block metadata; total file = 8 + 24 = 32.
    return b'wvpk' + u32le(24) + b'\x00' * 24


def make_dxf(_):
    return nonzero(b'  0\r\nSECTION' + junk(64))


# ---------------- spec-valid fixtures for walker-verified formats --------------
# These mirror the corpus builders in test/scripts/regen_corpora.py: each file
# is minimal but spec-valid for the format's validator, so the carved output
# must equal the fixture byte-for-byte.  Walkers that need a structural
# zero-tail (EVT/JOB terminators) are fine: the engine sizes them exactly.
def make_aiff(_):
    return b'FORM' + u32be(200) + b'AIFF' + junk(196)


def make_aifc(_):
    return b'FORM' + u32be(200) + b'AIFC' + junk(196)


def make_ape(_):
    desc = b'MAC ' + u32le(3980) + u32le(52) + u32le(24)
    desc += b'\x00' * (52 - len(desc))
    hdr = b'\x00' * 8 + u16le(2) + b'\x00' * (24 - 10)
    tag = bytearray(12) + junk(2014)
    tag[10:12] = u16le(16)
    footer = b'APETAGEX' + u32le(3980) + u32le(1994) + u32le(0) + u32le(0) + junk(8)
    return desc + hdr + bytes(tag) + footer


def make_rm(_):
    out = b'.RMF' + u16be(0) + u16be(1) + u32be(1915)
    for chunk, size in ((b'PROP', 100), (b'MDPR', 100), (b'CONT', 100)):
        out += chunk + u32be(size) + junk(size)
    out += b'DATA' + u32be(1571) + junk(1571)
    return out


def make_s3m(_):
    out = bytearray(96)
    out[28:30] = b'\x1A\x00'
    out[32:34] = u16le(0)          # orders
    out[34:36] = u16le(0)          # instruments
    out[36:38] = u16le(1)          # patterns
    out[38:40] = u16le(3)          # flags -> 4 channels
    out[40:42] = u16le(0x1234)
    out[42:44] = u16le(0)
    out[44:48] = b'SCRM'
    out[48:50] = u16le(0)
    out[50:52] = u16le(0)
    out[52:54] = u16le(0)
    out[54:56] = u16le(0)
    out[56:96] = junk(40)
    out += b'\x00\x00'             # pattern parapointers
    out += junk(256)
    out += u16le(7840)
    out += junk(7840)
    return bytes(out)


def make_xm(_):
    out = bytearray(94)
    out[0:16] = b'Extended Module:'
    out[37] = 0x1A
    out[60:64] = u32le(34)
    out[64:66] = u16le(0)
    out[66:68] = u16le(0)
    out[68:70] = u16le(1)
    out[70:72] = u16le(0)
    out[72:74] = u16le(0x1234)
    out[74:76] = u16le(0)
    out[76] = 0x78
    out[77] = 0x78
    pat = u32le(8115) + u32le(64) + u16le(8105)
    pat += b'\x00\x00' + junk(8103)
    return bytes(out) + pat


def make_djvu(_):
    out = b'AT&TFORM' + u32be(918)
    out += b'INFO' + u32be(10) + b'\x00' * 10
    out += b'ANTa' + u32be(0)
    out += b'TXTz' + u32be(876) + junk(876)
    out += b'END\x00' + u32be(0)
    return out


def make_mobi(_):
    out = bytearray(512)
    out[60:68] = b'BOOKMOBI'
    out[76:78] = u16be(2)
    out[78:82] = u32be(512)
    out[82:86] = u32be(0)
    out[86:90] = u32be(1000)
    out[90:94] = u32be(0)
    out[94:96] = u16be(382)
    return bytes(out) + junk(488) + junk(382)


def make_chm(_):
    out = b'ITSF' + u32be(3) + u32be(0x60) + junk(0x60 - 12)
    pages = b''
    for i, nxt in enumerate((1, 2, 3, 0)):
        pg = b'PMGL' + b'\x00' * 4 + u32le(nxt) + junk(0x800 - 12)
        pages += pg
    return out + pages


def make_one(_):
    out = b'\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D' + junk(72 - 8)
    out += u32le(8128)
    out += junk(8200 - len(out))
    return out


def make_wpd(_):
    out = b'\xFFWPC' + junk(0x0C)
    out += u32le(8196)
    out += junk(8196 - len(out))
    return out


def make_dbx(_):
    out = b'\xCF\xAD\x12\xFE' + junk(0x0C)
    out += u32le(4096) + u32le(4)
    out += junk(4100 - len(out))
    return out


def make_evt(_):
    hdr = bytearray(0x30)
    hdr[0:4] = b'\x30\x00\x00\x00'
    hdr[4:8] = b'LfLe'
    hdr[0x10:0x14] = u32le(0x30)
    recs = b''
    for i in range(2):
        rec = u32le(0x40) + b'LfLe' + junk(0x40 - 8)
        recs += rec
    return bytes(hdr) + recs + b'\x00\x00\x00\x00'


def make_pst(_):
    hdr = bytearray(512)
    hdr[0:4] = b'!BDN'
    hdr[0x0A:0x0C] = u16le(23)
    hdr[0x14:0x18] = u32le(530)
    return bytes(hdr) + junk(271360 - 512)


def make_job(_):
    out = bytearray(0x3C)
    out[0:4] = b'\x01\x05\x01\x00'
    out[4:6] = u16le(1)
    out[6:8] = u16le(4)
    return bytes(out) + junk(1988) + b'\x00\x00\x00\x00'


def make_prefetch(_):
    out = bytearray(0x0C)
    out[0:4] = b'SCCA'
    out[4:8] = u32le(0x30)
    out += u32le(2052)
    out += junk(2052 - len(out))
    return bytes(out)


def make_vmdk(_):
    out = bytearray(512)
    out[0:4] = b'KDMV'
    out[4:8] = u32le(1)
    out[8:12] = u32le(3)
    out[20:28] = u64le(0)
    out[36:44] = u64le(127)
    out[44:48] = u32le(0)
    out[48:52] = u32le(0)
    return bytes(out) + junk(127 * 512)


def make_leveldb(_):
    out = b'\x57\xFB\x80\x8B\x24\x75\x47\xDB'
    out += u32le(0x12345678) + u16le(4096) + b'\x01'
    out += junk(4096)
    out += b'\x00' * (32776 - len(out))
    return out


def make_blend(_):
    out = bytearray(31)
    out[0:7] = b'BLENDER'
    out[18:22] = u32le(4)
    out[22] = 0x2C
    out += b'\x00' * (31 - len(out))
    for code, size in ((b'GLOB', 100), (b'DNA1', 1000), (b'SCEN', 500),
                       (b'OB\x00\x00', 134893)):
        out += code + u32le(size) + b'\x00' * 24 + junk(size)
    out += b'ENDB' + u32le(0) + b'\x00' * 24
    return bytes(out)


def make_dwg(_):
    out = bytearray(0x3C)
    out[0:6] = b'AC1015'
    out[6] = 0x1F
    out[0x30:0x34] = u32le(0x1000)
    out[0x38:0x3C] = u32le(2)
    ent1 = u16le(0x04) + b'\x00' * 14
    ent1 += u64le(0x50) + u64le(0x1000)
    ent2 = u16le(0x0B) + b'\x00' * 14
    ent2 += u64le(0x1050) + u64le(169541)
    out += ent1 + ent2
    out += junk(173717 - len(out))
    return bytes(out)


def make_fbx(_):
    out = bytearray(28)
    out[0:20] = b'Kaydara FBX Binary'
    out[20:23] = b'\x00\x1A\x00'
    out[23:28] = b'7.4.0'
    out += u32le(14715)
    out += junk(14715 - len(out))
    return bytes(out)


def make_lzip(_):
    payload = 8158
    out = b'LZIP' + b'\x01\x01' + b'\x00' * 14
    out += junk(payload)
    out += b'\x00' * 4                 # crc32
    out += u64be(payload)              # dsize
    out += u64be(payload + 40)         # msize == total length
    return out


def make_rpm(_):
    lead = bytearray(96)
    lead[0:4] = b'\xED\xAB\xEE\xDB'
    lead[4:8] = b'\x03\x00\x00\x00'
    sig = b'\x8E\xAD\xE8\x01' + b'\x00' * 4
    sig += u32be(1) + u32be(16)
    sig += u32be(1002) + u32be(4) + u32be(0) + u32be(0)
    sig += u32le(3968) + b'\x00' * 12
    main = b'\x8E\xAD\xE8\x01' + b'\x00' * 4
    main += u32be(0) + u32be(0)
    return bytes(lead) + sig + main + junk(3968)


def make_sit(_):
    out = bytearray(91)
    out[0:7] = b'StuffIt'
    out[82] = 0x05
    out += b'\x08' + b'archive\x00' + u32le(3999)
    out += junk(4103 - len(out))
    return bytes(out)


def make_squashfs(_):
    out = b'hsqs' + junk(24)
    out += u16be(4) + u16be(0)
    out += b'\x00' * 8
    out += u64le(4096)
    out += junk(4096 - len(out))
    return out


def make_dmg_koly(_):
    data = junk(267325)
    koly = b'koly' + u32be(4) + u32be(512) + u32be(1)
    koly += b'\x00' * 28
    koly += u64be(267325)
    koly += b'\x00' * (512 - len(koly))
    return data + koly


def make_kdb(_):
    out = b'\x03\xD9\xA2\x9A\x65\xFB\x4B\xB5'
    out += u32le(3)
    out += b'\x00' * (116 - len(out))
    out += u32le(500)
    out += junk(620 - len(out))
    return out


def make_kdbx(_):
    out = b'\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5' + u32le(0x00030001)
    out += b'\x02' + u32le(32) + junk(32)
    out += b'\x03' + u32le(4) + u32le(1)
    out += b'\x00\x07\x00\x00'           # END type + LE32 length 1792 at 58
    out += junk(1792)
    return out


def make_jks(_):
    out = b'\xFE\xED\xFE\xED' + u32be(2) + u32be(1)
    out += u16be(4) + b'key1' + b'\x00' * 8
    out += u32be(64) + junk(64)
    out += u32be(1)
    out += u32be(512) + junk(512)
    return out


def make_wallet(_):
    out = b'\x00\x05\x31\x62\x00\x09\x00\x00'
    out += b'\x00\x05\x31\x62'
    out += u32le(9)
    out += u32le(4096)
    out += b'\x01'
    out += b'\x00' * 5
    out += u32le(3)
    out += junk(16384 - len(out))
    return out


def make_mdb(accent):
    out = b'\x00\x01\x00\x00' + (b'Standard ACE' if accent else b'Standard Jet')
    out += b'\x00' * (0x14 - len(out))
    out += u32le(4096)
    out += b'\x00' * (0x3C - len(out))
    out += u32le(2)
    out += junk(8256 - len(out))
    return out


def make_wal(_):
    salt1, salt2 = 0xA1B2C3D4, 0x55667788
    out = b'\x37\x7f\x06\x82' + u32be(3007000) + u32be(4096)
    out += u32be(0) + u32be(2)
    out += u32be(salt1) + u32be(salt2) + b'\x00' * 4
    for pgno in (1, 2):
        out += u32be(pgno) + u32be(0) + u32be(salt1) + u32be(salt2)
        out += u32be(0) + u32be(0)
        out += junk(4096)
    out += u32be(salt1) + u32be(salt2) + u32be(0) + u32be(0) + b'\x00' * 8
    return out


def make_feather(_):
    out = b'ARROW1\x00\x00' + junk(198)
    p = len(out) + 4
    out += u32le(p - 12)
    out += b'ARROW1' + b'\x01\x02'
    return out


def make_parquet(_):
    return b'PAR1' + junk(100) + u32le(4) + b'PAR1'


def make_avro(_):
    sync = bytes(range(16))
    out = b'Obj\x01' + sync
    out += b'\x01\x64' + junk(100)
    out += sync
    return out


def make_hdf5(_):
    addr = 0x1000
    out = bytearray(64)
    out[0:8] = b'\x89HDF\r\n\x1a\n'
    out[13] = 8
    out[14] = 8
    out[40:48] = u64le(addr)
    node = u32be(0x534E4F44) + b'\x01\x00' + u16be(2)
    out += b'\x00' * (addr - len(out))
    out += node + junk(48)
    return bytes(out)


def make_bigtiff(_):
    out = b'II\x2B\x00' + u16le(8) + b'\x00\x00'
    out += u64le(16)
    out += u64le(4)
    for tag, val in ((256, 64), (257, 48), (273, 112), (279, 3072)):
        out += u16le(tag) + u16le(4) + u64le(1) + u64le(val)
    out += u64le(0)
    out += junk(3072)
    return out


def make_j2k(_):
    out = b'\xFF\x4F'
    out += b'\xFF\x51' + u16be(38) + b'\x00' * 36
    out += b'\xFF\x52' + u16be(12) + b'\x00' * 10
    out += b'\xFF\x90' + u16be(10) + u16be(1)
    out += u32be(514) + u16be(0) + u16be(0)
    out += junk(500)
    out += b'\xFF\xD9'
    return out


def make_jxl_iso(_):
    sig = b'\x00\x00\x00\x0CJXL ' + b'\x00' * 4
    jxlp = u32be(383) + b'jxlp' + junk(375)
    return sig + jxlp


def make_jp2(_):
    out = b'\x00\x00\x00\x0CjP  ' + b'\x00' * 4
    out += u32be(16) + b'cont' + junk(8)
    out += u32be(24) + b'jp2c' + junk(16)
    return out


def make_icns(_):
    return b'icns' + u32be(16) + b'ICON' + u32be(8)


def make_macho_fat(_):
    out = b'\xCA\xFE\xBA\xBF' + u32be(1)
    out += u32be(7) + u32be(3) + u32be(28) + u32be(20) + u32be(12)
    return out + junk(20)


def make_cramfs(_):
    return b'\x45\x3D\xCD\x28' + u32le(76) + junk(68)


def make_emf(_):
    hdr = bytearray(88)
    hdr[0:4] = u32le(1)
    hdr[4:8] = u32le(88)
    hdr[48:52] = u32le(2032)
    rec = u32le(1) + u32le(1924) + junk(1916)
    eof = u32le(14) + u32le(20) + junk(12)
    return bytes(hdr) + rec + eof


def make_exr(_):
    def attr(name, typ, val):
        return name + b'\x00' + typ + b'\x00' + u32le(len(val)) + val
    chlist = b''
    for ch in (b'R', b'G', b'B'):
        chlist += ch + b'\x00' + struct.pack('<iB3xii', 0, 0, 1, 1)
    chlist += b'\x00'
    hdr = b'\x76\x2f\x31\x01' + u32le(2) + attr(b'channels', b'chlist', chlist)
    hdr += attr(b'compression', b'compression', struct.pack('<B', 0))
    hdr += attr(b'dataWindow', b'box2i', struct.pack('<iiii', 0, 0, 63, 47))
    hdr += attr(b'displayWindow', b'box2i', struct.pack('<iiii', 0, 0, 63, 47))
    hdr += attr(b'lineOrder', b'lineOrder', struct.pack('<B', 0))
    hdr += attr(b'pixelAspectRatio', b'float', struct.pack('<f', 1.0))
    hdr += attr(b'screenWindowCenter', b'v2f', struct.pack('<ff', 0.0, 0.0))
    hdr += attr(b'screenWindowWidth', b'float', struct.pack('<f', 1.0))
    body = b''
    for y in range(48):
        scan = b''
        for x in range(64):
            v = ((x * 7 + y * 3) & 0x3FF) / 1024.0
            scan += struct.pack('<e', v) * 3
        body += struct.pack('<iI', y, len(scan)) + scan
    return hdr + body


def make_hdr(_):
    w, h = 64, 48
    header = b'#?RADIANCE\n# crafted corpus hdr\nFORMAT=32-bit_rle_rgbe\n\n'
    header += b'-Y %d +X %d\n' % (h, w)
    scan = b''
    for y in range(h):
        scan += b'\x02\x02' + u16be(1) + bytes([w])
        for c in range(4):
            run = bytes(((x * (c + 1) + y) & 0xFF) for x in range(w))
            scan += run
    return header + scan


def make_raf(_):
    jpeg = junk(15000)
    tiff = junk(23346)
    tiffOff = 0x6A + len(jpeg)
    out = b'FUJIFILMCCD-RAW ' + junk(0x5A - 16)
    out += u32be(0x6A) + u32be(len(jpeg))
    out += u32be(tiffOff) + u32be(len(tiff))
    out += jpeg + tiff
    return out


def make_x3f(_):
    out = b'FOVb' + junk(0x10)
    out += u32be(44) + u32be(1420)
    out += junk(1464 - len(out))
    return out


def make_xcf(_):
    out = b'gimp xcf ' + b'v0010' + b'\x00' * (22 - len(b'gimp xcf v0010'))
    out += u32be(2405)
    out += junk(2405 - len(out))
    return out


def make_y4m(_):
    out = b'YUV4MPEG2 W320 H240 C420jpeg\n'
    out += b'FRAME\n'
    out += junk(320 * 240 * 15 // 10)
    return out


# ---------------- phase-2 formats (arj/arc/pak/wad/... plus 52 new specs) -----
def make_arj(_):
    hdr = b'\x60\xEA' + u16le(30) + bytes([1, 0, 1, 0])          # magic, hdrSize, ver, flags, method, ftype
    hdr += u16le(0) + u16le(0) + u32le(0)                        # time, date, crc
    hdr += u32le(64) + u32le(64)                                 # comp, orig
    hdr += bytes([1, 0]) + u16le(0) + b'a.txt\x00'               # filever, host, reserved, name
    return hdr + junk(64) + b'\x60\xEA' + u16le(0)               # entry + end marker


def make_arc(_):
    hdr = b'\x1A\x08' + bytes([1, 0]) + u16le(0) + u16le(0)      # magic, method, ftype, time, date
    hdr += u32le(0) + u32le(64) + u32le(64)                      # crc, comp, orig
    return hdr + junk(64) + b'\x1A\x00'                          # entry + 1A 00 end marker


def make_pak(_):
    dir_off = 12 + 64
    entry = b'\x00' * 56 + u32le(12) + u32le(64)
    return b'PACK' + u32le(dir_off) + u32le(64) + junk(64) + entry


def make_wad(_):
    lumps, dir_off = 2, 28
    out = b'IWAD' + u32le(lumps) + u32le(dir_off) + junk(16)
    for i in range(lumps):
        out += u32le(12) + u32le(8) + b'lump%d' % i + b'\x00' * 3
    return out


def make_wad_pwad(_):
    out = bytearray(make_wad(None))
    out[0:4] = b'PWAD'
    return bytes(out)


def make_qed(_):
    return b'QED\x00' + u32le(4096) + u32le(4096) + u32le(64) + junk(8192 - 16)


def make_android_boot(_):
    out = bytearray(2048 + 3 * 4096)
    out[0:8] = b'ANDROID!'
    out[8:12] = u32le(16)          # kernel size
    out[16:20] = u32le(16)         # ramdisk size
    out[24:28] = u32le(16)         # second size
    out[36:40] = u32le(4096)       # page size
    out[2048:2064] = junk(16)
    out[6144:6160] = junk(16)
    out[10240:10256] = junk(16)
    return bytes(out)


def make_ewf(version):
    magic = b'EVF' if version == 'E01' else b'LVF'
    out = magic + b'\x09\x0D\x0A\xFF\x00' + u32le(2) + u32le(16)
    out += u32le(0x10000000) + u32le(64) + u64le(32) + junk(32)      # section 1
    out += u32le(0x20000001) + u32le(0) + u64le(16) + junk(16)       # section 2
    return out


def make_dmp(_):
    out = b'MDMP' + u32le(0x0000A793) + u32le(2) + u32le(136) + junk(20)
    out += junk(40) + junk(60)                                       # stream 0, 1
    out += u32le(0x1000) + u32le(40) + u32le(36)                     # dir entry 0
    out += u32le(0x1000) + u32le(60) + u32le(76)                     # dir entry 1
    return out


def make_pnm_text(name):
    if name == 'PNM_P1':
        return ('P1\n8 8\n' + '1 0 1 0 1 0 1 0\n' * 8).encode()
    if name == 'PNM_P2':
        return ('P2\n8 8\n255\n' + ' '.join(str((i * 7) % 256) for i in range(64)) + '\n').encode()
    rows = [' '.join(str(i % 256) for i in range(24)) for _ in range(8)]
    return ('P3\n8 8\n255\n' + '\n'.join(rows) + '\n').encode()


def make_pnm_binary(name):
    if name == 'PNM_P4':
        return b'P4\n8 8\n' + junk(8)
    if name == 'PNM_P5':
        return b'P5\n8 8\n255\n' + junk(8 * 8)
    return b'P6\n8 8\n255\n' + junk(8 * 8 * 3)


def make_sgi(_):
    out = bytearray(512)
    out[0:2] = b'\x01\xDA'
    out[2] = 0                    # storage: uncompressed
    out[3] = 1                    # bpc
    out[4:6] = u16be(2)           # dim
    out[6:8] = u16be(16)          # x
    out[8:10] = u16be(16)         # y
    out[10:12] = u16be(1)         # z
    out[18:22] = u32be(255)       # pixmax
    return bytes(out) + junk(16 * 16)


def make_xpm(_):
    return b'/* XPM */\nstatic char *x[] = {\n"1 1 1 1",\n"a c #000000",\n"a"\n};\n'


def make_crw(_):
    out = b'II\x1A\x00\x00\x00' + b'\x00\x00' + b'HEAPCCDR' + u32le(92) + u32le(2) + u32le(0)
    out += junk(64)
    for _ in range(2):
        out += u16le(0) + u16le(0) + u32le(0) + u32le(0)
    return out


def make_form(name):
    form = {'ILBM': b'ILBM', 'LWO2': b'LWO2'}[name]
    return b'FORM' + u32be(200) + form + junk(196)


def make_nsv(_):
    return b'NSVf' + u32le(16) + junk(16) + b'NSVs' + u32le(8) + junk(8) + b'NSVf' + u32le(0)


def make_wtv(_):
    return b'\xB7\xD8\x00\x20\x37\x49\xDA\x11\xA6\x4E\x00\x07\xE9\x5E\xAD\x8D' \
           + u64le(1024) + junk(1000)


def make_nes(_):
    return b'NES\x1A' + bytes([1, 1, 0, 0]) + junk(8) + junk(16384) + junk(8192)


def make_dbf(version):
    ver = {'DBF': 0x03, 'DBF_DBASE4': 0x04, 'DBF_DBASE3_MEMO': 0x83, 'DBF_DBASE4_MEMO': 0x8B}[version]
    out = bytes([ver]) + b'\x24\x08\x14' + u32le(1) + u16le(65) + u16le(8) + junk(20)
    out += b'NAME' + b'\x00' * 7 + b'C' + u32le(0) + bytes([8, 0]) + junk(14)
    return out + b'\x0D' + junk(8)


# name -> (builder, category).  Builders take the spec name.
BUILDERS = {}


def reg(name, builder, cat):
    BUILDERS[name] = (builder, cat)


# ---------------- images ----------------
reg('JPEG', make_jpeg, 'image')
reg('JPEG_EOI_TAIL', make_jpeg_eoi_tail, 'image')
reg('PNG', make_png, 'image')
reg('GIF89a', lambda n: make_gif(b'GIF89a'), 'image')
reg('GIF87a', lambda n: make_gif(b'GIF87a'), 'image')
reg('BMP', make_bmp, 'image')
reg('CR2', make_cr2, 'image')
reg('DNG', lambda n: make_tiff_le(b'DNG'), 'image')
reg('ARW', lambda n: make_tiff_le(b'SONY'), 'image')
reg('NEF', lambda n: make_tiff_be(b'NIKON'), 'image')
reg('ORF', make_orw, 'image')
reg('RW2', make_orw, 'image')
reg('PEF', lambda n: make_tiff_be(b'PENTAX'), 'image')
reg('RAF', make_raf, 'image')
reg('X3F', make_x3f, 'image')
reg('TIFF_LE', lambda n: make_tiff_le(None), 'image')
reg('TIFF_BE', lambda n: make_tiff_be(None), 'image')
reg('BigTIFF', make_bigtiff, 'image')
reg('WEBP', make_webp, 'image')
reg('HEIC', make_ftyp, 'image')
reg('HEIF', make_ftyp, 'image')
reg('AVIF', make_ftyp, 'image')
reg('ICO', lambda n: make_ico(False), 'image')
reg('CUR', lambda n: make_ico(True), 'image')
reg('PSD', make_psd, 'image')
reg('XCF', make_xcf, 'image')
reg('JP2', make_jp2, 'image')
reg('J2K', make_j2k, 'image')
reg('JXL', lambda _n: bytes([0xFF, 0x0A]) + struct.pack('>I', 66) + b'\x00' * 66, 'image')  # codestream: 4-byte BE size + zero-prefixed payload
reg('JXL_ISO', make_jxl_iso, 'image')
reg('QOI', make_qoi, 'image')
reg('DDS', make_stub(b'DDS '), 'image')
reg('EXR', make_exr, 'image')
reg('HDR', make_hdr, 'image')
reg('PCX', make_pcx, 'image')
reg('ICNS', make_icns, 'image')
reg('EMF', make_emf, 'image')
reg('WMF', make_stub(bytes([0xD7, 0xCD, 0xC6, 0x9A])), 'image')
reg('SVG', make_text, 'image')
reg('SVG_XML', make_text, 'image')
reg('CDR', make_cdr, 'image')

# ---------------- video ----------------
reg('MP4', make_ftyp, 'video')
reg('MOV', make_ftyp, 'video')
reg('M4V', make_ftyp, 'video')
reg('M4A', make_ftyp, 'audio')
reg('3GP', make_ftyp, 'video')
reg('MOV_MDAT', make_mov_mdat, 'video')
reg('MKV', lambda n: make_ebml(b'matroska'), 'video')
reg('WEBM', lambda n: make_ebml(b'webm'), 'video')
reg('EBML', lambda n: make_ebml(b'ghost__'), 'video')
reg('AVI', lambda n: b'RIFF' + u32le(1024) + b'AVI ' + b'LIST' + u32le(1012) + b'hdrl' + junk(1008), 'video')
reg('WAV', lambda n: b'RIFF' + u32le(44) + b'WAVE' + b'fmt ' + u32le(16) + junk(16) + b'data' + u32le(8) + junk(8), 'audio')
reg('FLV', make_flv, 'video')
reg('WMV', make_asf, 'video')
reg('WMA', make_asf, 'audio')
reg('ASF', make_asf, 'video')
reg('MPEG_TS', lambda n: make_ts(bytes([0x40, 0x00])), 'video')
reg('MPEG_TS1', lambda n: make_ts(bytes([0x41, 0x01])), 'video')
reg('MPEG_PS', make_mpeg_ps, 'video')
reg('MPEG_VES', make_mpeg_ves, 'video')
reg('RM', make_rm, 'video')
reg('MXF', make_mxf, 'video')
reg('IVF', make_ivf, 'video')
reg('Y4M', make_y4m, 'video')
reg('BIK', make_bik, 'video')
reg('SWF', make_swf, 'video')
reg('SWF_ZLIB', make_swf, 'video')
reg('SWF_LZMA', make_zws, 'video')

# ---------------- audio ----------------
reg('MP3_ID3', make_mp3_id3, 'audio')
reg('MP3_FRAME', lambda n: make_mp3_frames(b'\xFF\xFB', 417, 5), 'audio')
reg('MP3_FRAME_V2', lambda n: make_mp3_frames(b'\xFF\xF3', 261, 3), 'audio')
reg('MP3_FRAME_V25', lambda n: make_mp3_frames(b'\xFF\xE3', 522, 3), 'audio')
reg('FLAC', make_flac, 'audio')
reg('OPUS', lambda n: make_ogg(b'OpusHead'), 'audio')
reg('OGA', lambda n: make_ogg(b'vorbis'), 'audio')
reg('SPX', lambda n: make_ogg(b'Speex'), 'audio')
reg('OGV', lambda n: make_ogg(b'theora'), 'video')
reg('OGG', lambda n: make_ogg(b'junk'), 'audio')
reg('AAC', lambda n: make_aac(b'\xF1'), 'audio')
reg('AAC_MPEG2', lambda n: make_aac(b'\xF9'), 'audio')
reg('AC3', make_ac3, 'audio')
reg('AMR', lambda n: make_amr(False), 'audio')
reg('AMR_WB', lambda n: make_amr(True), 'audio')
reg('MIDI', make_midi, 'audio')
reg('DTS', make_dts, 'audio')
reg('APE', make_ape, 'audio')
reg('AIFF', make_aiff, 'audio')
reg('AIFC', make_aifc, 'audio')
reg('WV', make_wv, 'audio')
reg('MPC', make_mpc, 'audio')
reg('MPC_SV7', make_mpc, 'audio')
reg('AU', make_au, 'audio')
reg('CAF', make_caf, 'audio')
reg('VOC', make_voc, 'audio')
reg('MOD_IT', make_stub(b'IMPM'), 'audio')
reg('MOD_S3M', make_s3m, 'audio')
reg('MOD_XM', make_xm, 'audio')

# ---------------- documents ----------------
reg('PDF', make_pdf, 'document')
reg('PS', make_text, 'document')
reg('DOCX', make_zip_oo, 'document')
reg('XLSX', make_zip_oo, 'document')
reg('PPTX', make_zip_oo, 'document')
reg('ODT', make_zip_oo, 'document')
reg('ODS', make_zip_oo, 'document')
reg('ODP', make_zip_oo, 'document')
reg('EPUB', make_zip_oo, 'document')
reg('XLS', make_ole_doc, 'document')
reg('PPT', make_ole_doc, 'document')
reg('DOC', lambda n: make_ole2(None), 'document')
reg('RTF', make_text, 'document')
reg('MOBI', make_mobi, 'document')
reg('DJVU', make_djvu, 'document')
reg('CHM', make_chm, 'document')
reg('ONE', make_one, 'document')
reg('WPD', make_wpd, 'document')
reg('HTML', make_text, 'document')
reg('HTML_TAG', make_text, 'document')
reg('XML', make_text, 'document')
reg('LATEX', make_text, 'document')

# ---------------- archives ----------------
reg('ZIP', make_zip_oo, 'archive')
reg('JAR', make_zip_oo, 'archive')
reg('APK', make_zip_oo, 'archive')
reg('GZIP', make_gzip, 'archive')
reg('BZIP2', make_bzip2, 'archive')
reg('XZ', make_xz, 'archive')
reg('7Z', make_7z, 'archive')
reg('RAR4', make_rar4, 'archive')
reg('RAR5', make_rar5, 'archive')
reg('TAR', make_tar, 'archive')
reg('DEB', make_deb, 'archive')
reg('AR', make_ar, 'archive')
reg('CAB', make_cab, 'archive')
reg('ZSTD', make_stub(bytes([0x28, 0xB5, 0x2F, 0xFD])), 'archive')
reg('LZ4', make_stub(bytes([0x04, 0x22, 0x4D, 0x18])), 'archive')
reg('LZIP', make_lzip, 'archive')
reg('LZMA_ALONE', make_lzma_alone, 'archive')
reg('RPM', make_rpm, 'archive')
reg('CPIO_ASCII', make_cpio, 'archive')
reg('CPIO_ODC', make_cpio_odc, 'archive')
reg('CPIO_BIN', make_cpio_bin, 'archive')
reg('LZH', make_stub(b'-lh'), 'archive')
reg('ACE', make_stub(b'**ACE**'), 'archive')
reg('SIT', make_sit, 'archive')
reg('WIM', make_stub(b'MSWIM'), 'archive')
reg('DMG_KOLY', make_dmg_koly, 'archive')
reg('ISO9660', make_iso, 'archive')
reg('SQUASHFS', make_squashfs, 'archive')
reg('CRAMFS', make_cramfs, 'archive')

# ---------------- databases ----------------
reg('SQLite', make_sqlite, 'database')
reg('SQLite_WAL', make_sqlite3_wal, 'database')
reg('MDB', lambda n: make_mdb(False), 'database')
reg('ACCDB', lambda n: make_mdb(True), 'database')
reg('BerkeleyDB', make_stub(bytes([0x00, 0x05, 0x31, 0x62])), 'database')
reg('LevelDB', make_leveldb, 'database')
reg('Firebird', make_stub(bytes([0x01, 0x00, 0x39, 0x30])), 'database')
reg('MSSQL_MDF', make_stub(bytes([0x01, 0x0F, 0x00, 0x00])), 'database')
reg('Parquet', make_parquet, 'database')
reg('ORC', make_stub(b'ORC'), 'database')
reg('Avro', make_avro, 'database')
reg('HDF5', make_hdf5, 'database')
reg('NetCDF', make_stub(b'CDF'), 'database')
reg('Feather', make_feather, 'database')
reg('NPY', make_npy, 'database')
reg('MAT', make_mat, 'database')
reg('PICKLE', make_pickle, 'database')
reg('PICKLE2', make_pickle, 'database')
reg('PICKLE3', make_pickle, 'database')
reg('PICKLE5', make_pickle, 'database')
reg('PICKLE_P0', make_pickle, 'database')
reg('PICKLE_P1', make_pickle, 'database')

# ---------------- email ----------------
reg('PST', make_pst, 'email')
reg('MBOX', make_text, 'email')
reg('EML', make_text, 'email')
reg('EML_MSGID', make_text, 'email')
reg('DBX', make_dbx, 'email')
reg('MSG', make_ole_doc, 'email')

# ---------------- crypto ----------------
for n in ('PEM_CERT', 'PEM_RSA', 'PEM_EC', 'PEM_DSA', 'PEM_OPENSSH',
          'PEM_PRIVATE', 'PGP_PRIVATE', 'PGP_MESSAGE'):
    reg(n, make_pem, 'crypto')
reg('SSH_RSA_PUB', make_sshpub, 'crypto')
reg('SSH_ED25519_PUB', make_sshpub, 'crypto')
reg('PKCS12', make_der, 'crypto')
reg('JKS', make_jks, 'crypto')
reg('KDBX', make_kdbx, 'crypto')
reg('KDB', make_kdb, 'crypto')
reg('GPG_KEYRING', lambda _n: bytes([0x99, 0x01, 0x1D, 0x01]) + b'\x00' * 284, 'crypto')  # self-consistent 288-byte key: len 0x011D=288-3, v1 body
reg('BITCOIN_WALLET', make_wallet, 'crypto')

# ---------------- executables ----------------
reg('ELF', make_elf, 'executable')
reg('PE', make_pe, 'executable')
reg('MachO64', make_macho, 'executable')
reg('MachO32', make_macho, 'executable')
reg('MachO_FAT', make_macho_fat, 'executable')
reg('JavaClass', make_class, 'executable')
reg('DEX', make_dex, 'executable')
reg('WASM', make_wasm, 'executable')
reg('PYC', make_pyc, 'executable')
reg('PYC_F3', make_pyc, 'executable')

# ---------------- forensic ----------------
reg('PCAP_LE', lambda n: make_pcap(b'\xD4\xC3\xB2\xA1'), 'forensic')
reg('PCAP_BE', lambda n: make_pcap(b'\xA1\xB2\xC3\xD4', swapped=True), 'forensic')
reg('PCAP_NS', lambda n: make_pcap(b'\xA1\xB2\x3C\x4D', swapped=True), 'forensic')
reg('PCAP_NS_LE', lambda n: make_pcap(b'\x4D\x3C\xB2\xA1'), 'forensic')
reg('PCAPNG', make_pcapng, 'forensic')
reg('EVTX', make_evtx, 'forensic')
reg('EVT', make_evt, 'forensic')
reg('REGF', make_regf, 'forensic')
reg('LNK', make_stub(bytes([0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])), 'forensic')
reg('PREFETCH', make_prefetch, 'forensic')
reg('PREFETCH_C', make_stub(bytes([0x4D, 0x41, 0x4D, 0x04])), 'forensic')
reg('JOB', make_job, 'forensic')

# ---------------- vm ----------------
reg('QCOW2', make_qcow, 'vm')
reg('VMDK_SPARSE', make_vmdk, 'vm')
reg('VMDK_DESC', make_stub(b'# Disk DescriptorFile'), 'vm')
reg('VDI', make_vdi, 'vm')
reg('VDI_QEMU', make_vdi, 'vm')
reg('VHD', make_vhd, 'vm')
reg('VHDX', make_vhdx, 'vm')
reg('OVA', make_tar, 'vm')

# ---------------- fonts ----------------
reg('TTF', make_ttf, 'font')
reg('OTF', make_otf, 'font')
reg('TTC', make_ttc, 'font')
reg('WOFF', make_woff, 'font')
reg('WOFF2', make_woff, 'font')

# ---------------- misc ----------------
reg('DWG', make_dwg, 'misc')
reg('DXF', make_dxf, 'misc')
reg('STL_ASCII', make_stl, 'misc')
reg('BLEND', make_blend, 'misc')
reg('FBX', make_fbx, 'misc')
reg('GLTF_BIN', make_glb, 'misc')
reg('TORRENT', make_stub(b'd8:announce', 80), 'misc')
reg('PLIST_XML', make_text, 'misc')
reg('PLIST_BIN', make_plist_bin, 'misc')
reg('DER', make_der, 'misc')
reg('DER_SMALL', make_der_small, 'misc')
reg('OPENVPN', make_stub(b'client\ndev tun'), 'misc')

# ---------------- phase-2 formats (52 new specs) ----------------
for n in ('ARJ', 'ARC', 'ZOO', 'SQX', 'KGB', 'ZPAQ', 'RZIP', 'UHARC', 'ALZ',
          'XAR', 'PAK', 'WAD', 'WAD_PWAD'):
    if n == 'ARJ':
        b = make_arj
    elif n == 'ARC':
        b = make_arc
    elif n == 'PAK':
        b = make_pak
    elif n == 'WAD':
        b = make_wad
    elif n == 'WAD_PWAD':
        b = make_wad_pwad
    else:
        b = make_stub({'ZOO': b'ZOO ', 'SQX': b'SQX ', 'KGB': b'KGB', 'ZPAQ': b'7kBa',
                       'RZIP': b'RZIP', 'UHARC': b'UHARC', 'ALZ': b'ALZ\x01\x01',
                       'XAR': b'xar!'}[n])
    reg(n, b, 'archive')
reg('QED', make_qed, 'vm')
reg('ANDROID_BOOT', make_android_boot, 'vm')
reg('E01', lambda n: make_ewf('E01'), 'forensic')
reg('L01', lambda n: make_ewf('L01'), 'forensic')
reg('AFF', make_stub(b'AFF1'), 'forensic')
reg('DMP', make_dmp, 'forensic')
reg('FLIF', make_stub(b'FLIF'), 'image')
reg('BPG', make_stub(bytes([0x42, 0x50, 0x47, 0xFB])), 'image')
reg('PNM_P1', make_pnm_text, 'image')
reg('PNM_P2', make_pnm_text, 'image')
reg('PNM_P3', make_pnm_text, 'image')
reg('PNM_P4', make_pnm_binary, 'image')
reg('PNM_P5', make_pnm_binary, 'image')
reg('PNM_P6', make_pnm_binary, 'image')
reg('SGI', make_sgi, 'image')
reg('XPM', make_xpm, 'image')
reg('PICT', make_stub(bytes([0x00, 0x11, 0x02, 0xFF, 0x0C, 0x00, 0x00, 0x00])), 'image')
reg('MRW', make_stub(bytes([0x00, 0x4D, 0x52, 0x4D])), 'image')
reg('CRW', make_crw, 'image')
reg('ILBM', make_form, 'image')
reg('LWO2', make_form, 'image')
reg('TTA', make_stub(b'TTA1'), 'audio')
reg('OFR', make_stub(b'OFR '), 'audio')
reg('VQF', make_stub(b'TWIN'), 'audio')
reg('RA', make_stub(bytes([0x2E, 0x72, 0x61, 0xFD])), 'audio')
reg('NSV', make_nsv, 'video')
reg('WTV', make_wtv, 'video')
reg('QXP', make_stub(b'MXXN'), 'document')
reg('DVI', make_stub(bytes([0xF7, 0x02])), 'document')
reg('FDF', lambda n: text_file(b'%FDF-1.2\n', 128), 'document')
reg('REG', lambda n: text_file(b'Windows Registry Editor Version 5.00\n', 128), 'code')
reg('PLY', lambda n: text_file(b'ply\n', 128), 'misc')
reg('NES', make_nes, 'misc')
reg('DBF', lambda n: make_dbf('DBF'), 'database')
reg('DBF_DBASE4', lambda n: make_dbf('DBF_DBASE4'), 'database')
reg('DBF_DBASE3_MEMO', lambda n: make_dbf('DBF_DBASE3_MEMO'), 'database')
reg('DBF_DBASE4_MEMO', lambda n: make_dbf('DBF_DBASE4_MEMO'), 'database')
reg('ESEDB', make_stub(b'EFile'), 'database')
reg('PCF', make_stub(bytes([0x01, 0x66, 0x63, 0x70])), 'font')

# ---------------- code ----------------
for n in ('JSON', 'SHEBANG_SH', 'SHEBANG_BASH', 'SHEBANG_ENV', 'PYTHON',
          'PYTHON_DEF', 'C_INCLUDE', 'C_IFNDEF', 'GO', 'JAVA', 'PHP', 'RUST',
          'SQL', 'SQL_DUMP', 'DOCKERFILE', 'YAML_DOC', 'TOML', 'INI_UNIT',
          'GIT_CONFIG', 'CMAKE', 'CSV_HEADER', 'VCARD', 'ICAL', 'GPX', 'KML'):
    reg(n, make_text, 'code')


def run_carve(bin_path, img, out, cat):
    r = subprocess.run([bin_path, 'carve', img, '--out', out, '--categories', cat],
                       capture_output=True, text=True)
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def check_one(bin_path, work, name):
    global PASS, FAIL
    builder, cat = BUILDERS[name]
    fixture = builder(name)
    if isinstance(fixture, str):
        fixture = fixture.encode()
    if not fixture.endswith(b'\x00'):
        fixture = nonzero(fixture)
    img = os.path.join(work, 'img', name + '.img')
    out = os.path.join(work, 'out', name)
    os.makedirs(os.path.dirname(img), exist_ok=True)
    with open(img, 'wb') as f:
        f.write(fixture)
        f.write(b'\x00' * 4096)
    if os.path.exists(out):
        shutil.rmtree(out)
    rc, log = run_carve(bin_path, img, out, cat)
    want_md5 = hashlib.md5(fixture).hexdigest()
    want_size = len(fixture)
    got = os.path.join(out, cat, 'placeholder', 'never')
    got_path = None
    if os.path.isdir(out):
        for root, _dirs, files in os.walk(out):
            for f in files:
                if f.startswith(name + '_') and f.endswith('.md5check'):
                    pass
                if f == (name.replace(' ', '_') + '_00001.' + 'x'):
                    pass
                p = os.path.join(root, f)
                if got_path is None or os.path.getsize(p) > os.path.getsize(got_path):
                    got_path = p
    if got_path is None:
        FAIL += 1
        failures.append((name, 'no output carved'))
        print(f'FAIL {name:16s} no output carved (cat={cat})')
        if 'Recovered' in log:
            print('     ' + log.splitlines()[-2])
        return
    got_data = open(got_path, 'rb').read()
    got_md5 = hashlib.md5(got_data).hexdigest()
    if got_md5 == want_md5 and len(got_data) == want_size:
        PASS += 1
        print(f'pass {name:16s} {want_size:>7d} B  {os.path.basename(got_path)}')
    else:
        FAIL += 1
        failures.append((name, f'md5/size mismatch: want {want_md5}/{want_size} '
                               f'got {got_md5}/{len(got_data)} in {got_path}'))
        print(f'FAIL {name:16s} want {want_md5} {want_size}B got {got_md5} {len(got_data)}B '
              f'({os.path.basename(got_path)})')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', default='build/ghost_recover')
    ap.add_argument('--work', default='/tmp/opencode/carve-spec')
    ap.add_argument('--names', default=None, help='comma list; default = all')
    args = ap.parse_args()
    if not os.path.isfile(args.bin):
        print(f'error: binary not found: {args.bin}')
        sys.exit(2)
    names = sorted(BUILDERS)
    if args.names:
        names = [n.strip() for n in args.names.split(',') if n.strip()]
    by_cat = {}
    for n in names:
        cat = BUILDERS[n][1]
        by_cat.setdefault(cat, []).append(n)
    print(f'# verifying {len(names)} signatures (fixtures in {args.work})')
    for cat, ns in by_cat.items():
        print(f'## category {cat} ({len(ns)} formats)')
        for n in ns:
            if n in SKIP:
                print(f'skip {n:16s} (see SKIP comment)')
                continue
            check_one(args.bin, args.work, n)
    print(f'\nTOTAL: {PASS} passed, {FAIL} failed of {len(names)}')
    for name, why in failures:
        print(f'  FAIL {name}: {why}')
    sys.exit(1 if FAIL else 0)


if __name__ == '__main__':
    main()

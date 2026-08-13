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
import struct
import subprocess
import sys
import tarfile
import zipfile

PASS = FAIL = 0
SKIP = []
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
            + junk(1) + b'\x00')


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
        return b'FWS' + bytes([1]) + u32le(48) + junk(40)
    # SWF_ZLIB
    body = junk(56)
    return b'CWS' + bytes([1]) + u32le(len(body) + 8) + bytes(gzip.zlib.compress(body, 9))


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
        h[20:22] = u16le(ns)
        h[22:26] = u16le(fs & 0xFFFF) + u16le(fs >> 16)
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
    return bytes([0x30, 0x82, 0x00, 0x08, 0x30, 0x82, 0x00, 0x04, 0x04, 0x02, 0xAA, 0xBB])


def make_der_small(_):
    return bytes([0x30, 0x81, 0x04, 0x04, 0x02, 0xAA, 0xBB])


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
    rt += bat_guid + u64be(0x60000) + u32be(0x20000) + junk(8)
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
    return b'\x37\x7F\x06\x82' + junk(64)


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


def make_dxf(_):
    return nonzero(b'  0\r\nSECTION' + junk(64))


# name -> (builder, category).  Builders take the spec name.
BUILDERS = {}


def reg(name, builder, cat):
    BUILDERS[name] = (builder, cat)


# ---------------- images ----------------
reg('JPEG', make_jpeg, 'image')
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
reg('RAF', make_stub(b'FUJIFILMCCD-RAW '), 'image')
reg('X3F', make_stub(b'FOVb'), 'image')
reg('TIFF_LE', lambda n: make_tiff_le(None), 'image')
reg('TIFF_BE', lambda n: make_tiff_be(None), 'image')
reg('BigTIFF', make_stub(b'II\x2B\x00'), 'image')
reg('WEBP', make_webp, 'image')
reg('HEIC', make_ftyp, 'image')
reg('HEIF', make_ftyp, 'image')
reg('AVIF', make_ftyp, 'image')
reg('ICO', lambda n: make_ico(False), 'image')
reg('CUR', lambda n: make_ico(True), 'image')
reg('PSD', make_psd, 'image')
reg('XCF', make_stub(b'gimp xcf '), 'image')
reg('JP2', make_stub(bytes([0x00, 0x00, 0x00, 0x0C]) + b'jP\x20\x20'), 'image')
reg('J2K', make_stub(bytes([0xFF, 0x4F, 0xFF, 0x51])), 'image')
reg('JXL', lambda _n: bytes([0xFF, 0x0A]) + struct.pack('>I', 66) + b'\x00' * 66, 'image')  # codestream: 4-byte BE size + zero-prefixed payload
reg('JXL_ISO', make_stub(bytes([0x00, 0x00, 0x00, 0x0C]) + b'JXL\x20'), 'image')
reg('QOI', make_qoi, 'image')
reg('DDS', make_stub(b'DDS '), 'image')
reg('EXR', make_stub(bytes([0x76, 0x2F, 0x31, 0x01])), 'image')
reg('HDR', make_stub(b'#?RADIANCE'), 'image')
reg('PCX', make_pcx, 'image')
reg('ICNS', make_stub(b'icns'), 'image')
reg('EMF', make_stub(bytes([0x01, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00])), 'image')
reg('WMF', make_stub(bytes([0xD7, 0xCD, 0xC6, 0x9A])), 'image')
reg('SVG', make_text, 'image')
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
reg('AVI', lambda n: b'RIFF' + u32le(1024) + b'AVI ' + b'LIST' + u32le(1016) + b'hdrl' + junk(1008), 'video')
reg('WAV', lambda n: b'RIFF' + u32le(44) + b'WAVE' + b'fmt ' + u32le(16) + junk(16) + b'data' + u32le(8) + junk(8), 'audio')
reg('FLV', make_flv, 'video')
reg('WMV', make_asf, 'video')
reg('WMA', make_asf, 'audio')
reg('ASF', make_asf, 'video')
reg('MPEG_TS', lambda n: make_ts(bytes([0x40, 0x00])), 'video')
reg('MPEG_TS1', lambda n: make_ts(bytes([0x41, 0x01])), 'video')
reg('MPEG_PS', make_mpeg_ps, 'video')
reg('MPEG_VES', make_mpeg_ves, 'video')
reg('RM', make_stub(b'.RMF'), 'video')
reg('MXF', make_mxf, 'video')
reg('IVF', make_ivf, 'video')
reg('Y4M', make_stub(b'YUV4MPEG2'), 'video')
reg('BIK', make_stub(b'BIK'), 'video')
reg('SWF', make_swf, 'video')
reg('SWF_ZLIB', make_swf, 'video')
reg('SWF_LZMA', make_stub(b'ZWS'), 'video')

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
reg('APE', make_stub(b'MAC '), 'audio')
reg('WV', make_stub(b'wvpk'), 'audio')
reg('MPC', make_stub(b'MPCK'), 'audio')
reg('MPC_SV7', make_stub(b'MP+'), 'audio')
reg('AU', make_au, 'audio')
reg('CAF', make_caf, 'audio')
reg('VOC', make_voc, 'audio')
reg('MOD_IT', make_stub(b'IMPM'), 'audio')
reg('MOD_S3M', lambda n: nonzero(b'\x00' * 44 + b'SCRM' + junk(20)), 'audio')
reg('MOD_XM', make_stub(b'Extended Module:'), 'audio')

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
reg('MOBI', make_stub(b'BOOKMOBI'), 'document')
reg('DJVU', make_stub(b'AT&TFORM'), 'document')
reg('CHM', make_stub(b'ITSF'), 'document')
reg('ONE', make_stub(bytes([0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D])), 'document')
reg('WPD', make_stub(b'\xFFWPC'), 'document')
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
reg('LZIP', make_stub(b'LZIP'), 'archive')
reg('LZMA_ALONE', make_stub(bytes([0x5D, 0x00, 0x00])), 'archive')
reg('RPM', make_stub(bytes([0xED, 0xAB, 0xEE, 0xDB])), 'archive')
reg('CPIO_ASCII', make_cpio, 'archive')
reg('CPIO_ODC', make_cpio_odc, 'archive')
reg('CPIO_BIN', make_cpio_bin, 'archive')
reg('LZH', make_stub(b'-lh'), 'archive')
reg('ACE', make_stub(b'**ACE**'), 'archive')
reg('SIT', make_stub(b'StuffIt'), 'archive')
reg('WIM', make_stub(b'MSWIM'), 'archive')
reg('DMG_KOLY', make_stub(b'koly'), 'archive')
reg('ISO9660', make_iso, 'archive')
reg('SQUASHFS', make_stub(b'hsqs'), 'archive')
reg('CRAMFS', make_stub(bytes([0x45, 0x3D, 0xCD, 0x28])), 'archive')

# ---------------- databases ----------------
reg('SQLite', make_sqlite, 'database')
reg('SQLite_WAL', make_sqlite3_wal, 'database')
reg('MDB', make_stub(b'\x00\x01\x00\x00Standard Jet'), 'database')
reg('ACCDB', make_stub(b'\x00\x01\x00\x00Standard ACE'), 'database')
reg('BerkeleyDB', make_stub(bytes([0x00, 0x05, 0x31, 0x62])), 'database')
reg('LevelDB', make_stub(bytes([0x57, 0xFB, 0x80, 0x8B, 0x24, 0x75, 0x47, 0xDB])), 'database')
reg('Firebird', make_stub(bytes([0x01, 0x00, 0x39, 0x30])), 'database')
reg('MSSQL_MDF', make_stub(bytes([0x01, 0x0F, 0x00, 0x00])), 'database')
reg('Parquet', make_stub(b'PAR1'), 'database')
reg('ORC', make_stub(b'ORC'), 'database')
reg('Avro', make_stub(b'Obj\x01'), 'database')
reg('HDF5', make_stub(bytes([0x89]) + b'HDF' + bytes([0x0D, 0x0A, 0x1A, 0x0A])), 'database')
reg('NetCDF', make_stub(b'CDF'), 'database')
reg('Feather', make_stub(b'ARROW1'), 'database')
reg('NPY', make_npy, 'database')
reg('MAT', make_mat, 'database')
reg('PICKLE', make_pickle, 'database')
reg('PICKLE2', make_pickle, 'database')
reg('PICKLE3', make_pickle, 'database')
reg('PICKLE5', make_pickle, 'database')
reg('PICKLE_P0', make_pickle, 'database')
reg('PICKLE_P1', make_pickle, 'database')

# ---------------- email ----------------
reg('PST', make_stub(bytes([0x21, 0x42, 0x44, 0x4E])), 'email')
reg('MBOX', make_text, 'email')
reg('EML', make_text, 'email')
reg('EML_MSGID', make_text, 'email')
reg('DBX', make_stub(bytes([0xCF, 0xAD, 0x12, 0xFE])), 'email')
reg('MSG', make_ole_doc, 'email')

# ---------------- crypto ----------------
for n in ('PEM_CERT', 'PEM_RSA', 'PEM_EC', 'PEM_DSA', 'PEM_OPENSSH',
          'PEM_PRIVATE', 'PGP_PRIVATE', 'PGP_MESSAGE'):
    reg(n, make_pem, 'crypto')
reg('SSH_RSA_PUB', make_sshpub, 'crypto')
reg('SSH_ED25519_PUB', make_sshpub, 'crypto')
reg('PKCS12', make_der, 'crypto')
reg('JKS', make_stub(bytes([0xFE, 0xED, 0xFE, 0xED])), 'crypto')
reg('KDBX', make_stub(bytes([0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5])), 'crypto')
reg('KDB', make_stub(bytes([0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5])), 'crypto')
reg('GPG_KEYRING', lambda _n: bytes([0x99, 0x01, 0x1D, 0x01]) + b'\x00' * 284, 'crypto')  # self-consistent 288-byte key: len 0x011D=288-3, v1 body
reg('BITCOIN_WALLET', make_stub(bytes([0x00, 0x05, 0x31, 0x62, 0x00, 0x09, 0x00, 0x00])), 'crypto')

# ---------------- executables ----------------
reg('ELF', make_elf, 'executable')
reg('PE', make_pe, 'executable')
reg('MachO64', make_macho, 'executable')
reg('MachO32', make_macho, 'executable')
reg('MachO_FAT', make_stub(bytes([0xCA, 0xFE, 0xBA, 0xBF])), 'executable')
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
reg('EVT', make_stub(bytes([0x30, 0x00, 0x00, 0x00]) + b'LfLe'), 'forensic')
reg('REGF', make_regf, 'forensic')
reg('LNK', make_stub(bytes([0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])), 'forensic')
reg('PREFETCH', make_stub(b'SCCA'), 'forensic')
reg('PREFETCH_C', make_stub(bytes([0x4D, 0x41, 0x4D, 0x04])), 'forensic')
reg('JOB', make_stub(bytes([0x01, 0x05, 0x01, 0x00])), 'forensic')

# ---------------- vm ----------------
reg('QCOW2', make_qcow, 'vm')
reg('VMDK_SPARSE', make_stub(b'KDMV'), 'vm')
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
reg('DWG', make_stub(b'AC10'), 'misc')
reg('DXF', make_dxf, 'misc')
reg('STL_ASCII', make_stl, 'misc')
reg('BLEND', make_stub(b'BLENDER'), 'misc')
reg('FBX', make_stub(b'Kaydara FBX Binary'), 'misc')
reg('GLTF_BIN', make_glb, 'misc')
reg('TORRENT', make_stub(b'd8:announce', 80), 'misc')
reg('PLIST_XML', make_text, 'misc')
reg('PLIST_BIN', make_plist_bin, 'misc')
reg('DER', make_der, 'misc')
reg('DER_SMALL', make_der_small, 'misc')
reg('OPENVPN', make_stub(b'client\ndev tun'), 'misc')

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
            check_one(args.bin, args.work, n)
    print(f'\nTOTAL: {PASS} passed, {FAIL} failed of {len(names)}')
    for name, why in failures:
        print(f'  FAIL {name}: {why}')
    sys.exit(1 if FAIL else 0)


if __name__ == '__main__':
    main()

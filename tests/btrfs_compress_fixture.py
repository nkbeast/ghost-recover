#!/usr/bin/env python3
"""Rewrites raw extents of a mkfs.btrfs -r image into compressed ones.

The walker in src/fs/btrfs.cpp scans metadata chunks for valid leaves and
never validates checksums, so a fixture can be patched in place: the target
files' EXTENT_DATA items are updated to the compressed form and the payload
bytes are overwritten with the compressed stream. Byte-identical recovery
then proves the codec paths really ran (the raw bytes no longer exist).

Targets (all under the corpus root):
  docs/inline-a.txt   -> inline zlib  compressed extent
  docs/inline-b.txt   -> inline lzo   compressed extent
  docs/inline-c.txt   -> inline zstd  compressed extent
  media/compressible.bin -> regular zlib compressed extent(s)

Exits non-zero when a target is not stored in the expected form.
"""

import ctypes
import struct
import sys

MAGIC = b'_BHRfS_M'
K_HEADER = 101
K_ITEM = 25
KEY_EXTENT_DATA = 108
KEY_INODE_REF = 12
KEY_INODE_EXTREF = 13
BLOCK_GROUP_SYSTEM = 1 << 1
BLOCK_GROUP_METADATA = 1 << 2

# file_extent_item.ram_bytes, .compression, .type, and the inline payload
INLINE_COMP = 16
INLINE_RAM = 8
INLINE_TYPE = 20
INLINE_DATA = 21
REG_COMP = 16
REG_DISK_BYTENR = 21
REG_DISK_NUM_BYTES = 29
REG_NUM_BYTES = 45

BTRFS_COMPRESS_ZLIB = 1
BTRFS_COMPRESS_LZO = 2
BTRFS_COMPRESS_ZSTD = 3


def le16(b, o): return struct.unpack_from('<H', b, o)[0]
def le32(b, o): return struct.unpack_from('<I', b, o)[0]
def le64(b, o): return struct.unpack_from('<Q', b, o)[0]
def wle16(b, o, v): struct.pack_into('<H', b, o, v)
def wle32(b, o, v): struct.pack_into('<I', b, o, v)
def wle64(b, o, v): struct.pack_into('<Q', b, o, v)


class Lzo:
    def __init__(self):
        self.lib = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/liblzo2.so.2')
        getattr(self.lib, '__lzo_init_v2')(0x2060, -1, -1, -1, -1, -1, -1, -1, -1, -1)
        self.lib.lzo1x_1_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                              ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                              ctypes.c_void_p]

    def compress(self, data):
        out = ctypes.create_string_buffer(len(data) * 2 + 64)
        out_len = ctypes.c_size_t(0)
        wrk = ctypes.create_string_buffer(16384 * 64)
        rc = self.lib.lzo1x_1_compress(data, len(data), out,
                                       ctypes.byref(out_len), wrk)
        if rc != 0:
            raise RuntimeError(f'lzo1x_1_compress rc={rc}')
        return out.raw[:out_len.value]


class Zstd:
    def __init__(self):
        self.lib = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libzstd.so.1')
        self.lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
        self.lib.ZSTD_compressBound.restype = ctypes.c_size_t
        self.lib.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                           ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        self.lib.ZSTD_compress.restype = ctypes.c_size_t

    def compress(self, data):
        cap = self.lib.ZSTD_compressBound(len(data))
        out = ctypes.create_string_buffer(cap)
        n = self.lib.ZSTD_compress(out, cap, data, len(data), 3)
        if self.lib.ZSTD_isError(n):
            raise RuntimeError('zstd compress failed')
        return out.raw[:n]


def zlib_raw_deflate(data):
    import zlib
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def main():
    img_path, src_path = sys.argv[1], sys.argv[2]
    with open(img_path, 'r+b') as img:
        volume = img.seek(0, 2)
        img.seek(0)

        sb_off = None
        sb = None
        for off in (0x10000, 0x4000000, 0x4000000000, 0x4000000000000):
            if off + 4096 > volume:
                break
            img.seek(off)
            raw = img.read(4096)
            if raw[0x40:0x48] == MAGIC:
                sb_off, sb = off, raw
                break
        if sb is None:
            print('no btrfs superblock found')
            return 1

        fsid = sb[0x20:0x30]
        nodesize = le32(sb, 0x94)
        sectorsize = le32(sb, 0x90)
        sys_size = le32(sb, 0xA0)
        sys_off = 0x32B

        chunks = []          # (logical, length, type, physical)
        p = sys_off
        end = min(sys_off + sys_size, 0x32B + 2048)
        while p + 17 + 48 <= end:
            key_type = sb[p + 8]
            key_off = le64(sb, p + 9)
            cp = p + 17
            if key_type != 228:
                break
            length = le64(sb, cp)
            ctype = le64(sb, cp + 24)
            nstripes = le16(sb, cp + 44)
            if nstripes == 0 or nstripes > 64:
                break
            physical = le64(sb, cp + 56)
            chunks.append((key_off, length, ctype, physical))
            p = cp + 48 + 32 * nstripes

        def to_physical(logical):
            for (l, ln, _t, ph) in chunks:
                if l <= logical < l + ln:
                    return ph + (logical - l)
            return None

        def read_block(logical):
            ph = to_physical(logical)
            if ph is None or ph + nodesize > volume:
                return None
            img.seek(ph)
            return img.read(nodesize)

        # Descend the chunk tree so the map covers the whole volume.
        stack = [le64(sb, 0x58)]
        seen_logical = set()
        while stack:
            logical = stack.pop()
            if logical in seen_logical:
                continue
            seen_logical.add(logical)
            blk = read_block(logical)
            if blk is None or blk[0x20:0x30] != fsid:
                continue
            level = blk[100]
            nritems = le32(blk, 96)
            if nritems == 0 or nritems > nodesize // 25:
                continue
            if level > 0:
                for i in range(nritems):
                    q = K_HEADER + i * 33
                    stack.append(le64(blk, q + 17))
                continue
            for i in range(nritems):
                q = K_HEADER + i * K_ITEM
                if blk[q + 8] != 228:
                    continue
                data_off = le32(blk, q + 17)
                data_len = le32(blk, q + 21)
                dp = K_HEADER + data_off
                if data_len < 48 or dp + 48 > nodesize:
                    continue
                length = le64(blk, dp)
                ctype = le64(blk, dp + 24)
                nstripes = le16(blk, dp + 44)
                if nstripes == 0 or nstripes > 64:
                    continue
                physical = le64(blk, dp + 56)
                key_off = le64(blk, q + 9)
                if not any(c[0] == key_off for c in chunks):
                    chunks.append((key_off, length, ctype, physical))

        # Read the corpus files to know the true payloads.
        import os
        def corpus_bytes(rel):
            with open(os.path.join(src_path, rel), 'rb') as f:
                return f.read()

        lzo = Lzo()
        zstd = Zstd()
        targets = {
            'inline-a.txt': BTRFS_COMPRESS_ZLIB,
            'inline-b.txt': BTRFS_COMPRESS_LZO,
            'inline-c.txt': BTRFS_COMPRESS_ZSTD,
        }
        regular_target = ('compressible.bin', BTRFS_COMPRESS_ZLIB)

        inodes_by_name = {}
        extents = {}          # inode -> list of (leaf_physical, item_index)
        leaves_by_logical = {}

        # Scan metadata/system chunks for leaves, mirroring the walker.
        for (logical, length, ctype, physical) in chunks:
            if not (ctype & (BLOCK_GROUP_METADATA | BLOCK_GROUP_SYSTEM)):
                continue
            for off in range(0, length, nodesize):
                pos = physical + off
                if pos + nodesize > volume:
                    break
                img.seek(pos)
                blk = img.read(nodesize)
                if blk[0x20:0x30] != fsid:
                    continue
                if le64(blk, 48) != logical + off:
                    continue
                if blk[100] != 0:
                    continue
                nritems = le32(blk, 96)
                if nritems == 0 or nritems > nodesize // K_ITEM:
                    continue
                leaves_by_logical[logical + off] = (pos, blk)
                for i in range(nritems):
                    q = K_HEADER + i * K_ITEM
                    if q + K_ITEM > nodesize:
                        break
                    objid = le64(blk, q)
                    key_type = blk[q + 8]
                    data_off = le32(blk, q + 17)
                    data_len = le32(blk, q + 21)
                    dp = K_HEADER + data_off
                    if dp + data_len > nodesize:
                        continue
                    if key_type == KEY_INODE_REF and dp + 10 <= nodesize:
                        name_len = le16(blk, dp + 8)
                        name = blk[dp + 10:dp + 10 + name_len].decode('utf-8', 'replace')
                        inodes_by_name.setdefault(name, objid)
                    elif key_type == KEY_INODE_EXTREF and dp + 18 <= nodesize:
                        name_len = le16(blk, dp + 16)
                        name = blk[dp + 18:dp + 18 + name_len].decode('utf-8', 'replace')
                        inodes_by_name.setdefault(name, objid)
                    elif key_type == KEY_EXTENT_DATA and data_len >= 21:
                        extents.setdefault(objid, []).append((pos, i))

        import collections
        patched_inline = collections.Counter()
        patched_regular = 0

        for name, comp_id in targets.items():
            ino = inodes_by_name.get(name)
            if ino is None:
                print(f'ERROR: target {name} not found in image')
                return 1
            hits = [e for e in extents.get(ino, [])]
            if len(hits) != 1:
                print(f'ERROR: {name}: expected one inline extent, found {len(hits)}')
                return 1
            pos, idx = hits[0]
            img.seek(pos)
            blk = bytearray(img.read(nodesize))
            q = K_HEADER + idx * K_ITEM
            data_off = le32(blk, q + 17)
            data_len = le32(blk, q + 21)
            dp = K_HEADER + data_off
            if blk[dp + INLINE_TYPE] != 0:
                print(f'ERROR: {name}: extent is not inline')
                return 1
            payload = bytes(blk[dp + INLINE_DATA:dp + data_len])
            if payload != corpus_bytes(f'docs/{name}'):
                print(f'ERROR: {name}: inline payload mismatch at scan')
                return 1
            if comp_id == BTRFS_COMPRESS_ZLIB:
                blob = zlib_raw_deflate(payload)
            elif comp_id == BTRFS_COMPRESS_LZO:
                # Btrfs stores LZO inline extents in the page framing: a
                # LE32 total-size header plus LE32 segment sizes (lzo.c).
                raw = lzo.compress(payload)
                blob = struct.pack('<II', 4 + 4 + len(raw), len(raw)) + raw
            else:
                blob = zstd.compress(payload)
            new_len = INLINE_DATA + len(blob)
            if new_len > data_len:
                print(f'ERROR: {name}: compressed {len(blob)}B does not fit in '
                      f'{data_len - INLINE_DATA}B item')
                return 1
            wle64(blk, dp + INLINE_RAM, len(payload))
            blk[dp + INLINE_COMP] = comp_id
            blk[dp + INLINE_DATA:dp + new_len] = blob
            wle32(blk, q + 21, new_len)
            img.seek(pos)
            img.write(blk)
            patched_inline[name] = 1
            print(f'{name}: inline {data_len - INLINE_DATA}B -> {len(blob)}B (codec {comp_id})')

        name, comp_id = regular_target
        ino = inodes_by_name.get(name)
        if ino is None:
            print(f'ERROR: target {name} not found in image')
            return 1
        hits = extents.get(ino, [])
        if not hits:
            print(f'ERROR: {name}: no extents found')
            return 1
        want = corpus_bytes(f'media/{name}')
        offset = 0
        for (pos, idx) in hits:
            img.seek(pos)
            blk = bytearray(img.read(nodesize))
            q = K_HEADER + idx * K_ITEM
            data_off = le32(blk, q + 17)
            data_len = le32(blk, q + 21)
            dp = K_HEADER + data_off
            if blk[dp + INLINE_TYPE] != 1:
                print(f'ERROR: {name}: extent {idx} is not regular')
                return 1
            disk_bytenr = le64(blk, dp + REG_DISK_BYTENR)
            disk_num = le64(blk, dp + REG_DISK_NUM_BYTES)
            ext_off = le64(blk, dp + 37)
            num_bytes = le64(blk, dp + REG_NUM_BYTES)
            if ext_off != offset:
                print(f'ERROR: {name}: unexpected extent offset {ext_off} (want {offset})')
                return 1
            ph = to_physical(disk_bytenr)
            if ph is None or ph + disk_num > volume:
                print(f'ERROR: {name}: extent data outside the image')
                return 1
            img.seek(ph)
            raw = img.read(disk_num)
            # mkfs pads the final extent to a sector multiple; clamp to the
            # true file content so the recovered size matches the corpus.
            want_slice = want[offset:offset + num_bytes]
            if len(want_slice) < num_bytes:
                num_bytes = len(want_slice)
            if raw[:num_bytes] != want_slice:
                print(f'ERROR: {name}: extent payload mismatch at scan '
                      f'(off {offset}, {num_bytes}B)')
                return 1
            blob = zlib_raw_deflate(want_slice)
            if len(blob) >= disk_num:
                print(f'ERROR: {name}: compressed {len(blob)}B not smaller than {disk_num}B')
                return 1
            img.seek(ph)
            img.write(blob)
            blk[dp + INLINE_COMP] = comp_id
            wle64(blk, dp + REG_DISK_NUM_BYTES, len(blob))
            wle64(blk, dp + REG_NUM_BYTES, num_bytes)
            img.seek(pos)
            img.write(blk)
            offset += num_bytes
            patched_regular += 1
            print(f'{name}: extent {idx} {num_bytes}B -> {len(blob)}B (codec {comp_id})')

        if offset != len(want):
            print(f'ERROR: {name}: extents cover {offset} of {len(want)} bytes')
            return 1
        print(f'patched inline={sum(patched_inline.values())} regular={patched_regular}')
        return 0


if __name__ == '__main__':
    sys.exit(main())

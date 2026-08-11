#!/usr/bin/env python3
"""Populates an empty mkfs.exfat image with the corpus files.

A pure-python exFAT writer: parses the boot region, rewrites the root
directory cluster (system entries kept, then one entry set per corpus
file, then the terminator), writes each file as a contiguous cluster
run with the NoFatChain flag, and updates the FAT and the allocation
bitmap. Nothing needs a mount or root.

Exits non-zero when the volume layout cannot be handled.
"""

import os
import struct
import sys


def le16(b, o): return struct.unpack_from('<H', b, o)[0]
def le32(b, o): return struct.unpack_from('<I', b, o)[0]
def le64(b, o): return struct.unpack_from('<Q', b, o)[0]
def wle16(b, o, v): struct.pack_into('<H', b, o, v)
def wle32(b, o, v): struct.pack_into('<I', b, o, v)
def wle64(b, o, v): struct.pack_into('<Q', b, o, v)


def fat_time(ts):
    import datetime
    dt = datetime.datetime(2024, 1, 15, 12, 30, 0)
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return date, time


def main():
    img_path, src_path = sys.argv[1], sys.argv[2]
    with open(img_path, 'r+b') as img:
        volume = img.seek(0, 2)
        img.seek(0)
        boot = bytearray(img.read(512))
        if boot[3:11] != b'EXFAT   ':
            print('not an exFAT volume')
            return 1
        bps = 1 << boot[0x6C]
        spc = 1 << boot[0x6D]
        cluster = bps * spc
        fat_off = le32(boot, 0x50) * bps
        fat_len = le32(boot, 0x54) * bps
        heap_off = le32(boot, 0x58) * bps
        cluster_count = le32(boot, 0x5C)
        root_cluster = le32(boot, 0x60)
        if fat_off + fat_len > volume or heap_off + cluster_count * cluster > volume:
            print('implausible geometry')
            return 1

        img.seek(fat_off)
        fat = bytearray(img.read(fat_len))

        def fat_get(c):
            return le32(fat, c * 4)

        def chain(first, limit=65536):
            out, seen = [], set()
            cur = first
            while cur >= 2 and cur < cluster_count + 2 and len(out) < limit:
                if cur in seen:
                    break
                seen.add(cur)
                out.append(cur)
                nxt = fat_get(cur)
                if nxt == 0 or nxt >= 0xFFFFFFF8 or nxt < 2:
                    break
                cur = nxt
            return out

        root_clusters = chain(root_cluster)
        if not root_clusters:
            print('cannot follow the root directory chain')
            return 1
        img.seek(heap_off + (root_clusters[0] - 2) * cluster)
        root = bytearray(img.read(cluster))

        # Locate the allocation bitmap entry inside the root directory.
        bm_first = bm_len = None
        i = 0
        while i + 32 <= len(root):
            t = root[i]
            if t == 0:
                break
            if t == 0x81:
                bm_first = le32(root, i + 20)
                bm_len = le64(root, i + 24)
            i += 32
        if bm_first is None:
            print('no allocation bitmap entry found')
            return 1
        img.seek(heap_off + (bm_first - 2) * cluster)
        bitmap = bytearray(img.read(bm_len))

        def bitmap_get(c):
            if c < 2:
                return True
            byte = (c - 2) // 8
            if byte >= len(bitmap):
                return True
            return bool(bitmap[byte] & (1 << ((c - 2) % 8)))

        # First free cluster: scan past the system clusters.
        first_free = None
        for c in range(2, cluster_count + 2):
            if not bitmap_get(c):
                first_free = c
                break
        if first_free is None:
            print('volume is full')
            return 1

        # Where the system entries end (before the terminator).
        end_sys = 0
        i = 0
        while i + 32 <= len(root):
            t = root[i]
            if t == 0:
                break
            end_sys = i + 32
            i += 32

        entries = bytearray()
        cur = first_free
        files = []
        for name in sorted(f for f in os.listdir(f'{src_path}/docs') +
                           os.listdir(f'{src_path}/media') if os.path.isfile):
            for rel in ('docs', 'media'):
                p = f'{src_path}/{rel}/{name}'
                if not os.path.isfile(p):
                    continue
                data = open(p, 'rb').read()
                need = (len(data) + cluster - 1) // cluster
                files.append((name, cur, need * cluster, data))
                cur += need
                break

        date, time = fat_time(None)
        for (name, first, alloc_len, data) in files:
            nbytes = len(data)
            u16name = name.encode('utf-16-le')
            # entry 0: file
            e = bytearray(32)
            e[0] = 0x85
            e[1] = 2 + (len(u16name) + 29) // 30
            e[2:4] = b'\x00\x00'           # set checksum (unused by the walker)
            wle16(e, 4, 0x20)               # attributes: archive
            wle16(e, 8, time)               # ctime
            wle16(e, 10, date)
            wle16(e, 12, time)              # mtime
            wle16(e, 14, date)
            wle16(e, 16, time)              # atime
            wle16(e, 18, date)
            e[20] = 0                       # 10ms ctime
            e[21] = 0                       # 10ms mtime
            wle32(e, 22, 0)                 # ctime (unix)
            wle32(e, 26, 0)                 # mtime (unix)
            entries += e
            # entry 1: stream extension
            e = bytearray(32)
            e[0] = 0xC0
            e[1] = 0x02                     # NoFatChain | allocation possible
            e[3] = len(u16name) // 2        # name length
            wle64(e, 8, nbytes)             # valid data length
            wle32(e, 20, first)             # first cluster
            wle64(e, 24, nbytes)            # data length
            entries += e
            # name entries
            for k in range(0, len(u16name), 30):
                e = bytearray(32)
                e[0] = 0xC1
                part = u16name[k:k + 30]
                e[2:2 + len(part)] = part
                entries += e

        if len(entries) + end_sys + 32 > len(root):
            print(f'root directory overflow ({len(entries)} bytes of entries)')
            return 1
        new_root = bytearray(root[:end_sys]) + entries + bytes(32)
        img.seek(heap_off + (root_clusters[0] - 2) * cluster)
        img.write(new_root)

        # Mark the file clusters used in the FAT and the bitmap.
        used = set()
        for (name, first, alloc_len, data) in files:
            need = alloc_len // cluster
            for k in range(need):
                c = first + k
                nxt = c + 1 if k + 1 < need else 0xFFFFFFFF
                wle32(fat, c * 4, nxt)
                used.add(c)
        img.seek(fat_off)
        img.write(fat)
        for c in used:
            bitmap[(c - 2) // 8] |= 1 << ((c - 2) % 8)
        img.seek(heap_off + (bm_first - 2) * cluster)
        img.write(bitmap)

        # The files themselves.
        for (name, first, alloc_len, data) in files:
            img.seek(heap_off + (first - 2) * cluster)
            img.write(data)

        print(f'populated {len(files)} files, {sum(a for _, _, a, _ in files)} bytes '
              f'of clusters (heap starts at cluster {first_free})')
        return 0


if __name__ == '__main__':
    sys.exit(main())

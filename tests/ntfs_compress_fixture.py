#!/usr/bin/env python3
"""Turns one file of an mkntfs-populated image into an LZNT1-compressed one.

The corpus file media/compressible.bin is stored as a non-resident $DATA
attribute. This script rewrites its clusters with an LZNT1 stream (4 KiB
sub-blocks with 0xB000/0x3000 headers, zero end marker) and sets the
compressed flag on the attribute. The walker in src/fs/ntfs.cpp then has to
run the whole chain through lznt1Decode to recover the original bytes; the
raw content no longer exists in the image.

Exits non-zero when the target is not stored as expected.
"""

import struct
import sys


def le16(b, o): return struct.unpack_from('<H', b, o)[0]
def le32(b, o): return struct.unpack_from('<I', b, o)[0]
def le64(b, o): return struct.unpack_from('<Q', b, o)[0]
def wle16(b, o, v): struct.pack_into('<H', b, o, v)


def make_lznt1_encoder():
    # Greedy byte-pair hashing, MS-XCA shift rules; cross-validated against
    # the engine's decoder (see /tmp history and the selftest vectors).
    def encode_chunk(data):
        n = len(data)
        if n == 0:
            return b''
        heads, prevs = {}, {}

        def find(offset, maxoff, maxlen):
            if offset + 3 > n:
                return 0, 0
            key = (data[offset] << 8) | data[offset + 1]
            best_l, best_o = 0, 0
            pos = heads.get(key)
            limit = max(1, offset - maxoff)
            while pos is not None and pos >= limit:
                max_len = min(n - offset, maxlen)
                l = 0
                while l < max_len and data[pos + l] == data[offset + l]:
                    l += 1
                if l > best_l:
                    best_l, best_o = l, offset - pos
                pos = prevs.get(pos, None)
            return best_l, best_o

        out = bytearray()
        pos = 0
        shift = 12
        threshold = 16
        tag_pos = 0
        cur_tag = -1

        def commit(bit, payload):
            nonlocal out, tag_pos, cur_tag
            if tag_pos % 8 == 0:
                out.append(0)
                cur_tag = len(out) - 1
            if bit:
                out[cur_tag] |= 1 << (tag_pos % 8)
            tag_pos += 1
            out += payload

        while pos < n:
            maxoff = (0xFFFF >> shift) + 1
            maxlen = (1 << shift) + 2
            plen, poff = find(pos, maxoff, maxlen)
            if plen >= 3 and poff > 0:
                off_bits = poff - 1
                len_bits = plen - 3
                assert off_bits <= (0xFFFF >> shift), (pos, poff, shift)
                commit(True, struct.pack('<H', (off_bits << shift) | len_bits))
            else:
                commit(False, bytes([data[pos]]))
                plen = 1
            nxt = pos + plen
            for i in range(pos, nxt):
                if i + 3 <= n:
                    key = (data[i] << 8) | data[i + 1]
                    prevs[i] = heads.get(key, -1)
                    heads[key] = i
            pos = nxt
            while pos > threshold and shift > 0:
                shift -= 1
                threshold <<= 1
        return bytes(out)

    def encode(data):
        units = bytearray()
        for off in range(0, len(data), 4096):
            chunk = data[off:off + 4096]
            enc = encode_chunk(chunk)
            if len(enc) + 2 < len(chunk):
                units += struct.pack('<H', 0x8000 | (len(enc) - 1))
                units += enc
            else:
                units += struct.pack('<H', len(chunk) - 1)
                units += chunk
        units += struct.pack('<H', 0)
        return bytes(units)

    return encode


def decode_runlist(blk, run_off, attr_off):
    runs = []
    p = attr_off + run_off
    offset = 0
    while True:
        h = blk[p]
        if h == 0:
            break
        p += 1
        len_bytes = h & 0x0F
        off_bytes = h >> 4
        length = int.from_bytes(blk[p:p + len_bytes], 'little')
        p += len_bytes
        off_raw = blk[p:p + off_bytes]
        if off_bytes:
            off_raw = off_raw + (b'\x00' if off_raw[-1] < 0x80 else b'\xff')
            offset += int.from_bytes(off_raw, 'little', signed=True)
            p += off_bytes
        runs.append((length, offset))
    return runs


def main():
    img_path, src_path = sys.argv[1], sys.argv[2]
    target = 'compressible.bin'
    with open(img_path, 'r+b') as img:
        volume = img.seek(0, 2)
        img.seek(0)
        boot = img.read(512)
        if boot[3:11] != b'NTFS    ':
            print('no NTFS boot sector found')
            return 1
        sector = le16(boot, 0x0B)
        cluster = sector * boot[0x0D]
        mft_lcn = le64(boot, 0x30)
        cpr = boot[0x40]
        record = (1 << (0x100 - cpr)) if cpr >= 0x80 else cpr * cluster

        img.seek(mft_lcn * cluster)
        mft0 = img.read(record)
        if mft0[0:4] != b'FILE':
            print('MFT record 0 missing')
            return 1
        # $DATA attribute of record 0 holds the MFT runlist.
        p = le16(mft0, 0x14)
        mft_runs = []
        while True:
            t = le32(mft0, p)
            if t == 0xFFFFFFFF:
                break
            if t == 0x80 and mft0[p + 8] != 0:
                run_off = le16(mft0, p + 0x20)
                mft_runs = decode_runlist(mft0, run_off, p)
                break
            p += le32(mft0, p + 4)

        if not mft_runs:
            print('cannot find the MFT runlist')
            return 1
        mft_base = mft_runs[0][1] * cluster

        def read_mft(idx):
            img.seek(mft_base + idx * record)
            return bytearray(img.read(record))

        want = None
        with open(f'{src_path}/media/{target}', 'rb') as f:
            want = f.read()

        found = None
        mft_bytes = 0
        for (length, _lcn) in mft_runs:
            mft_bytes += length * cluster
        rec_count = mft_bytes // record

        for idx in range(rec_count):
            blk = read_mft(idx)
            if blk[0:4] != b'FILE':
                continue
            p = le16(blk, 0x14)
            guard = 0
            while guard < 64:
                guard += 1
                t = le32(blk, p)
                if t == 0xFFFFFFFF:
                    break
                if t == 0x30:
                    vlen = le32(blk, p + 0x10)
                    voff = le16(blk, p + 0x14)
                    vp = p + voff
                    if vlen >= 0x42 and 1 <= blk[vp + 0x40] <= 255 and \
                            vp + 0x42 + blk[vp + 0x40] * 2 <= len(blk):
                        nl = blk[vp + 0x40]
                        try:
                            name = blk[vp + 0x42:vp + 0x42 + nl * 2].decode('utf-16-le')
                        except UnicodeDecodeError:
                            name = ''
                        if name == target:
                            found = (idx, p)
                p += le32(blk, p + 4)
            if found:
                break
        if found is None:
            print(f'ERROR: {target} not found in MFT')
            return 1
        idx = found[0]
        blk = read_mft(idx)
        attr_off = None
        p = le16(blk, 0x14)
        guard = 0
        while guard < 64:
            guard += 1
            t = le32(blk, p)
            if t == 0xFFFFFFFF:
                break
            if t == 0x80 and blk[p + 8] != 0 and blk[p + 9] == 0:
                attr_off = p
                break
            p += le32(blk, p + 4)
        if attr_off is None:
            print(f'ERROR: {target} $DATA is not a non-resident unnamed stream')
            return 1
        run_off = le16(blk, attr_off + 0x20)
        runs = decode_runlist(blk, run_off, attr_off)
        if not runs:
            print(f'ERROR: {target} has no data runs')
            return 1
        # Reject sparse runs and multiple fragments: the chain must be one
        # contiguous extent for the engine's LZNT1 path.
        if len(runs) != 1:
            print(f'ERROR: {target} is fragmented ({len(runs)} runs); '
                  'cannot compress in place')
            return 1
        length, lcn = runs[0]
        data_off = lcn * cluster
        data_bytes = length * cluster
        if data_bytes < len(want):
            print(f'ERROR: {target} run is smaller than the file')
            return 1

        img.seek(data_off)
        raw = img.read(data_bytes)
        if raw[:len(want)] != want:
            print('ERROR: stored bytes do not match the corpus file')
            return 1

        stream = make_lznt1_encoder()(want)
        if len(stream) >= data_bytes:
            print(f'ERROR: compressed stream {len(stream)}B does not fit in '
                  f'{data_bytes}B of clusters')
            return 1
        img.seek(data_off)
        img.write(stream)
        img.seek(data_off + len(stream))
        img.write(bytes(data_bytes - len(stream)))

        # Set the compressed flag; the compression-unit byte (exponent of a
        # 4 KiB sub-block cluster count) is informational for the walker,
        # which decodes the whole chain regardless.
        blk[attr_off + 0x22] = 16
        wle16(blk, attr_off + 0x0C, le16(blk, attr_off + 0x0C) | 0x0001)
        img.seek(mft_base + idx * record)
        img.write(blk)

        print(f'{target}: {len(want)}B -> {len(stream)}B LZNT1 in {data_bytes}B '
              f'(record {idx}, attr {attr_off:#x})')
        return 0


if __name__ == '__main__':
    sys.exit(main())

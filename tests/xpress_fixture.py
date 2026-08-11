#!/usr/bin/env python3
"""Independent MS-XCA XPRESS encoders (plain LZ77 + LZ77+Huffman).

Produces compressed blocks from plain bytes with NO dependency on the
engine's decoders. The blocks are valid per the spec's own worked examples
(section 3.1), so the engine decoding them byte-for-byte proves the in-tree
decoders.

Plain LZ77 (MS-XCA 2.1.1):
  - 32-bit flag groups, bit 31 tested first; 0 = literal, 1 = match.
  - Match word: LE16 ((off-1) << 3) | (len-3), off in [1, 8192].
  - len-3 == 7: shared-nibble byte (first extension match uses the low
    nibble, the next consecutive one uses the high nibble; an intervening
    non-extension token leaves the unused half at 0).
  - nibble 15: extension byte = len-3 (must be >= 22; len 18..24 is never
    emitted -- matches in that range are clamped to 17), 255 -> u16 = len-3,
    u16 0 -> u32 = len-3.
  - The last flag group is padded with 1 bits; a match flag with no input
    left is the end-of-data marker.

LZ77+Huffman (MS-XCA 2.1.2/2.1.4):
  - 256-byte table of 512 4-bit code lengths (even symbol = low nibble,
    odd symbol = high nibble). Canonical codes sorted by (len, symbol).
  - Bit stream: LE16 words, MSB-first, 32-bit register (2 words preloaded),
    refill one word while fewer than 15 bits remain.
  - Symbol < 256: literal. Symbol 256: EOF (Microsoft treats it as a
    match of length 3, distance 1 when output is not yet complete).
  - Match symbol: 256 + min(len-3, 15) + 16 * highbit(off).
  - nibble 15: extension byte = len-18 (mlen = byte + 18), 255 -> u16 =
    len-3, u16 0 -> u32 = len-3.
  - Extra-length bytes are NOT in the bit stream: they are written after
    the bit words (the decoder reads them from the raw stream at the
    current word boundary). The fixture therefore only places a single
    trailing nib-15 match per block, with all symbol bits (including EOF)
    written before the extras; the bit region is padded to >= 32 bits.

Usage:
    python3 tests/xpress_fixture.py            # self-check both encoders
    python3 tests/emit_xpress_vectors.py       # emit C vector literals
"""

import heapq
import struct
import sys


def high_bit(n):
    return n.bit_length() - 1


# ---------------------------------------------------------------------------
# Plain LZ77 (MS-XCA 2.1.1)
# ---------------------------------------------------------------------------

class PlainLz77Encoder:
    def __init__(self, data, window=8192, max_len=65536):
        self.data = data
        self.window = window
        self.max_len = max_len

    def _find_match(self, pos):
        n = len(self.data)
        if pos + 3 > n:
            return 0, 0
        key = (self.data[pos] << 8) | self.data[pos + 1]
        best_l, best_o = 0, 0
        cand = self._heads.get(key)
        tries = 0
        while cand is not None and cand >= max(0, pos - self.window) and tries < 64:
            l = 0
            while pos + l < n and l < self.max_len and self.data[cand + l] == self.data[pos + l]:
                l += 1
            if l > best_l:
                best_l, best_o = l, pos - cand
            cand = self._prevs.get(cand)
            tries += 1
        return best_l, best_o

    def _lz77(self):
        n = len(self.data)
        items = []  # ('lit', byte) | ('match', offset, length)
        self._heads, self._prevs = {}, {}
        pos = 0
        while pos < n:
            l, o = self._find_match(pos)
            if l >= 3:
                if 18 <= l <= 24:
                    l = 17  # lengths 18..24 cannot be encoded in the plain variant
                items.append(('match', o, l))
            else:
                items.append(('lit', self.data[pos]))
                l = 1
            if pos + 2 < n:
                key = (self.data[pos] << 8) | self.data[pos + 1]
                self._prevs[pos] = self._heads.get(key)
                self._heads[key] = pos
            pos += l
        return items

    def encode(self):
        items = self._lz77()
        out = bytearray()
        pending_idx = None  # index into out of the shared-length byte

        def emit_lit(b):
            out.append(b)

        def emit_match(offset, length):
            nonlocal pending_idx
            low3 = length - 3
            if low3 <= 6:
                if pending_idx is not None:
                    pending_idx = None
                out.extend(struct.pack('<H', ((offset - 1) << 3) | low3))
                return
            out.extend(struct.pack('<H', ((offset - 1) << 3) | 7))
            if low3 <= 14:
                if pending_idx is None:
                    out.append(low3)
                    pending_idx = len(out) - 1
                else:
                    out[pending_idx] |= low3 << 4
                    pending_idx = None
                return
            if pending_idx is None:
                out.append(15)
                pending_idx = len(out) - 1
            else:
                out[pending_idx] |= 15 << 4
                pending_idx = None
            v = length - 3
            if v < 255:
                out.append(v)
                return
            out.append(255)
            if v < 65536:
                out.extend(struct.pack('<H', v))
            else:
                out.extend(struct.pack('<H', 0) + struct.pack('<I', v))

        n_groups = (len(items) + 31) // 32
        for g in range(n_groups):
            chunk = items[g * 32:(g + 1) * 32]
            flags = 0
            for j, item in enumerate(chunk):
                if item[0] == 'match':
                    flags |= 1 << (31 - j)
            if g == n_groups - 1:
                for j in range(len(chunk), 32):
                    flags |= 1 << (31 - j)  # end-of-data marker
            out += struct.pack('<I', flags)
            for item in chunk:
                if item[0] == 'lit':
                    emit_lit(item[1])
                else:
                    emit_match(item[1], item[2])
        return bytes(out)


# ---------------------------------------------------------------------------
# LZ77+Huffman (MS-XCA 2.1.2/2.1.4)
# ---------------------------------------------------------------------------

class HuffmanEncoder:
    def __init__(self, data, window=32768, max_len=65535):
        self.data = data
        self.window = window
        self.max_len = max_len

    def _find_match(self, pos):
        n = len(self.data)
        if pos + 3 > n:
            return 0, 0
        key = (self.data[pos] << 8) | self.data[pos + 1]
        best_l, best_o = 0, 0
        cand = self._heads.get(key)
        tries = 0
        while cand is not None and cand >= max(0, pos - self.window) and tries < 64:
            l = 0
            while pos + l < n and l < self.max_len and self.data[cand + l] == self.data[pos + l]:
                l += 1
            if l > best_l:
                best_l, best_o = l, pos - cand
            cand = self._prevs.get(cand)
            tries += 1
        return best_l, best_o

    def _lz77(self):
        n = len(self.data)
        items = []
        self._heads, self._prevs = {}, {}
        pos = 0
        while pos < n:
            l, o = self._find_match(pos)
            if l >= 3:
                items.append(('match', o, l))
            else:
                items.append(('lit', self.data[pos]))
                l = 1
            if pos + 2 < n:
                key = (self.data[pos] << 8) | self.data[pos + 1]
                self._prevs[pos] = self._heads.get(key)
                self._heads[key] = pos
            pos += l
        return items

    def encode(self):
        items = self._lz77()
        for it in items:
            if it[0] != 'match':
                continue
            _, o, l = it
            hb = high_bit(o)
            assert hb <= 15, o
            assert l <= self.max_len + 1, l
        freq = {}
        for it in items:
            if it[0] == 'lit':
                freq[it[1]] = freq.get(it[1], 0) + 1
            else:
                o, l = it[1], it[2]
                nib = min(l - 3, 15)
                freq[256 + nib + 16 * high_bit(o)] = freq.get(256 + nib + 16 * high_bit(o), 0) + 1
        freq[256] = freq.get(256, 0) + 1  # EOF symbol
        lengths = self._real_huffman_lengths(freq)
        codes = build_huffman(lengths)
        bits = []

        def put(n, v):
            for i in range(n - 1, -1, -1):
                bits.append((v >> i) & 1)

        def pack16(chunk):
            w = 0
            for b in chunk:
                w = (w << 1) | b
            return struct.pack('<H', w)

        extras = bytearray()
        nbits = 32              # decoder register: 2 words preloaded
        words_flushed = 2
        pre_words = None        # word count at the nib-15 match (extras position)

        def sim_refill(need):
            nonlocal nbits, words_flushed
            while nbits < need:
                nbits += 16
                words_flushed += 1

        for it in items:
            if it[0] == 'lit':
                sym, nib, hb, off = it[1], None, 0, 0
            else:
                o, l = it[1], it[2]
                hb = high_bit(o)
                nib = min(l - 3, 15)
                off = o - (1 << hb) if hb else 0
                sym = 256 + nib + 16 * hb
            llen, ccode = codes[sym]
            sim_refill(15)
            put(llen, ccode)
            nbits -= llen
            if it[0] == 'match':
                sim_refill(hb)
                if hb:
                    put(hb, off)
                    nbits -= hb
                if nib == 15:
                    assert pre_words is None, "only one trailing nib-15 match per block"
                    pre_words = words_flushed
                    v = l - 18
                    if v < 255:
                        extras.append(v)
                    else:
                        extras.append(255)
                        if l - 3 < 65536:
                            extras += struct.pack('<H', l - 3)
                        else:
                            extras += struct.pack('<H', 0) + struct.pack('<I', l - 3)
        llen, ccode = codes[256]
        sim_refill(15)
        put(llen, ccode)
        nbits -= llen
        assert nbits >= 0

        while len(bits) < 32:
            bits.append(0)
        while len(bits) % 16:
            bits.append(0)
        total_words = words_flushed
        while len(bits) < total_words * 16:
            bits.append(0)
        pre = (pre_words if pre_words is not None else total_words) * 16
        table = bytearray(256)
        for s in range(512):
            l = lengths.get(s, 0)
            table[s // 2] |= (l << 4) if (s & 1) else l
        block = bytes(table)
        block += b''.join(pack16(bits[i:i + 16]) for i in range(0, pre, 16))
        block += bytes(extras)
        block += b''.join(pack16(bits[i:i + 16]) for i in range(pre, len(bits), 16))
        return block

    def _real_huffman_lengths(self, freq):
        """Real Huffman tree depths; must stay <= 15 for the format."""
        class Node:
            __slots__ = ('kids', 'sym')
            def __init__(self, kids, sym=None):
                self.kids = kids
                self.sym = sym
        heap = []
        seq = 0
        for s, w in freq.items():
            if w > 0:
                heap.append([w, seq, Node(None, s)])
                seq += 1
        heapq.heapify(heap)
        while len(heap) > 1:
            a = heapq.heappop(heap)
            b = heapq.heappop(heap)
            heapq.heappush(heap, [a[0] + b[0], seq, Node((a[2], b[2]))])
            seq += 1
        lens = {}

        def walk(node, depth):
            if node.kids is None:
                lens[node.sym] = depth
                return
            walk(node.kids[0], depth + 1)
            walk(node.kids[1], depth + 1)

        walk(heap[0][2], 0)
        mx = max(lens.values())
        assert mx <= 15, mx
        return lens


def build_huffman(lengths):
    """Canonical codes for a {symbol: bit_length} dict, (len, symbol) order."""
    codes = {}
    code = 0
    prev = None
    for l, s in sorted((lengths.get(s, 0), s) for s in range(512)):
        if l == 0:
            continue
        if prev is None:
            code = 0
        else:
            code = (code + 1) << (l - prev)
        codes[s] = (l, code)
        prev = l
    return codes


# ---------------------------------------------------------------------------
# Reference decoders for self-check (independent of the C++ side)
# ---------------------------------------------------------------------------

def decode_plain(data, expected):
    out = bytearray()
    pos = 0
    flags = 0
    flag_count = 0
    last_len_pos = None
    while len(out) < expected:
        if flag_count == 0:
            if pos + 4 > len(data):
                break
            flags = struct.unpack('<I', data[pos:pos + 4])[0]
            pos += 4
            flag_count = 32
        flag_count -= 1
        if (flags & (1 << flag_count)) == 0:
            last_len_pos = None
            out += bytes([data[pos]])
            pos += 1
            continue
        if pos >= len(data):
            break  # end-of-data marker
        mb = struct.unpack('<H', data[pos:pos + 2])[0]
        pos += 2
        mlen = mb & 7
        moff = (mb >> 3) + 1
        if mlen == 7:
            if last_len_pos is None:
                nib = data[pos] & 0x0F
                last_len_pos = pos
                pos += 1
            else:
                nib = data[last_len_pos] >> 4
                last_len_pos = None
            if nib == 15:
                v = data[pos]
                pos += 1
                if v == 255:
                    v = struct.unpack('<H', data[pos:pos + 2])[0]
                    pos += 2
                    if v == 0:
                        v = struct.unpack('<I', data[pos:pos + 4])[0]
                        pos += 4
                assert v >= 22, (v, data.hex())
                mlen = v + 3
            else:
                mlen = nib + 3
        else:
            mlen = mlen + 3
            last_len_pos = None
        assert moff <= len(out), (moff, len(out), data.hex())
        for _ in range(mlen):
            out.append(out[-moff])
    return bytes(out[:expected])


def rev16(w):
    return int('{:016b}'.format(w)[::-1], 2)


def decode_huffman(data, expected):
    out = bytearray()
    pos = 0
    while len(out) < expected:
        assert pos + 256 <= len(data)
        lens = []
        for i in range(256):
            b = data[pos + i]
            lens.append(b & 0x0F)
            lens.append(b >> 4)
        pos += 256
        table = [0] * 32768
        entry = 0
        for l in range(1, 16):
            for s in range(512):
                if lens[s] == l:
                    for _ in range(1 << (15 - l)):
                        table[entry] = s
                        entry += 1
        assert entry == 32768, entry
        sym_len = lens
        bits = 0
        nbits = 0
        while nbits < 32:
            assert pos + 2 <= len(data)
            bits |= struct.unpack('<H', data[pos:pos + 2])[0] << (16 - nbits)
            pos += 2
            nbits += 16
        while len(out) < expected:
            while nbits < 15:
                assert pos + 2 <= len(data)
                bits |= struct.unpack('<H', data[pos:pos + 2])[0] << (16 - nbits)
                pos += 2
                nbits += 16
            idx = (bits >> 17) & 0x7FFF
            sym = table[idx]
            l = sym_len[sym]
            bits = (bits << l) & 0xFFFFFFFF
            nbits -= l
            if sym < 256:
                out.append(sym)
                continue
            if sym == 256:
                if len(out) == expected:
                    break
                mlen, hb, moff = 3, 0, 1  # Microsoft: 256 is match(3, 1) mid-stream
            else:
                hb = (sym - 256) // 16
                mlen = (sym - 256) % 16
                if mlen == 15:
                    v = data[pos]
                    pos += 1
                    if v == 255:
                        v = struct.unpack('<H', data[pos:pos + 2])[0]
                        pos += 2
                        if v == 0:
                            v = struct.unpack('<I', data[pos:pos + 4])[0]
                            pos += 4
                        mlen = v + 3
                    else:
                        mlen = v + 18
                else:
                    mlen = mlen + 3
                while nbits < hb:
                    assert pos + 2 <= len(data)
                    bits |= struct.unpack('<H', data[pos:pos + 2])[0] << (16 - nbits)
                    pos += 2
                    nbits += 16
                moff = (bits >> (32 - hb)) & ((1 << hb) - 1) if hb else 0
                bits = (bits << hb) & 0xFFFFFFFF
                nbits -= hb
                moff += (1 << hb)
            assert moff <= len(out), (moff, len(out))
            for _ in range(mlen):
                out.append(out[-moff])
    return bytes(out[:expected])


# ---------------------------------------------------------------------------
# MS-XCA section 3.1 example: 100 repetitions of "abc" (authoritative anchor)
# ---------------------------------------------------------------------------

def anchor_block():
    """Table: a=3, b=3, c=2, EOF(256)=2, 287=2; stream: a8 dc 00 00 ff 26 01.

    287 is a match: nibble 15 (length extension), high bit 1 (offset 2..3).
    Extras: 0xff, 0x0126 -> length 0x126+3 = 297 at offset 3; then EOF.
    """
    table = bytearray(256)
    for s, l in ((97, 3), (98, 3), (99, 2), (256, 2), (287, 2)):
        if s & 1:
            table[s // 2] |= l << 4
        else:
            table[s // 2] |= l
    return bytes(table) + bytes.fromhex('a8 dc 00 00 ff 26 01')


def main():
    emit = '--c' in sys.argv
    plains = [
        b"GHOST//RECOVER data recovery engine.\n",
        b'abc' * 100,                       # short matches only
        b'P' * 40,                          # single-byte length extension (len 37)
        b'A' * 700,                         # 0xff + u16 extension
        b'Q' * 4000,                        # 0xff + u16 extension
        b'abcdefghij' * 30,                 # shared half-byte, two consecutive
        b'abcdefghij' * 3 + b'!' + b'abcdefghij' * 3,  # shared half-byte, interrupted
        bytes((i * 7 + 3) % 251 for i in range(9000)),  # one long match, u16 extension
    ]
    huffs = [
        b"The quick brown fox jumps over the lazy dog. " * 8,
        b'abcdabcdabcdabcd' * 600,
        b'z' * 3000,
        bytes(((i * 13 + 5) % 253) for i in range(20000)),
        b'x' * 65536,
        b'x' * 21,                          # single-byte extension (len 18, byte 0)
        b'abcdefghijklmnopqrst' * 2,        # len 20, offset 20 (high bit 4)
    ]
    print("== plain LZ77 ==")
    for i, d in enumerate(plains):
        enc = PlainLz77Encoder(d).encode()
        if not emit:
            dec = decode_plain(enc, len(d))
            assert dec == d, f"plain self-check {i} failed"
        print(f"  case {i}: {len(d)} bytes -> {len(enc)} coded")
        print(f"    {enc.hex()}")
    print("== LZ77+Huffman ==")
    for i, d in enumerate(huffs):
        enc = HuffmanEncoder(d).encode()
        if not emit:
            dec = decode_huffman(enc, len(d))
            assert dec == d, f"huffman self-check {i} failed"
        print(f"  case {i}: {len(d)} bytes -> {len(enc)} coded")
        print(f"    {enc.hex()}")
    if not emit:
        dec = decode_huffman(anchor_block(), 300)
        assert dec == b'abc' * 100, dec[:32]
        print("  anchor: MS-XCA 3.1 example decodes to 100x'abc'")
        print("self-check: ok")
    else:
        print("emitting vectors")


if __name__ == '__main__':
    main()

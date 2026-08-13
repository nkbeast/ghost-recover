#!/usr/bin/env python3
"""Independent encoders for the WOF system-compression codecs.

Formats implemented (from public specifications [MS-XCA], [MS-PATCH] and the
Microsoft LZX 1997 spec; semantics cross-checked against the reference
implementations in ntfs-3g-system-compression and wimlib):

  XPRESS LZ77+Huffman   256-byte table of 512 4-bit codeword lengths; a bit
                        stream of 16-bit little-endian coding units consumed
                        MSB-first within each unit; extended match lengths
                        are interleaved into the stream as literal bytes
                        between the coding units; end-of-data symbol 256.
  LZX (WIM subset)      verbatim/aligned/uncompressed blocks, precode
                        delta-coded codeword lengths, repeat offsets, and
                        E8 preprocessing with the fixed WIM magic file
                        size 12000000.

These encoders are deliberately simple (greedy literal/match parsing, exact
canonical Huffman codes) but emit bit-exact valid streams.  They produce the
WOF-compressed fixture files and the embedded selftest vectors, so the C++
decoders in src/core/decompress.cpp are exercised against an independent
implementation of the same formats.

Delta-code caveat: in LZX, each codeword length is encoded as a delta from
the *corresponding length in the previous block* of the same chunk (zero for
the first block), not from a running chain.  The main code is split into two
independent chains (symbols 0..255 and 256..num_main_syms-1) and the length
code into a third.  `lzx_encode_blocks` tracks the previous block's lengths
so multi-block chunks round-trip correctly.
"""

import struct
import sys

# --------------------------------------------------------------- bit streams
def _bitreverse(x, n):
    return int(('{:0%db}' % n).format(x)[::-1], 2)


class UnitBitWriter:
    """Writes a bit stream of 16-bit little-endian coding units, bits
    consumed MSB-first within each unit (the XPRESS/LZX convention).

    A raw-byte interleave is supported: bytes written via write_byte() land
    *between* the coding units, exactly as the XPRESS format requires for
    extended match lengths.  The bookkeeping mirrors the reference output
    bitstream: a pending bit buffer flushes 16-bit units at `next_bits`, raw
    bytes go to `next_byte`, and finish() zero-fills the trailing slots."""

    def __init__(self):
        self.buf = bytearray()
        self.bitbuf = 0
        self.bitcount = 0
        self.next_bits = 0
        self.next_bits2 = 2
        self.next_byte = 4

    def write_bits(self, bits, num):
        if num == 0:
            return
        self.bitcount += num
        self.bitbuf = (self.bitbuf << num) | bits
        if self.bitcount > 16:
            self.bitcount -= 16
            self._put16(self.bitbuf >> self.bitcount, self.next_bits)
            self.next_bits, self.next_bits2 = self.next_bits2, self.next_byte
            self.next_byte += 2

    def write_byte(self, b):
        self._put8(b, self.next_byte)
        self.next_byte += 1

    def write_u16(self, v):
        self._put16(v, self.next_byte)
        self.next_byte += 2

    def finish(self):
        self._put16(self.bitbuf << (16 - self.bitcount), self.next_bits)
        self._put16(0, self.next_bits2)
        return bytes(self.buf[:self.next_byte])

    def _put8(self, b, off):
        while len(self.buf) < off + 1:
            self.buf.append(0)
        self.buf[off] = b & 0xFF

    def _put16(self, v, off):
        while len(self.buf) < off + 2:
            self.buf.append(0)
        self.buf[off] = v & 0xFF
        self.buf[off + 1] = (v >> 8) & 0xFF


# ------------------------------------------------------------- huffman codes
def canonical_codes(lengths):
    """Canonical prefix codes from a length list: codewords are enumerated in
    lexicographic order after sorting symbols by increasing length, then by
    symbol value; the first bit of a codeword is its most significant bit."""
    n = len(lengths)
    counts = {}
    for L in lengths:
        if L:
            counts[L] = counts.get(L, 0) + 1
    if not counts:
        return [(0, 0)] * n
    code = 0
    next_code = {}
    for L in range(1, max(lengths) + 1):
        code = (code + counts.get(L - 1, 0)) << 1
        next_code[L] = code
    out = []
    for L in lengths:
        if L == 0:
            out.append((0, 0))
        else:
            out.append((next_code[L], L))
            next_code[L] += 1
    return out


def huffman_lengths(freqs, max_len=16):
    """Huffman tree depths.  The resulting code is complete (Kraft sum 1),
    which the reference decoders require.  A single-symbol code is completed
    with one dummy codeword of the same length.  If the tree would exceed
    `max_len`, a flat complete code is used instead (all used symbols at
    length L = ceil(log2 k), padded with dummies) — always valid."""
    n = len(freqs)

    class Node:
        __slots__ = ('w', 'sym', 'left', 'right')

        def __init__(self, w, sym=None):
            self.w = w
            self.sym = sym
            self.left = None
            self.right = None

    import heapq
    heap = []
    seq = 0
    for i, f in enumerate(freqs):
        if f > 0:
            heapq.heappush(heap, (f, seq, Node(f, i)))
            seq += 1
    if not heap:
        return [0] * n
    if len(heap) == 1:
        # A single-symbol code is rejected by the decoders; give the used
        # symbol and the first unused one both length 1.
        lens = [1 if f > 0 else 0 for f in freqs]
        for i in range(n):
            if lens[i] == 0:
                lens[i] = 1
                break
        return lens
    order = 0
    while len(heap) > 1:
        _, _, a = heapq.heappop(heap)
        _, _, b = heapq.heappop(heap)
        parent = Node(a.w + b.w)
        parent.left, parent.right = a, b
        heapq.heappush(heap, (a.w + b.w, seq, parent))
        seq += 1
    lens = [0] * n

    def walk(node, depth):
        if node.sym is not None:
            lens[node.sym] = depth
        else:
            if node.left:
                walk(node.left, depth + 1)
            if node.right:
                walk(node.right, depth + 1)
    walk(heap[0][2], 0)
    if max(lens) <= max_len:
        return lens
    # Flat fallback: every used symbol at length L, padded to a complete code.
    k = sum(1 for f in freqs if f > 0)
    L = 0
    while (1 << L) < k:
        L += 1
    lens = [0] * n
    for i, f in enumerate(freqs):
        if f > 0:
            lens[i] = L
    need = (1 << L) - k
    unused = [i for i in range(n) if lens[i] == 0]
    if need > len(unused):
        raise ValueError('cannot build a complete flat code (%d symbols)'
                         % k)
    for i in unused[:need]:
        lens[i] = L
    return lens


# ---------------------------------------------------------------------- LZX
LZX_MIN_MATCH_LEN = 2
LZX_NUM_PRIMARY_LENS = 7
LZX_WINDOW_SIZE = 1 << 15          # WOF LZX always uses a 32 KiB window
LZX_BLOCKTYPE_VERBATIM = 1
LZX_BLOCKTYPE_ALIGNED = 2
LZX_BLOCKTYPE_UNCOMPRESSED = 3
LZX_WIM_MAGIC_FILESIZE = 12000000
LZX_NUM_MAIN_SYMS = 496            # 256 + 8 * 30 for the 32 KiB window
LZX_NUM_LEN_SYMS = 249
LZX_MAX_OFFSET_SLOT = 30           # only slots 0..29 are used for WOF

# From lzx_common.c (wimlib / ntfs-3g-system-compression): 51 entries, the
# last one being the sentinel base for the slot search.
LZX_OFFSET_SLOT_BASE = [
    -2, -1, 0, 1, 2, 4, 6, 10, 14, 22, 30, 46, 62, 94, 126,
    190, 254, 382, 510, 766, 1022, 1534, 2046, 3070, 4094,
    6142, 8190, 12286, 16382, 24574, 32766, 49150, 65534,
    98302, 131070, 196606, 262142, 393214, 524286, 655358,
    786430, 917502, 1048574, 1179646, 1310718, 1441790,
    1572862, 1703934, 1835006, 1966078, 2097150]

# From lzx_common.c: 50 entries, one per used slot; extra bits cap at 17
# (slots 36..49 all use 17 extra bits).
LZX_EXTRA_OFFSET_BITS = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17]


def lzx_offset_slot(offset):
    for s in range(3, LZX_MAX_OFFSET_SLOT):
        if offset < LZX_OFFSET_SLOT_BASE[s + 1]:
            return s
    raise ValueError('offset too large: %d' % offset)


def e8_do_translate(data, target_off, input_pos):
    """do_translate_target() from lzx_common.c: only rel offsets within
    [-input_pos, 12000000) are translated; targets near the magic size use
    the compensating subtraction."""
    rel = struct.unpack_from('<i', data, target_off)[0]
    if rel >= -input_pos and rel < LZX_WIM_MAGIC_FILESIZE:
        if rel < LZX_WIM_MAGIC_FILESIZE - input_pos:
            abs_off = rel + input_pos
        else:
            abs_off = rel - LZX_WIM_MAGIC_FILESIZE
        struct.pack_into('<i', data, target_off, abs_off)


def lzx_e8_preprocess(data):
    """The E8 filter, translate direction.  Mirrors lzx_e8_filter() with
    do_translate_target(): 0xE8 bytes in the last 6 bytes are never
    processed, and after a translation the scan continues 5 bytes later
    (an instruction's target cannot itself be translated)."""
    n = len(data)
    if n <= 10:
        return data
    tail = n - 6
    p = data.find(b'\xe8')
    while p != -1:
        if p >= tail:
            break
        e8_do_translate(data, p + 1, p)
        p = data.find(b'\xe8', p + 5)
    return data


def _lzx_update_r(R, slot, offset):
    if slot < 3:
        R[slot] = R[0]
    else:
        R[2] = R[1]
        R[1] = R[0]
    R[0] = offset


def _lzx_parse(data):
    """Greedy parse into ('lit', byte) and ('match', length, offset, slot)
    items.  Runs (offset 1) and period-2 repeats (offset 2) are matched; the
    repeat offsets R0/R1/R2 are used when they already hold the offset."""
    n = len(data)
    R = [1, 1, 1]
    symbols = []
    i = 0
    while i < n:
        run = 1
        while i + run < n and data[i + run] == data[i]:
            run += 1
        if run >= 3 and i > 0 and data[i] == data[i - 1]:
            off = 1
            slot = None
            for s in range(3):
                if R[s] == off:
                    slot = s
                    break
            if slot is None:
                slot = 3
            left = run
            while left:
                L = min(left, 257)
                symbols.append(('match', L, off, slot))
                _lzx_update_r(R, slot, off)
                left -= L
            i += run
            continue
        if i + 1 < n and i >= 2 and data[i] == data[i - 2] and \
                data[i + 1] == data[i - 1]:
            off = 2
            L = 2
            while i + L < n and data[i + L] == data[i + L - 2]:
                L += 1
            slot = None
            for s in range(3):
                if R[s] == off:
                    slot = s
                    break
            if slot is None:
                slot = lzx_offset_slot(off)
            symbols.append(('match', min(L, 257), off, slot))
            _lzx_update_r(R, slot, off)
            i += min(L, 257)
            continue
        symbols.append(('lit', data[i]))
        i += 1
    return symbols


def _lzx_trees(symbols, block_type):
    """Frequency-driven code lengths for the main, length and aligned trees
    implied by `symbols`."""
    main_freq = [0] * LZX_NUM_MAIN_SYMS
    len_freq = [0] * LZX_NUM_LEN_SYMS
    aligned_freq = [0] * 8
    for item in symbols:
        if item[0] == 'lit':
            main_freq[item[1]] += 1
        else:
            length, offset, slot = item[1], item[2], item[3]
            hdr = min(length - LZX_MIN_MATCH_LEN, LZX_NUM_PRIMARY_LENS)
            main_freq[256 + slot * 8 + hdr] += 1
            if hdr == LZX_NUM_PRIMARY_LENS:
                len_freq[length - 2 - LZX_NUM_PRIMARY_LENS] += 1
            if block_type == LZX_BLOCKTYPE_ALIGNED and slot >= 8:
                aligned_freq[(offset - LZX_OFFSET_SLOT_BASE[slot]) & 7] += 1
    main_lens = huffman_lengths(main_freq, 16)
    len_lens = huffman_lengths(len_freq, 16)
    aligned_lens = []
    if block_type == LZX_BLOCKTYPE_ALIGNED:
        aligned_lens = huffman_lengths(aligned_freq, 7)
    return main_lens, len_lens, aligned_lens


def _lzx_precode_items(lengths, prev_lens):
    """Simulates the precode item stream for `lengths`, whose delta base at
    each position is the previous block's length there (`prev_lens`).  Items
    are (presym,) or (presym, extra_bits) or (presym, extra_bits, delta).
    The run forms (presym 17/18 for zeroes, 19 for identical lengths) match
    lzx_compute_precode_items() in wimlib; leftover run positions fall back
    to single deltas exactly as the reference encoder does."""
    items = []
    i = 0
    n = len(lengths)
    while i < n:
        l = lengths[i]
        run_end = i + 1
        while run_end < n and lengths[run_end] == l:
            run_end += 1
        if run_end == i + 1:
            items.append(((prev_lens[i] - l) % 17,))
            i += 1
            continue
        if l == 0:
            while run_end - i >= 20:
                extra = min((run_end - i) - 20, 31)
                items.append((18, extra))
                i += 20 + extra
            if run_end - i >= 4:
                extra = min((run_end - i) - 4, 15)
                items.append((17, extra))
                i += 4 + extra
        else:
            while run_end - i >= 4:
                extra = (run_end - i) > 4
                delta = (prev_lens[i] - l) % 17
                items.append((19, extra, delta))
                i += 4 + extra
        while i < run_end:
            items.append(((prev_lens[i] - l) % 17,))
            i += 1
    return items


def _lzx_write_lengths(bw, items, pre_codes):
    """Writes a precode item stream produced by `_lzx_precode_items`."""
    for item in items:
        sym = item[0]
        if sym < 17:
            code, L = pre_codes[sym]
            bw.write_bits(code, L)
        elif sym == 17:
            code, L = pre_codes[17]
            bw.write_bits(code, L)
            bw.write_bits(item[1], 4)
        elif sym == 18:
            code, L = pre_codes[18]
            bw.write_bits(code, L)
            bw.write_bits(item[1], 5)
        else:
            code, L = pre_codes[19]
            bw.write_bits(code, L)
            bw.write_bits(item[1], 1)
            code, L = pre_codes[item[2]]
            bw.write_bits(code, L)


def _lzx_write_block(bw, block_type, block_size, main_lens, len_lens,
                     aligned_lens, symbols, prev_main, prev_len):
    """Writes one LZX block: header, precode, the three codeword-length
    tables, then the symbol stream.  The precode frequencies come from the
    actual item stream (deltas and run symbols), exactly as wimlib builds
    them, so every emitted precode symbol has a real codeword."""
    items1 = _lzx_precode_items(main_lens[:256], prev_main[:256])
    items2 = _lzx_precode_items(main_lens[256:], prev_main[256:])
    items3 = _lzx_precode_items(len_lens, prev_len)
    main_codes = canonical_codes(main_lens)
    len_codes = canonical_codes(len_lens)
    aligned_codes = []
    if block_type == LZX_BLOCKTYPE_ALIGNED:
        aligned_codes = canonical_codes(aligned_lens)

    def pre_freqs(items):
        freq = [0] * 20
        for item in items:
            freq[item[0]] += 1
        return freq

    # Each codeword-length section carries its own precode, built from the
    # frequencies of that section's item stream (the reference encoder
    # writes each section independently).
    precodes = [canonical_codes(huffman_lengths(pre_freqs(items), 15))
                for items in (items1, items2, items3)]

    bw.write_bits(block_type, 3)
    if block_size == LZX_WINDOW_SIZE:
        bw.write_bits(1, 1)
    else:
        bw.write_bits(0, 1)
        bw.write_bits(block_size, 16)
    if block_type == LZX_BLOCKTYPE_ALIGNED:
        for l in aligned_lens:
            bw.write_bits(l, 3)
    for items, pre_codes in ((items1, precodes[0]),
                             (items2, precodes[1]),
                             (items3, precodes[2])):
        pre_lens = huffman_lengths(pre_freqs(items), 15)
        for l in pre_lens:
            bw.write_bits(l, 4)
        _lzx_write_lengths(bw, items, pre_codes)

    for item in symbols:
        if item[0] == 'lit':
            code, L = main_codes[item[1]]
            bw.write_bits(code, L)
        else:
            length, offset, slot = item[1], item[2], item[3]
            hdr = length - LZX_MIN_MATCH_LEN
            len_sym = None
            if hdr >= LZX_NUM_PRIMARY_LENS:
                hdr = LZX_NUM_PRIMARY_LENS
                len_sym = length - 2 - LZX_NUM_PRIMARY_LENS
            code, L = main_codes[256 + slot * 8 + hdr]
            bw.write_bits(code, L)
            if len_sym is not None:
                code, L = len_codes[len_sym]
                bw.write_bits(code, L)
            if slot >= 3:
                extra = offset - LZX_OFFSET_SLOT_BASE[slot]
                if block_type == LZX_BLOCKTYPE_ALIGNED and slot >= 8:
                    bw.write_bits(extra >> 3, LZX_EXTRA_OFFSET_BITS[slot] - 3)
                    acode, aL = aligned_codes[extra & 7]
                    bw.write_bits(acode, aL)
                else:
                    bw.write_bits(extra, LZX_EXTRA_OFFSET_BITS[slot])


def lzx_encode_blocks(blocks):
    """Encodes a list of (block_type, block_size, symbols) blocks into a
    single LZX chunk stream, tracking the previous block's codeword lengths
    for the delta encoding across blocks (for selftest vectors)."""
    bw = UnitBitWriter()
    prev_main = [0] * LZX_NUM_MAIN_SYMS
    prev_len = [0] * LZX_NUM_LEN_SYMS
    for block_type, block_size, symbols in blocks:
        main_lens, len_lens, aligned_lens = _lzx_trees(symbols, block_type)
        _lzx_write_block(bw, block_type, block_size, main_lens, len_lens,
                         aligned_lens, symbols, prev_main, prev_len)
        prev_main = main_lens
        prev_len = len_lens
    return bw.finish()


def lzx_encode_symbols(symbols, block_size, block_type=LZX_BLOCKTYPE_VERBATIM):
    """Encodes an explicit symbol list into a single LZX block (no E8
    preprocessing, no chunking) — used for the selftest vectors."""
    return lzx_encode_blocks([(block_type, block_size, symbols)])


def _lzx_encode_chunk(data, block_type=LZX_BLOCKTYPE_VERBATIM):
    n = len(data)
    if n == 0:
        return b''
    data = lzx_e8_preprocess(bytearray(data))
    symbols = _lzx_parse(bytes(data))
    return lzx_encode_symbols(symbols, n, block_type)


def lzx_encode(data, chunk_size=32768):
    """Encode `data` as independent LZX chunks of `chunk_size` (the WOF
    chunk size for the LZX format is 32768).  E8 preprocessing is applied
    per chunk, exactly as the WIM/WOF format requires.  Returns the
    compressed bytes with no chunk framing."""
    out = bytearray()
    for base in range(0, len(data), chunk_size):
        out += _lzx_encode_chunk(bytes(data[base:base + chunk_size]))
    return bytes(out)


# -------------------------------------------------------------------- XPRESS
XPRESS_MIN_MATCH_LEN = 3


def _xpress_parse(data):
    """Greedy parse into ('lit', byte) and ('match', length, offset) items.
    Runs (offset 1) and period-2 repeats (offset 2) are matched."""
    n = len(data)
    symbols = []
    i = 0
    while i < n:
        run = 1
        while i + run < n and data[i + run] == data[i]:
            run += 1
        if run >= 3 and i > 0 and data[i] == data[i - 1]:
            left = run
            while left >= 3:
                L = min(left, 21)          # 3..21: exercises the extended byte
                symbols.append(('match', L, 1))
                left -= L
            i += run - left                # tail < 3 bytes: emit literals
            while left:
                symbols.append(('lit', data[i]))
                i += 1
                left -= 1
            continue
        if i + 2 < n and i >= 2 and data[i] == data[i - 2] and \
                data[i + 1] == data[i - 1]:
            L = 2
            while i + L < n and data[i + L] == data[i + L - 2]:
                L += 1
            if L >= 3:
                symbols.append(('match', min(L, 21), 2))
                i += min(L, 21)
                continue
        symbols.append(('lit', data[i]))
        i += 1
    return symbols


def _xpress_encode_chunk(data):
    n = len(data)
    if n == 0:
        return b''
    symbols = _xpress_parse(data)
    freq = [0] * 512
    freq[256] += 1                       # end-of-data marker (MS compatibility)
    for item in symbols:
        if item[0] == 'lit':
            freq[item[1]] += 1
        else:
            length, off = item[1], item[2]
            log2 = 0
            while (1 << log2) < off:
                log2 += 1
            freq[256 + (log2 << 4) + min(length - 3, 0xF)] += 1
    lens = huffman_lengths(freq, 15)
    codes = canonical_codes(lens)

    bw = UnitBitWriter()
    table = bytearray()
    for i in range(0, 512, 2):           # length table: 256 bytes of nibbles
        table.append((lens[i + 1] << 4) | lens[i])
    for item in symbols:
        if item[0] == 'lit':
            code, L = codes[item[1]]
            bw.write_bits(code, L)
        else:
            length, off = item[1], item[2]
            log2 = 0
            while (1 << log2) < off:
                log2 += 1
            adj = length - XPRESS_MIN_MATCH_LEN
            sym = 256 + (log2 << 4) + min(adj, 0xF)
            code, L = codes[sym]
            bw.write_bits(code, L)
            if adj >= 0xF:
                bw.write_byte(min(adj - 0xF, 0xFF))
                if adj - 0xF >= 0xFF:
                    bw.write_u16(adj)
            bw.write_bits(off - (1 << log2), log2)
    code, L = codes[256]                 # end-of-data symbol
    bw.write_bits(code, L)
    return bytes(table) + bw.finish()


def xpress_encode(data, chunk_size=4096):
    """Encode `data` as independent XPRESS LZ77+Huffman chunks (the WOF
    chunk sizes are 4096/8192/16384).  Returns the compressed bytes, with
    no chunk framing."""
    out = bytearray()
    for base in range(0, len(data), chunk_size):
        out += _xpress_encode_chunk(bytes(data[base:base + chunk_size]))
    return bytes(out)


# -------------------------------------------------------------------- WOF
def wof_compress(data, compression_format, chunk_size):
    """Builds a complete WofCompressedData stream: a table of
    (num_chunks - 1) u32 offsets (each relative to the end of the table)
    followed by the compressed chunks.  Chunks that do not compress to less
    than their original size are stored uncompressed."""
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    chunks_enc = []
    for chunk in chunks:
        if compression_format == 1:
            c = _lzx_encode_chunk(bytes(chunk))
        else:
            c = _xpress_encode_chunk(bytes(chunk))
        if len(c) >= len(chunk):
            c = bytes(chunk)
        chunks_enc.append(c)
    table = bytearray()
    pos = 0
    for c in chunks_enc[:-1]:
        pos += len(c)
        table += struct.pack('<I', pos)
    return bytes(table) + b''.join(chunks_enc)


# ------------------------------------------------------ deterministic corpus
def make_wof_corpus(lzx_bytes=49152, xpress_bytes=11008):
    """Deterministic synthetic file content for the WOF fixture files and
    selftest vectors.  Includes runs, period-2 repeats, varied text, and
    E8 bytes chosen to exercise both translation directions of the filter:
    a "compensating" translation (stored value near the magic size) and a
    "good" one (small positive absolute target)."""
    import random
    rnd = random.Random(0x574F46)
    text = bytearray()
    for i in range(0, lzx_bytes):
        m = i % 79
        if m < 12:
            text += bytes([0x41 + (i // 79) % 26])          # runs
        elif m < 24:
            text += bytes([0x61 + ((i // 7) % 26), 0x61 + ((i // 7 + 1) % 26)])
        elif m < 40:
            text += b'GHOST RECOVER-WOF-fixture-'
        else:
            text += bytes([rnd.randrange(32, 127)])
    text = bytes(text[:lzx_bytes])
    # Two E8 instructions with translated targets: the first uses the
    # compensating translation (rel near the magic size), the second a good
    # translation (small positive target).
    if lzx_bytes > 200:
        text = text[:100] + b'\xe8' + struct.pack('<i', 11999950) + text[105:]
    text = text[:150] + b'\xe8' + struct.pack('<i', 0x00001000) + text[155:]
    return text


def _main():
    data = make_wof_corpus()
    lzx = lzx_encode(data)
    xpress = xpress_encode(data[:11008])
    wof_lzx = wof_compress(data, 1, 32768)
    wof_xpress = wof_compress(data[:11008], 0, 4096)
    print('lzx: %d -> %d bytes (%.2f%%)' %
          (len(data), len(lzx), 100.0 * len(lzx) / len(data)))
    print('xpress: %d -> %d bytes (%.2f%%)' %
          (11008, len(xpress), 100.0 * len(xpress) / 11008))
    print('wof-lzx stream: %d bytes' % len(wof_lzx))
    print('wof-xpress stream: %d bytes' % len(wof_xpress))
    return 0


if __name__ == '__main__':
    sys.exit(_main())
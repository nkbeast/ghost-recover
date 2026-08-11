#!/usr/bin/env python3
"""Reference decoders for the WOF system-compression codecs.

These mirror, byte-for-byte, the semantics of the reference implementations
in ntfs-3g-system-compression and wimlib (the decoders in
src/decompress_common.c, src/xpress_decompress.c and src/lzx_decompress.c):

  * 16-bit little-endian coding units consumed MSB-first within each unit;
  * canonical Huffman codes that must be complete (an all-zero, empty code
    is permitted and decodes as symbol 0 without consuming bits);
  * XPRESS: 256-byte nibble length table, interleaved raw bytes for extended
    match lengths, end-of-data symbol 256 which is ignored;
  * LZX: per-chunk state (codeword lengths zeroed, recent offsets {1,1,1}),
    blocks of type verbatim/aligned/uncompressed, codeword lengths stored as
    deltas from the previous block (per position), E8 postprocessing with
    the fixed WIM magic size 12000000.

The encoders in wof_encoding.py are validated against these decoders before
the C++ decoders in src/core/decompress.cpp are written; the C++ decoders
then get independent selftest vectors produced by the same encoders.
"""

import math
import struct

import wof_encoding as enc

LZX_NUM_MAIN_SYMS = 256 + 8 * 30
LZX_PRECODE_NUM_SYMS = 20
LZX_PRECODE_MAX_LEN = 15
LZX_ALIGNED_MAX_LEN = 7
LZX_MAX_LEN = 16

XPRESS_MAX_LEN = 15


# ------------------------------------------------------------- bit streams
class BitReader:
    """Reads a bit stream of 16-bit little-endian coding units, MSB-first
    within each unit.  `ensure_bits` refills two bytes at a time when
    `bitsleft < n`; missing bytes are read as zeroes and bitsleft is forced
    to 32.  The raw `read_byte` / `read_u16` / `read_u32` calls advance the
    byte pointer directly, interleaved with the coding units exactly like
    the reference implementation."""

    __slots__ = ('buf', 'pos', 'bitbuf', 'bitsleft')

    def __init__(self, buf):
        self.buf = buf
        self.pos = 0
        self.bitbuf = 0
        self.bitsleft = 0

    def ensure_bits(self, n):
        while self.bitsleft < n:
            b1 = self.buf[self.pos] if self.pos < len(self.buf) else 0
            b0 = self.buf[self.pos + 1] if self.pos + 1 < len(self.buf) else 0
            self.pos += 2
            self.bitbuf |= ((b0 << 8) | b1) << (16 - self.bitsleft)
            self.bitsleft = 32 if self.pos > len(self.buf) else \
                self.bitsleft + 16

    def pop_bits(self, n):
        self.ensure_bits(n)
        bits = 0
        if n:
            bits = (self.bitbuf >> (32 - n)) & ((1 << n) - 1)
        self.bitbuf <<= n
        self.bitsleft -= n
        return bits

    def peek_bits(self, n):
        if n == 0:
            return 0
        return (self.bitbuf >> (32 - n)) & ((1 << n) - 1)

    def align(self):
        self.bitbuf = 0
        self.bitsleft = 0

    def read_byte(self):
        if self.pos < len(self.buf):
            b = self.buf[self.pos]
            self.pos += 1
            return b
        return 0

    def read_u16(self):
        b1 = self.buf[self.pos] if self.pos < len(self.buf) else 0
        b0 = self.buf[self.pos + 1] if self.pos + 1 < len(self.buf) else 0
        self.pos += 2
        return (b0 << 8) | b1

    def read_u32(self):
        v = 0
        for i in range(4):
            v |= self.read_byte() << (8 * i)
        return v


# ------------------------------------------------------------- huffman code
def build_huff(lengths, max_len):
    """Build a full decode table (2**max_len entries) for a canonical code.
    Entry value is sym + 1 (0 means "empty code", which decodes as symbol 0
    without consuming bits).  Raises ValueError for incomplete or overfull
    nonempty codes, exactly like the reference make_huffman_decode_table."""
    num_syms = len(lengths)
    counts = [0] * (max_len + 1)
    for L in lengths:
        counts[L] += 1
    remainder = 1
    for L in range(1, max_len + 1):
        remainder = (remainder << 1) - counts[L]
        if remainder < 0:
            raise ValueError('overfull code')
    if remainder != 0:
        if remainder != 1 << max_len:
            raise ValueError('incomplete code')
        return [0] * (1 << max_len)
    table = [0] * (1 << max_len)
    code = 0
    prev = 0
    for L in range(1, max_len + 1):
        code <<= L - prev
        for sym in range(num_syms):
            if lengths[sym] == L:
                span = 1 << (max_len - L)
                base = code << (max_len - L)
                for k in range(span):
                    table[base + k] = sym + 1
                code += 1
        prev = L
    return table


def read_huff(br, table, lens, max_len):
    """Decode one symbol with the full-table code built by build_huff."""
    br.ensure_bits(max_len)
    entry = table[br.peek_bits(max_len)]
    if entry == 0:
        return 0
    sym = entry - 1
    br.pop_bits(lens[sym])
    return sym


# ------------------------------------------------------------------ XPRESS
def xpress_decode(data, uncompressed_size):
    br = BitReader(data)
    lens = []
    for i in range(0, 512, 2):
        b = br.read_byte()
        lens.append(b & 0xF)
        lens.append(b >> 4)
    table = build_huff(lens, XPRESS_MAX_LEN)
    out = bytearray()
    while len(out) < uncompressed_size:
        sym = read_huff(br, table, lens, XPRESS_MAX_LEN)
        if sym < 256:
            out.append(sym)
        else:
            length = sym & 0xF
            log2_offset = (sym >> 4) & 0xF
            br.ensure_bits(16)
            offset = (1 << log2_offset) | br.pop_bits(log2_offset)
            if length == 0xF:
                length += br.read_byte()
                if length == 0xF + 0xFF:
                    length = br.read_u16()
            length += enc.XPRESS_MIN_MATCH_LEN
            if offset > len(out) or length > uncompressed_size - len(out):
                raise ValueError('bad match (off %d len %d at %d)'
                                 % (offset, length, len(out)))
            src = len(out) - offset
            for _ in range(length):
                out.append(out[src])
                src += 1
    return bytes(out)


# ---------------------------------------------------------------------- LZX
def _read_lens(br, lens, num):
    """Reads a precode (20 explicitly stored 4-bit lengths) and uses it to
    delta-decode `num` codeword lengths; the base at each position is the
    value already stored there (the previous block's length).  Run overruns
    past the end are permitted (the reference allows up to 50); here they are
    simply truncated."""
    pre_lens = [br.pop_bits(4) for _ in range(LZX_PRECODE_NUM_SYMS)]
    pre_table = build_huff(pre_lens, LZX_PRECODE_MAX_LEN)
    i = 0
    while i < num:
        presym = read_huff(br, pre_table, pre_lens, LZX_PRECODE_MAX_LEN)
        if presym < 17:
            lens[i] = (lens[i] - presym) % 17
            i += 1
        elif presym == 17:
            run = 4 + br.pop_bits(4)
            for _ in range(run):
                if i >= num:
                    return
                lens[i] = 0
                i += 1
        elif presym == 18:
            run = 20 + br.pop_bits(5)
            for _ in range(run):
                if i >= num:
                    return
                lens[i] = 0
                i += 1
        else:
            run = 4 + br.pop_bits(1)
            presym = read_huff(br, pre_table, pre_lens, LZX_PRECODE_MAX_LEN)
            if presym > 17:
                raise ValueError('presym 19 delta > 17')
            for _ in range(run):
                if i >= num:
                    return
                lens[i] = (lens[i] - presym) % 17
                i += 1


def _e8_undo(data):
    n = len(data)
    if n <= 10:
        return
    tail = n - 6
    p = data.find(b'\xe8')
    while p != -1:
        if p >= tail:
            break
        abs_off = struct.unpack_from('<i', data, p + 1)[0]
        if abs_off >= 0:
            if abs_off < enc.LZX_WIM_MAGIC_FILESIZE:
                struct.pack_into('<i', data, p + 1, abs_off - p)
        else:
            if abs_off >= -p:
                struct.pack_into('<i', data, p + 1,
                                 abs_off + enc.LZX_WIM_MAGIC_FILESIZE)
        p = data.find(b'\xe8', p + 5)


def lzx_decode_chunk(data, uncompressed_size):
    br = BitReader(data)
    maincode_lens = [0] * LZX_NUM_MAIN_SYMS
    lencode_lens = [0] * 249
    recent_offsets = [1, 1, 1]
    may_have_e8 = 0
    out = bytearray()

    while len(out) < uncompressed_size:
        block_type = br.pop_bits(3)
        if br.pop_bits(1):
            block_size = enc.LZX_WINDOW_SIZE
        else:
            block_size = br.pop_bits(16)
        if block_size < 1 or block_size > uncompressed_size - len(out):
            raise ValueError('bad block size %d' % block_size)

        if block_type == enc.LZX_BLOCKTYPE_UNCOMPRESSED:
            br.align()
            recent_offsets[0] = br.read_u32()
            recent_offsets[1] = br.read_u32()
            recent_offsets[2] = br.read_u32()
            if 0 in recent_offsets:
                raise ValueError('zero recent offset')
            for _ in range(block_size):
                out.append(br.read_byte())
            if block_size & 1:
                br.read_byte()
            may_have_e8 = 1
            continue

        aligned_lens = None
        if block_type == enc.LZX_BLOCKTYPE_ALIGNED:
            aligned_lens = [br.pop_bits(3) for _ in range(8)]
        elif block_type != enc.LZX_BLOCKTYPE_VERBATIM:
            raise ValueError('bad block type %d' % block_type)

        # Each codeword-length section is preceded by its own precode.
        _read_lens(br, maincode_lens, 256)
        second_half = [0] * (LZX_NUM_MAIN_SYMS - 256)
        _read_lens(br, second_half, LZX_NUM_MAIN_SYMS - 256)
        maincode_lens[256:] = second_half
        _read_lens(br, lencode_lens, 249)

        main_table = build_huff(maincode_lens, LZX_MAX_LEN)
        len_table = build_huff(lencode_lens, LZX_MAX_LEN)
        if block_type == enc.LZX_BLOCKTYPE_ALIGNED:
            aligned_table = build_huff(aligned_lens, LZX_ALIGNED_MAX_LEN)
            extra_bits = list(enc.LZX_EXTRA_OFFSET_BITS)
            for s in range(8, 30):
                extra_bits[s] -= 3
            min_aligned_slot = 8
        else:
            aligned_table = None
            extra_bits = enc.LZX_EXTRA_OFFSET_BITS
            min_aligned_slot = 30

        block_end = len(out) + block_size
        while len(out) < block_end:
            mainsym = read_huff(br, main_table, maincode_lens, LZX_MAX_LEN)
            if mainsym < 256:
                out.append(mainsym)
                continue
            length = mainsym % 8
            offset_slot = (mainsym - 256) // 8
            if length == 7:
                length += read_huff(br, len_table, lencode_lens, LZX_MAX_LEN)
            length += enc.LZX_MIN_MATCH_LEN
            if offset_slot < 3:
                offset = recent_offsets[offset_slot]
                recent_offsets[offset_slot] = recent_offsets[0]
            else:
                offset = br.pop_bits(extra_bits[offset_slot])
                if aligned_table is not None and offset_slot >= min_aligned_slot:
                    offset = (offset << 3) | \
                        read_huff(br, aligned_table, aligned_lens,
                                  LZX_ALIGNED_MAX_LEN)
                offset += enc.LZX_OFFSET_SLOT_BASE[offset_slot]
                recent_offsets[2] = recent_offsets[1]
                recent_offsets[1] = recent_offsets[0]
            recent_offsets[0] = offset
            if offset > len(out) or length > block_end - len(out):
                raise ValueError('bad match (off %d len %d at %d)'
                                 % (offset, length, len(out)))
            src = len(out) - offset
            for _ in range(length):
                out.append(out[src])
                src += 1
        may_have_e8 |= maincode_lens[0xE8]

    if may_have_e8:
        _e8_undo(out)
    return bytes(out)


# ------------------------------------------------------------ WOF framing
def wof_split(stream, uncompressed_size, chunk_size):
    """Splits a WofCompressedData stream into its compressed chunks using
    the chunk table: (num_chunks - 1) u32 offsets, each relative to the end
    of the table; chunk 0 starts right after the table, the last chunk ends
    at the end of the stream."""
    num_chunks = math.ceil(uncompressed_size / chunk_size)
    if num_chunks <= 1:
        return [stream]
    table_entries = num_chunks - 1
    table_end = table_entries * 4
    offs = [struct.unpack_from('<I', stream, 4 * i)[0]
            for i in range(table_entries)]
    chunks = []
    prev = 0
    for off in offs:
        chunks.append(stream[table_end + prev:table_end + off])
        prev = off
    chunks.append(stream[table_end + prev:])
    return chunks


def wof_decode(stream, compression_format, uncompressed_size, chunk_size):
    out = bytearray()
    for i, chunk in enumerate(wof_split(stream, uncompressed_size,
                                        chunk_size)):
        size = min(chunk_size, uncompressed_size - i * chunk_size)
        if len(chunk) >= size:
            out += chunk                   # stored uncompressed
            continue
        if compression_format == 1:
            out += lzx_decode_chunk(chunk, size)
        else:
            out += xpress_decode(chunk, size)
    return bytes(out)


# ------------------------------------------------------------------- tests
def test_wof(compression_format, chunk_size, size):
    data = enc.make_wof_corpus()[:size]
    stream = enc.wof_compress(data, compression_format, chunk_size)
    dec = wof_decode(stream, compression_format, len(data), chunk_size)
    assert dec == data, \
        'round-trip failed (format %d chunk %d size %d)' % \
        (compression_format, chunk_size, size)


def test_lzx_multi_block():
    # Two verbatim blocks in one chunk with different codes: the second
    # block's codeword lengths are deltas from the first block's, so this
    # exercises the prev_lens tracking in the encoder.
    data = bytes(range(256)) * 64
    symbols1 = enc._lzx_parse(bytes(data[:4000]))
    symbols2 = enc._lzx_parse(bytes(data[4000:]))
    stream = enc.lzx_encode_blocks([
        (enc.LZX_BLOCKTYPE_VERBATIM, 4000, symbols1),
        (enc.LZX_BLOCKTYPE_VERBATIM, 4000, symbols2),
    ])
    dec = lzx_decode_chunk(stream, 8000)
    assert dec == data[:8000], 'multi-block round-trip failed'


def test_lzx_aligned():
    # An aligned block with an explicit offset in slot >= 8 (offset 15 ->
    # slot 8, base 14, 1 extra bit + 3 aligned bits), exercising the aligned
    # tree.  After the 21 literals the match copies out[6:14] == b'world he'.
    symbols = []
    symbols += [('lit', b) for b in b'hello world hello wor']
    symbols += [('match', 8, 15, 8)]           # offset 15: slot 8
    symbols += [('lit', b) for b in b'!']
    stream = enc.lzx_encode_symbols(symbols, 30,
                                    enc.LZX_BLOCKTYPE_ALIGNED)
    dec = lzx_decode_chunk(stream, 30)
    assert dec == b'hello world hello worworld he!', \
        'aligned round-trip failed'


def test_xpress_extended():
    # A match of length 21 exercises the interleaved extended-length byte
    # (len 21 -> adjusted 18 -> one extra byte).
    data = b'ABCD' + b'X' * 21 + b'YZ'
    stream = enc.xpress_encode(data, 4096)
    dec = xpress_decode(stream, len(data))
    assert dec == data, 'xpress extended round-trip failed'


def _main():
    test_wof(0, 4096, 11008)               # XPRESS4K, 3 chunks
    test_wof(0, 8192, 25000)               # XPRESS8K, 4 chunks
    test_wof(0, 16384, 40000)              # XPRESS16K, 3 chunks
    test_wof(1, 32768, 49152)              # LZX, 2 chunks
    test_wof(1, 32768, 32768)              # LZX, exactly one chunk
    test_wof(1, 32768, 65536)              # LZX, 2 full chunks
    test_lzx_multi_block()
    test_lzx_aligned()
    test_xpress_extended()
    print('all round-trips OK')
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_main())

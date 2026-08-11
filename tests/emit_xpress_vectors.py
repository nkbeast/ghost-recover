#!/usr/bin/env python3
"""Emit C vector literals for the xpress selftest from xpress_fixture.py."""

import sys

sys.path.insert(0, 'tests')
import xpress_fixture as xf


def cstr(b):
    return ''.join('\\x%02x' % c for c in b)


plains = [
    b'GHOST//RECOVER data recovery engine.\n',
    b'abc' * 100,
    b'P' * 40,
    b'A' * 700,
    b'Q' * 4000,
    b'abcdefghij' * 30,
    b'abcdefghij' * 3 + b'!' + b'abcdefghij' * 3,
    bytes((i * 7 + 3) % 251 for i in range(9000)),
]
huffs = [
    b'The quick brown fox jumps over the lazy dog. ' * 8,
    b'abcdabcdabcdabcd' * 600,
    b'z' * 3000,
    bytes(((i * 13 + 5) % 253) for i in range(20000)),
    b'x' * 65536,
    b'x' * 21,
    b'abcdefghijklmnopqrst' * 2,
]

print('// Plain LZ77 vectors (independent encoder, tests/xpress_fixture.py)')
for i, d in enumerate(plains):
    enc = xf.PlainLz77Encoder(d).encode()
    print('  {%d, %d, "%s", ""},' % (len(d), len(enc), cstr(enc)))
print('// LZ77+Huffman vectors (independent encoder, tests/xpress_fixture.py)')
for i, d in enumerate(huffs):
    enc = xf.HuffmanEncoder(d).encode()
    print('  {%d, %d, "%s", ""},' % (len(d), len(enc), cstr(enc)))
print('// MS-XCA 3.1 authoritative anchor')
anc = xf.anchor_block()
print('  {%d, %d, "%s", "abcabcabc"},' % (300, len(anc), cstr(anc)))

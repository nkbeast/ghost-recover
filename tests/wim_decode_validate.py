#!/usr/bin/env python3
"""Validate the reference WOF decoders against real WIM files.

A WIM produced by wimlib-imagex or Windows WIMGAPI stores each file as an
independently compressed resource in exactly the same LZX/XPRESS formats used
by WOF-compressed files on NTFS.  We parse the WIM, decode every compressed
resource with wof_decode_ref, and check the SHA-1 of the result against the
hash stored in the WIM blob table.  This is the ground-truth test that the
decoders handle real-world streams, not just our own encoder's output.

Usage: python3 tests/wim_decode_validate.py <file.wim> [<file.wim> ...]
"""

import hashlib
import struct
import sys

sys.path.insert(0, 'tests')

import wof_decode_ref as ref  # noqa: E402
import wof_encoding as enc    # noqa: E402

WIM_HEADER_SIZE = 208
WIM_RESOURCE_ENTRY_SIZE = 50
WIM_RESHDR_FLAG_COMPRESSED = 0x04
WIM_RESHDR_FLAG_METADATA = 0x02

WIM_HDR_FLAG_COMPRESS_XPRESS = 0x00020000
WIM_HDR_FLAG_COMPRESS_LZX = 0x00040000


def parse_wim_header(data):
    if data[:8] != b'MSWIM\0\0\0':
        raise ValueError('not a WIM file (bad magic)')
    hdr_size, version = struct.unpack_from('<II', data, 8)
    if hdr_size != WIM_HEADER_SIZE:
        raise ValueError('unsupported header size %d' % hdr_size)
    wim_flags = struct.unpack_from('<I', data, 0x10)[0]
    chunk_size = struct.unpack_from('<I', data, 0x14)[0]
    if wim_flags & WIM_HDR_FLAG_COMPRESS_LZX:
        ctype = 'LZX'
    elif wim_flags & WIM_HDR_FLAG_COMPRESS_XPRESS:
        ctype = 'XPRESS'
    else:
        ctype = 'NONE'

    def reshdr(off):
        size_in_wim = int.from_bytes(data[off:off + 7], 'little')
        flags = data[off + 7]
        offset = struct.unpack_from('<Q', data, off + 8)[0]
        usize = struct.unpack_from('<Q', data, off + 16)[0]
        return size_in_wim, flags, offset, usize

    blob_table = reshdr(0x30)
    return ctype, chunk_size, blob_table, version


def read_blob_table(data, bt):
    size_in_wim, flags, offset, usize = bt
    if size_in_wim == 0:
        return []
    table = data[offset:offset + size_in_wim]
    if len(table) < size_in_wim:
        raise ValueError('truncated blob table')
    blobs = []
    for i in range(0, size_in_wim - WIM_RESOURCE_ENTRY_SIZE + 1,
                   WIM_RESOURCE_ENTRY_SIZE):
        e = table[i:i + WIM_RESOURCE_ENTRY_SIZE]
        size_in_wim = int.from_bytes(e[0:7], 'little')
        eflags = e[7]
        eoffset = struct.unpack_from('<Q', e, 8)[0]
        usize = struct.unpack_from('<Q', e, 16)[0]
        part_number = struct.unpack_from('<H', e, 24)[0]
        refcnt = struct.unpack_from('<I', e, 26)[0]
        sha1 = e[30:50]
        if size_in_wim == 0 and usize == 0 and refcnt == 0:
            break
        blobs.append({
            'size_in_wim': size_in_wim, 'flags': eflags,
            'offset': eoffset, 'uncompressed_size': usize,
            'part_number': part_number, 'refcnt': refcnt, 'sha1': sha1,
        })
    return blobs


def decode_wim_resource(data, blob, ctype, chunk_size):
    if not (blob['flags'] & WIM_RESHDR_FLAG_COMPRESSED):
        return data[blob['offset']:blob['offset'] + blob['uncompressed_size']]
    size_in_wim = blob['size_in_wim']
    usize = blob['uncompressed_size']
    start = blob['offset']
    resource = data[start:start + size_in_wim]
    num_chunks = (usize + chunk_size - 1) // chunk_size
    table_size = (num_chunks - 1) * 4
    out = bytearray()
    prev = 0
    pos = table_size
    for i in range(num_chunks):
        chunk_usize = min(chunk_size, usize - i * chunk_size)
        if i == num_chunks - 1:
            chunk_csize = size_in_wim - table_size - prev
        else:
            next_off = struct.unpack_from('<I', resource, i * 4)[0]
            chunk_csize = next_off - prev
            prev = next_off
        cbuf = resource[pos:pos + chunk_csize]
        pos += chunk_csize
        if len(cbuf) != chunk_csize:
            raise ValueError('chunk %d truncated' % i)
        if chunk_csize == chunk_usize:
            out += cbuf                       # stored uncompressed
            continue
        if ctype == 'LZX':
            out += ref.lzx_decode_chunk(bytes(cbuf), chunk_usize)
        else:
            out += ref.xpress_decode(bytes(cbuf), chunk_usize)
    return bytes(out)


def validate_wim(path):
    with open(path, 'rb') as f:
        data = f.read()
    ctype, chunk_size, bt, version = parse_wim_header(data)
    print('%-32s %s chunk=%d version=0x%x' %
          (path.split('/')[-1], ctype, chunk_size, version))
    blobs = read_blob_table(data, bt)
    print('  %d blobs' % len(blobs))
    n_checked = n_ok = n_fail = n_metadata = n_metadata_ok = 0
    for blob in blobs:
        decoded = decode_wim_resource(data, blob, ctype, chunk_size)
        digest = hashlib.sha1(decoded).digest()
        if blob['flags'] & WIM_RESHDR_FLAG_METADATA:
            n_metadata += 1
            tag = 'metadata'
        else:
            n_checked += 1
            tag = 'file'

        ok = digest == blob['sha1']
        if tag == 'file':
            n_ok += ok
        else:
            n_metadata_ok = ok
        if not ok:
            n_fail += 1
        print('  [%s] %-8s usize=%-9d csize=%-9d sha1 %s' %
              ('OK' if ok else 'FAIL', tag, blob['uncompressed_size'],
               blob['size_in_wim'], 'match' if ok else 'MISMATCH'))
    print('  => %d/%d resources verified%s' %
          (n_ok + (1 if n_metadata_ok else 0), n_checked + n_metadata,
           '' if n_fail == 0 else '  (%d FAILED)' % n_fail))
    return n_fail == 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    all_ok = True
    for wim in sys.argv[1:]:
        try:
            all_ok &= validate_wim(wim)
        except Exception as e:  # noqa: BLE001
            print('ERROR on %s: %s' % (wim, e))
            all_ok = False
    sys.exit(0 if all_ok else 1)

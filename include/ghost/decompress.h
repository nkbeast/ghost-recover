// GHOST//RECOVER — block decompression for filesystem codecs.
#pragma once

#include "ghost/types.h"

#include <string>
#include <vector>

namespace ghost {

// LZO1X raw stream decoder (instruction set from lzo1x_d.ch, LZO 2.10).
// Appends the decompressed bytes to `out`; returns true on success.
bool lzo1xDecode(const u8* in, size_t inLen, std::vector<u8>& out);

// Btrfs LZO framing (fs/btrfs/lzo.c): a LE32 total-size header followed by
// segments of [LE32 size, payload], with 1-3 zero pad bytes inserted when a
// segment header would cross a sector boundary. Each segment is raw LZO1X.
bool btrfsLzoDecode(const u8* in, size_t inLen, std::vector<u8>& out);

// zlib stream (btrfs zlib extents, squashfs-style zlib blocks).
bool zlibStreamDecode(const u8* in, size_t inLen, std::vector<u8>& out);

// Raw DEFLATE (no zlib wrapper), as Btrfs stores for zlib-compressed extents.
bool rawDeflateAll(const u8* in, size_t inLen, std::vector<u8>& out);

// Standard zstd frame (btrfs zstd extents). Empty result when the engine was
// built without zstd support.
std::vector<u8> zstdFrameDecode(const u8* in, size_t inLen);

// LZNT1 (NTFS compression, MS-XCA). A unit is a sequence of 4 KiB chunks,
// each with a 0x3000 (raw) or 0xB000 (compressed) header.
bool lznt1Decode(const u8* in, size_t inLen, std::vector<u8>& out);

// XPRESS plain LZ77 (MS-XCA 2.1.1): 32-bit flag groups (bit 31 first), LE16
// match words ((off-1) << 3) | (len-3), shared-nibble length bytes, optional
// 0xff/u16/u32 length extension. Decodes until the padded end-of-data marker.
bool xpressPlainDecode(const u8* in, size_t inLen, std::vector<u8>& out);

// XPRESS LZ77+Huffman (MS-XCA 2.1.2/2.1.4): 512-byte canonical-code table,
// then a bit stream of LE16 words (MSB first, 32-bit register, refill at
// < 15 bits), with any nibble-15 length extensions written raw after the bit
// region. `expectedOut` is required: the EOF symbol (256) is only emitted
// once the block is complete, so the decoder needs the uncompressed length.
bool xpressHuffmanDecode(const u8* in, size_t inLen, std::vector<u8>& out,
                         size_t expectedOut);

// Dispatches one independently compressed block on its codec id. `expectedOut`
// (when > 0) truncates the result to that length. Empty vector on failure.
std::vector<u8> decompressBlock(const std::string& codec, const u8* data,
                                size_t len, i64 expectedOut);

namespace selftest {
// Exercises every codec decoder against embedded, independently produced
// vectors. Returns 0 when everything passes, 1 otherwise.
int run();
}  // namespace selftest

}  // namespace ghost

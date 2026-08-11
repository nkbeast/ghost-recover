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

// GHOST//RECOVER — block decompression for filesystem codecs.
#pragma once

#include "ghost/types.h"

#include <string>
#include <vector>

namespace ghost {

// LZO1X raw stream decoder (instruction set from lzo1x_d.ch, LZO 2.10).
// Appends the decompressed bytes to `out`; returns true on success. `maxOut`
// (> 0) aborts once the output would grow past it.
bool lzo1xDecode(const u8* in, size_t inLen, std::vector<u8>& out,
                 i64 maxOut = 0);

// Btrfs LZO framing (fs/btrfs/lzo.c): a LE32 total-size header followed by
// segments of [LE32 size, payload], with 1-3 zero pad bytes inserted when a
// segment header would cross a sector boundary. Each segment is raw LZO1X.
// `sectorsize` is the filesystem's own sector size (default 4096); `maxOut`
// is passed through to the segment decoder.
bool btrfsLzoDecode(const u8* in, size_t inLen, std::vector<u8>& out,
                    u32 sectorsize = 4096, i64 maxOut = 0);

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
// (when > 0) truncates the result to that length. `sectorsize` (default 4096)
// is passed to the btrfs LZO frame decoder. Empty vector on failure.
std::vector<u8> decompressBlock(const std::string& codec, const u8* data,
                                size_t len, i64 expectedOut,
                                u32 sectorsize = 4096);

namespace selftest {
// Exercises every codec decoder against embedded, independently produced
// vectors. Returns 0 when everything passes, 1 otherwise.
int run();
}  // namespace selftest

}  // namespace ghost

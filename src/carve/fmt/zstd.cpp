// GHOST RECOVER — zstd signature family (one file per format).
//
// Part of the per-format split: every format family gets its own
// translation unit; shared plumbing (mk, withConfirm, cross-family
// validators) lives in sig_common.h / sig_common.cpp and the registry
// aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "../sig_common.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace ghost {

// Walks a zstd frame: frame header descriptor + optional window descriptor /
// FCS, then 3-byte block headers until the last block, optionally a 4-byte
// XXH64 content checksum. Returns the byte length or -1 if the frame is not
// valid (junk after the magic).
i64 vZstd(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    constexpr i64 kMaxFcs = i64(1) << 62;
    auto h = s.read(off, 16);
    if (h.size() < 5) return -1;
    const u8 fhd = h[4];
    if (fhd == 0) return -1;                        // empty FHD: reserved
    if (fhd & 0x10) return -1;                      // unused bit must be 0
    if ((fhd & 0x03) != 0) return -1;               // reserved bits must be 0
    const bool single = (fhd & 0x20) != 0;
    const bool checksum = (fhd & 0x04) != 0;
    const bool dict = (fhd & 0x08) != 0;
    const int fcsFlag = (fhd >> 6) & 0x03;
    i64 p = 5;
    if (!single) {
        if (p + 1 > max) return -1;
        const u8 wd = s.byte(off + p);
        const u32 exp = wd >> 3;
        if (exp > 31) return -1;
        const i64 win = i64(1) << exp;
        if (win > i64(1) << 43) return -1;
        p++;
    }
    i64 fcs = -1;
    const bool fcs1 = (fcsFlag == 0) && single && !dict;   // single-segment 1-byte FCS
    if (fcsFlag != 0 || fcs1) {
        const int bytes = fcsFlag == 0 ? 1 : fcsFlag == 1 ? 2 : fcsFlag == 2 ? 4 : 8;
        if (p + bytes > max) return -1;
        u64 f = 0;
        // Unsigned accumulation: an 8-byte FCS with a hostile high byte
        // would otherwise be signed-overflow UB.
        for (int k = 0; k < bytes; k++) f |= (u64)s.byte(off + p + k) << (8 * k);
        fcs = (i64)f;
        if (fcs1) fcs += 1;                  // 1-byte FCS stores size - 1
        if (fcsFlag == 1) fcs += 256;
        else if (fcsFlag == 2) fcs += 65536;
        if (fcs > kMaxFcs) return -1;
        p += bytes;
    }
    i64 consumed = 0;
    int blocks = 0;
    bool last = false;
    while (!last && p + 3 <= max && blocks < 1000000) {
        auto bh = s.read(off + p, 3);
        if (bh.size() < 3) return -1;
        const u32 hdr = (u32)bh[0] | ((u32)bh[1] << 8) | ((u32)bh[2] << 16);
        last = (hdr & 1) != 0;
        const int type = (int)((hdr >> 1) & 3);
        const u32 size = hdr >> 3;
        if (type == 3) return -1;                   // reserved
        if (size > 128 * 1024) return -1;
        if (type == 1) {                            // RLE: 1 content byte
            p += 3 + 1;
            consumed += size;
        } else if (type == 0) {                     // raw
            if (p + 3 + (i64)size > max) return -1;
            p += 3 + size;
            consumed += size;
        } else {                                    // compressed
            if (p + 3 + (i64)size > max) return -1;
            p += 3 + size;
            consumed += size;
        }
        blocks++;
    }
    if (!last) return -1;
    if (checksum) {
        if (p + 4 > max) return -1;
        p += 4;
    }
    if (fcs >= 0 && consumed != fcs) return -1;     // content size mismatch
    return p;
}

void registerFmt_zstd(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ZSTD", "zst", "archive", B({0x28,0xB5,0x2F,0xFD}), 8*GB,
                  SizeMode::FrameStream, vZstd); c.min_size = 16; add(c); }
}

}  // namespace ghost

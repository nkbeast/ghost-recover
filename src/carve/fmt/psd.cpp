// GHOST RECOVER — psd signature family (one file per format).
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

i64 vPsd(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 version = s.be16(off + 4);
    if (version != 1 && version != 2) return -1;
    u16 channels = s.be16(off + 12);
    u32 height = s.be32(off + 14);
    u32 width = s.be32(off + 18);
    u16 depth = s.be16(off + 22);
    if (channels == 0 || channels > 56 || width == 0 || height == 0) return -1;
    // The header is all we have before trusting these: bound the dimensions so
    // width * height * channels * depth cannot overflow signed arithmetic.
    if (width > 65536 || height > 65536) return -1;
    if (depth != 1 && depth != 8 && depth != 16 && depth != 32) return -1;
    i64 p = 26;
    u32 colorLen = s.be32(off + p); p += 4 + colorLen;
    u32 resLen   = s.be32(off + p); p += 4 + resLen;
    u32 layerLen = s.be32(off + p); p += 4 + layerLen;
    if (version == 2) {                          // global layer mask info section
        u32 maskLen = s.be32(off + p);
        p += 4 + maskLen;
    }
    if (p > max) return -1;
    // Image data section: uncompressed size is an upper bound.
    i64 raw = (i64)width * height * channels * (depth / 8 ? depth / 8 : 1);
    i64 total = std::min(p + raw + 2, max);
    return total;
}void registerFmt_psd(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PSD", "psd", "image", S("8BPS"), 2*GB, SizeMode::Header, vPsd);
      c.min_size = 128; add(c); }
}

}  // namespace ghost

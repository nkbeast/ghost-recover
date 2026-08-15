// GHOST RECOVER — bik signature family (one file per format).
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

i64 vBik(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u8 ver = s.byte(off + 3);
    if (ver != 'b' && ver != 'f' && ver != 'g') return -1;
    i64 hdrLen = (ver == 'b') ? 40 : 48;
    if (max < hdrLen + 8) return -1;
    u32 width = s.le32(off + 4), height = s.le32(off + 8);
    u32 frames = s.le32(off + 12), fps = s.le32(off + 16);
    if (width < 1 || width > 32768 || height < 1 || height > 32768) return -1;
    if (frames < 1 || frames > (1u << 20)) return -1;
    if (fps < 1 || fps > 100000) return -1;
    // The offset table holds frames+1 u32 entries: entry i = byte offset of
    // frame i; the final entry = the total file size.
    const i64 tableEnd = hdrLen + 4LL * (frames + 1);
    if (tableEnd > max) return -1;
    u32 first = s.le32(off + hdrLen);
    u32 total = s.le32(off + hdrLen + 4LL * frames);
    if (first < tableEnd || total <= first || total > max) return -1;
    u32 prev = first;
    for (u32 i = 1; i <= frames; i++) {
        u32 o = s.le32(off + hdrLen + 4LL * i);
        if (o < prev || o > total) return -1;
        prev = o;
    }
    return (i64)total;
}void registerFmt_bik(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("BIK", "bik", "video", S("BIK"), 4*GB, SizeMode::Container, vBik);
      c.min_size = 64; add(c); }
}

}  // namespace ghost

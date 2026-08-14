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
    if (max < hdrLen + 4) return -1;
    u32 width = s.le32(off + 8), height = s.le32(off + 12);
    u32 frames = s.le32(off + 16), fps = s.le32(off + 20);
    if (width < 1 || width > 32768 || height < 1 || height > 32768) return -1;
    if (frames < 1 || frames > (1u << 20)) return -1;
    if (fps < 1 || fps > 100000) return -1;
    u32 total = (ver == 'b') ? frames
                             : s.le32(off + 28) + s.le32(off + 32);
    if (total < 1 || total > (1u << 20)) return -1;
    i64 tableEnd = hdrLen + 4LL * total;
    if (tableEnd > max) return -1;
    i64 sum = 0;
    for (u32 i = 0; i < total; i++) {
        u32 fs = s.le32(off + hdrLen + 4LL * i);
        if (fs < 1 || fs > 128 * MB) return -1;
        sum += fs;
    }
    i64 size = tableEnd + sum;
    if (size > max) return -1;
    return size;
}void registerFmt_bik(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("BIK", "bik", "video", S("BIK"), 4*GB, SizeMode::Container, vBik);
      c.min_size = 64; add(c); }
}

}  // namespace ghost

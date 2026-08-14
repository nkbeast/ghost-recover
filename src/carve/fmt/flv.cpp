// GHOST RECOVER — flv signature family (one file per format).
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

i64 vFlv(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 9);
    if (h.size() < 9 || h[0] != 'F' || h[1] != 'L' || h[2] != 'V') return -1;
    u32 dataOffset = s.be32(off + 5);
    if (dataOffset < 9 || dataOffset > 1024) return -1;
    i64 p = off + dataOffset;
    int tags = 0;
    while (p + 15 <= off + max && tags < 4000000) {
        u32 prevSize = s.be32(p);
        (void)prevSize;
        u8 type = s.byte(p + 4) & 0x1F;
        if (type != 8 && type != 9 && type != 18) break;
        u32 dataSize = (u32)s.be16(p + 5) << 8 | s.byte(p + 7);
        i64 total = 4 + 11 + (i64)dataSize;
        if (p + total > off + max) break;
        p += total;
        tags++;
    }
    if (tags < 2) return -1;
    return (p + 4) - off;
}void registerFmt_flv(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("FLV", "flv", "video", B({'F','L','V',0x01}), 8*GB, SizeMode::Container, vFlv);
      c.min_size = 1024; add(c); }
}

}  // namespace ghost

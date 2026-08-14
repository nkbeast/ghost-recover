// GHOST RECOVER — ARJ archive signatures.
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

i64 vArj(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 pos = off;
    for (int step = 0; step < 64; step++) {
        if (pos + 30 > off + max) return -1;
        auto h = s.read(pos, 30);
        if (h.size() < 30) return -1;
        if (h[0] != 0x60 || h[1] != 0xEA) return -1;
        u16 hdrSize = (u16)h[2] | ((u16)h[3] << 8);
        if (hdrSize == 0) return pos + 4 - off;          // end-of-archive marker
        if (hdrSize < 26) return -1;
        u8 flags = h[5], ftype = h[7];
        u32 comp = 0;
        for (int i = 0; i < 4; i++) comp |= (u32)h[16 + i] << (i * 8);
        pos += 4 + hdrSize;
        if (ftype == 3 || (flags & 0x02)) continue;      // comment header: no data
        pos += comp;
    }
    return -1;
}

void registerFmt_arj(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ARJ", "arj", "archive", B({0x60, 0xEA}), 4*GB, SizeMode::Container, vArj); c.min_size = 30; add(c); }
}

}  // namespace ghost

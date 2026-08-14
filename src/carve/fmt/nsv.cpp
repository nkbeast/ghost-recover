// GHOST RECOVER — NSV video signatures.
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

i64 vNsv(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 pos = off;
    for (int step = 0; step < 512; step++) {
        if (pos + 8 > off + max) return -1;
        auto h = s.read(pos, 8);
        if (h.size() < 8) return -1;
        if (h[0] != 'N' || h[1] != 'S' || h[2] != 'V') return -1;
        u32 size = 0;
        for (int i = 0; i < 4; i++) size |= (u32)h[4 + i] << (i * 8);
        i64 next = pos + 8 + size;
        if (next > off + max) return -1;
        if (h[3] == 'f' && size == 0) return next - off; // NSVf EOF marker
        if (h[3] != 'f' && h[3] != 's') return -1;
        pos = next;
    }
    return -1;
}

void registerFmt_nsv(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("NSV", "nsv", "video", B({0x4E, 0x53, 0x56, 0x66}), 4*GB, SizeMode::Container, vNsv); c.min_size = 16; add(c); }
}

}  // namespace ghost

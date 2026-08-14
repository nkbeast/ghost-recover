// GHOST RECOVER — ARC archive signatures.
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

i64 vArc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 pos = off;
    for (int step = 0; step < 64; step++) {
        if (pos + 20 > off + max) return -1;
        auto h = s.read(pos, 20);
        if (h.size() < 20) return -1;
        if (h[0] != 0x1A) return -1;
        u8 method = h[1];
        if (method == 0) return pos + 2 - off;           // 1A 00 end marker
        if (method != 8) return -1;
        u8 ftype = h[3];
        u32 comp = 0;
        for (int i = 0; i < 4; i++) comp |= (u32)h[12 + i] << (i * 8);
        pos += 20 + ((ftype <= 1) ? (i64)comp : 0);
    }
    return -1;
}

void registerFmt_arc(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ARC", "arc", "archive", B({0x1A, 0x08}), 2*GB, SizeMode::Container, vArc); c.min_size = 23; add(c); }
}

}  // namespace ghost

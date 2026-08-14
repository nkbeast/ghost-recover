// GHOST RECOVER — emf signature family (one file per format).
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

i64 vEmf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.le32(off + 48);
    if (total < 88 || total > max) return -1;
    i64 p = off + 88;
    for (int guard = 0; guard < (1 << 20); guard++) {
        if (p + 8 > off + total) return -1;
        u32 type = s.le32(p);
        u32 size = s.le32(p + 4);
        if (size < 8 || p + size > off + total) return -1;
        p += size;
        if (type == 14) break;                                 // EMR_EOF
    }
    return (p == off + total) ? total : -1;
}void registerFmt_emf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("EMF", "emf", "image", B({0x01,0x00,0x00,0x00,0x58,0x00,0x00,0x00}), 64*MB, SizeMode::Header, vEmf));
}

}  // namespace ghost

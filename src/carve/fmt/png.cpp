// GHOST RECOVER — png signature family (one file per format).
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

i64 vPng(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 8;
    int chunks = 0;
    while (p + 12 <= off + max && chunks < 100000) {
        u32 len = s.be32(p);
        if (len > 0x7FFFFFFF) return -1;
        auto type = s.read(p + 4, 4);
        if (type.size() < 4) return -1;
        for (u8 c : type)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return -1;
        chunks++;
        i64 next = p + 12 + (i64)len;
        if (std::memcmp(type.data(), "IEND", 4) == 0) return next - off;
        if (next <= p || next > off + max) return -1;
        p = next;
    }
    return -1;
}void registerFmt_png(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PNG", "png", "image", B({0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A}), 512*MB,
                  SizeMode::Container, vPng); c.min_size = 67; c.priority = 10; add(c); }
}

}  // namespace ghost

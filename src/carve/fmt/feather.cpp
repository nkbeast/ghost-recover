// GHOST RECOVER — feather signature family (one file per format).
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

i64 vFeather(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = -1;
    i64 p = off + 8;
    while (p + 4 <= off + max) {
        auto m = s.read(p, 6);
        if (m.size() >= 6 && std::memcmp(m.data(), "ARROW1", 6) == 0) {
            u32 size = s.le32(p - 4);
            if ((i64)size == p - 4 - (off + 8) && p + 8 <= off + max)
                total = p + 8 - off;
        }
        p++;
    }
    return (total > 0 && total <= max) ? total : -1;
}void registerFmt_feather(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("Feather", "arrow", "database", S("ARROW1"), 8*GB, SizeMode::Header, vFeather));
}

}  // namespace ghost

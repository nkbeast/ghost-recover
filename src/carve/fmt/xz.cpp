// GHOST RECOVER — xz signature family (one file per format).
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

i64 vXz(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 12);
    if (h.size() < 12) return -1;
    static const u8 kFooter[2] = {'Y', 'Z'};
    const i64 kStep = 1 * MB;
    for (i64 base = 0; base < max; base += kStep - 16) {
        auto buf = s.read(off + base, std::min(kStep, max - base));
        if (buf.size() < 12) break;
        for (size_t i = 0; i + 2 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, kFooter, 2) == 0 && base + (i64)i >= 12)
                return base + (i64)i + 2;
        }
        if ((i64)buf.size() < std::min(kStep, max - base)) break;
    }
    return 0;
}void registerFmt_xz(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("XZ", "xz", "archive", B({0xFD,'7','z','X','Z',0x00}), 8*GB,
                  SizeMode::Heuristic, vXz); c.min_size = 32; add(c); }
}

}  // namespace ghost

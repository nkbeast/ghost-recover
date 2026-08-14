// GHOST RECOVER — icns signature family (one file per format).
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

i64 vIcns(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.be32(off + 4);
    if (total < 16 || total > max) return -1;
    i64 p = off + 8;
    while (p + 8 <= off + total) {
        u32 sz = s.be32(p + 4);
        if (sz < 8 || p + sz > off + total) return -1;
        p += sz;
    }
    return (p == off + total) ? total : -1;
}void registerFmt_icns(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("ICNS", "icns", "image", S("icns"), 64*MB, SizeMode::Header, vIcns));
}

}  // namespace ghost

// GHOST RECOVER — lzip signature family (one file per format).
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

i64 vLzip(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.byte(off + 4) < 1 || s.byte(off + 4) > 3) return -1;  // version
    i64 p = off + 20;
    while (p + 20 <= off + max) {
        i64 msize = (i64)s.be64(p + 12);
        if (msize >= 20 && msize == p + 20 - off) return p + 20 - off;
        p++;
    }
    return -1;
}void registerFmt_lzip(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("LZIP", "lz", "archive", S("LZIP"), 8*GB, SizeMode::Header, vLzip));
}

}  // namespace ghost

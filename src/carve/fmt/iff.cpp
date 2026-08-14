// GHOST RECOVER — iff signature family (one file per format).
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

i64 vIff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 sz = s.be32(off + 4);
    i64 total = (i64)sz + 8;
    if (total < 12 || total > max) return -1;
    return total;
}void registerFmt_iff(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("AIFF", "aiff", "audio", S("FORM"), 2*GB, SizeMode::Header, vIff);
      withConfirm(c, S("AIFF"), 8); c.priority = 20; c.min_size = 64; add(c); }
    { auto c = mk("AIFC", "aifc", "audio", S("FORM"), 2*GB, SizeMode::Header, vIff);
      withConfirm(c, S("AIFC"), 8); c.priority = 20; c.min_size = 64; add(c); }
}

}  // namespace ghost

// GHOST RECOVER — woff signature family (one file per format).
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

i64 vWoff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 length = s.be32(off + 8);
    if (length < 44 || (i64)length > max) return -1;
    return length;
}void registerFmt_woff(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("WOFF", "woff", "font", S("wOFF"), 64*MB, SizeMode::Header, vWoff);
      c.min_size = 44; add(c); }
    { auto c = mk("WOFF2", "woff2", "font", S("wOF2"), 64*MB, SizeMode::Header, vWoff);
      c.min_size = 48; add(c); }
}

}  // namespace ghost

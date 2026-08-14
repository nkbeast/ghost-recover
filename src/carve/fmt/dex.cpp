// GHOST RECOVER — dex signature family (one file per format).
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

i64 vDex(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 size = s.le32(off + 32);
    if (size < 112 || (i64)size > max) return -1;
    return size;
}void registerFmt_dex(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("DEX", "dex", "executable", S("dex\n"), 512*MB, SizeMode::Header, vDex);
      c.min_size = 112; add(c); }
}

}  // namespace ghost

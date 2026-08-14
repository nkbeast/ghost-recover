// GHOST RECOVER — regf signature family (one file per format).
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

i64 vRegf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 hbinsSize = s.le32(off + 0x28);
    if (hbinsSize == 0 || (i64)hbinsSize + 4096 > max) return -1;
    return 4096 + (i64)hbinsSize;
}void registerFmt_regf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("REGF", "hiv", "forensic", S("regf"), 4*GB, SizeMode::Header, vRegf);
      c.min_size = 4096; add(c); }
}

}  // namespace ghost

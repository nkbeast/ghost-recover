// GHOST RECOVER — prefetch signature family (one file per format).
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

i64 vPrefetch(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.le32(off + 4);
    if (ver != 0x11 && ver != 0x1A && ver != 0x1E && ver != 0x30) return -1;
    i64 total = s.le32(off + 0x0C);
    if (total < 0x50 || total > max) return -1;
    return total;
}void registerFmt_prefetch(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("PREFETCH", "pf", "forensic", S("SCCA"), 16*MB, SizeMode::Header, vPrefetch));
    add(mk("PREFETCH_C", "pf", "forensic", B({0x4D,0x41,0x4D,0x04}), 16*MB));
}

}  // namespace ghost

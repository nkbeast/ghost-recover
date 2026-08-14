// GHOST RECOVER — cab signature family (one file per format).
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

i64 vCab(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 size = s.le32(off + 8);
    if (size < 36 || (i64)size > max) return -1;
    return size;
}void registerFmt_cab(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("CAB", "cab", "archive", S("MSCF"), 2*GB, SizeMode::Header, vCab);
      c.min_size = 36; add(c); }
}

}  // namespace ghost

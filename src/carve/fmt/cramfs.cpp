// GHOST RECOVER — cramfs signature family (one file per format).
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

i64 vCramfs(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.le32(off + 4);
    if (total < 64 || total > max) return -1;
    return total;
}void registerFmt_cramfs(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("CRAMFS", "cramfs", "archive", B({0x45,0x3D,0xCD,0x28}), 2*GB, SizeMode::Header, vCramfs));
}

}  // namespace ghost

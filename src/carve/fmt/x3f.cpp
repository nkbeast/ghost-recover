// GHOST RECOVER — x3f signature family (one file per format).
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

i64 vX3f(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.be32(off + 0x14) + s.be32(off + 0x18);
    if (total < 28 || total > max) return -1;
    return total;
}void registerFmt_x3f(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("X3F", "x3f", "image", S("FOVb"), 256*MB, SizeMode::Header, vX3f));
}

}  // namespace ghost

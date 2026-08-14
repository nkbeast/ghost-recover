// GHOST RECOVER — xcf signature family (one file per format).
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

i64 vXcf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto v = s.read(off + 9, 5);
    if (v.size() < 5 || v[0] != 'v' || v[1] < '0' || v[1] > '1' ||
        v[2] < '0' || v[2] > '9' || v[3] < '0' || v[3] > '9' || v[4] < '0' || v[4] > '9')
        return -1;
    i64 total = s.be32(off + 22);
    if (total < 26 || total > max) return -1;
    return total;
}void registerFmt_xcf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("XCF", "xcf", "image", S("gimp xcf "), 512*MB, SizeMode::Header, vXcf));
}

}  // namespace ghost

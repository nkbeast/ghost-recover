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
    u32 baseType = s.be32(off + 22);
    if (baseType > 3) return -1;                    // 0 RGB, 1 grayscale, 2 indexed
    // The 27-byte header carries no file length: the extent is bounded by the
    // next signature and trailing-zero trim.
    return 0;
}void registerFmt_xcf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("XCF", "xcf", "image", S("gimp xcf "), 512*MB, SizeMode::Header, vXcf));
}

}  // namespace ghost

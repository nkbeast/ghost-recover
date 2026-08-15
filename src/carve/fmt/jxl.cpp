// GHOST RECOVER — jxl signature family (one file per format).
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

i64 vJxl(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 2);
    if (h.size() < 2) return -1;
    if (h[0] != 0xFF || h[1] != 0x0A) return -1;
    // The JXL codestream carries no length field: the extent is bounded by
    // the next signature and trailing-zero trim, so report an unknown size.
    return 0;
}void registerFmt_jxl(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("JXL", "jxl", "image", B({0xFF,0x0A}), 256*MB, SizeMode::Header, vJxl));
}

}  // namespace ghost

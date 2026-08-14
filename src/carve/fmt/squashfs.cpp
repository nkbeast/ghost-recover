// GHOST RECOVER — squashfs signature family (one file per format).
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

i64 vSquashfs(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 major = s.be16(off + 28), minor = s.be16(off + 30);
    if (major != 4 && major != 5) return -1;
    if (major == 4 && minor > 0) return -1;
    i64 total = (i64)s.le64(off + 40);
    if (total < 96 || total > max) return -1;
    return total;
}void registerFmt_squashfs(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("SQUASHFS", "squashfs", "archive", S("hsqs"), 8*GB, SizeMode::Header, vSquashfs));
}

}  // namespace ghost

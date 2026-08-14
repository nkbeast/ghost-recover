// GHOST RECOVER — dbx signature family (one file per format).
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

i64 vDbx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 indexStart = s.le32(off + 0x10);
    u32 indexSize = s.le32(off + 0x14);
    if (indexStart < 0x18 || indexSize == 0) return -1;
    i64 total = (i64)indexStart + indexSize;
    return (total <= max) ? total : -1;
}void registerFmt_dbx(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("DBX", "dbx", "email", B({0xCF,0xAD,0x12,0xFE}), 2*GB, SizeMode::Header, vDbx));
}

}  // namespace ghost

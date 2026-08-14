// GHOST RECOVER — one signature family (one file per format).
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

i64 vOne(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 cb = s.le32(off + 72);
    if (cb < 8) return -1;
    i64 total = 72 + (i64)cb;
    return (total <= max) ? total : -1;
}void registerFmt_one(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("ONE", "one", "document", B({0xE4,0x52,0x5C,0x7B,0x8C,0xD8,0xA7,0x4D}), 512*MB, SizeMode::Header, vOne));
}

}  // namespace ghost

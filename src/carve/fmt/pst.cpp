// GHOST RECOVER — pst signature family (one file per format).
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

i64 vPst(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 ver = s.le16(off + 0x0A);
    if (ver != 23) return -1;                                  // ANSI only
    u32 nextFree = s.le32(off + 0x14);
    if (nextFree < 2) return -1;
    i64 total = (i64)nextFree * 512;
    return (total <= max) ? total : -1;
}void registerFmt_pst(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("PST", "pst", "email", B({0x21,0x42,0x44,0x4E}), 32*GB, SizeMode::Header, vPst));
}

}  // namespace ghost

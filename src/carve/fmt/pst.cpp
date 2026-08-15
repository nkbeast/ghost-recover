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
    u16 ver = s.le16(off + 4);                 // dwVersion: 14/15 ANSI, 23 Unicode
    if (ver != 14 && ver != 15 && ver != 23) return -1;
    // No reliable total-size field exists across ANSI/Unicode layouts: the
    // extent is bounded by the next signature and trailing-zero trim.
    return 0;
}void registerFmt_pst(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("PST", "pst", "email", B({0x21,0x42,0x44,0x4E}), 32*GB, SizeMode::Header, vPst));
}

}  // namespace ghost

// GHOST RECOVER — raf signature family (one file per format).
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

i64 vRaf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.be32(off + 0x62) + s.be32(off + 0x66);
    if (total < 0x70 || total > max) return -1;
    return total;
}void registerFmt_raf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("RAF", "raf", "image", S("FUJIFILMCCD-RAW "), 256*MB, SizeMode::Header, vRaf));
}

}  // namespace ghost

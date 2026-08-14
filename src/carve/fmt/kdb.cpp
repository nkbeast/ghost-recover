// GHOST RECOVER — kdb signature family (one file per format).
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

i64 vKdb(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.le32(off + 8) != 3) return -1;                       // version
    u32 len = s.le32(off + 116);
    if (len < 1 || len > (u32)max) return -1;
    i64 total = 120 + (i64)len;
    return (total <= max) ? total : -1;
}void registerFmt_kdb(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("KDB", "kdb", "crypto", B({0x03,0xD9,0xA2,0x9A,0x65,0xFB,0x4B,0xB5}), 256*MB, SizeMode::Header, vKdb));
}

}  // namespace ghost

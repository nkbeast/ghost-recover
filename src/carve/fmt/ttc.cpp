// GHOST RECOVER — ttc signature family (one file per format).
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

i64 vTtc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.be32(off + 4);
    if (ver != 0x00010000 && ver != 0x00020000) return -1;
    u32 nfonts = s.be32(off + 8);
    if (nfonts == 0 || nfonts > 100000) return -1;
    const i64 end = off + max;
    i64 highest = -1;
    for (u32 f = 0; f < nfonts; f++) {
        u32 foff = s.be32(off + 12 + 4 * f);
        if ((i64)foff > end) return -1;
        u16 numTables = s.be16(off + foff + 4);
        if (numTables == 0 || numTables > 4096) return -1;
        for (u16 t = 0; t < numTables; t++) {
            i64 toff = off + foff + 12 + 16 * t;
            if (toff + 16 > end) return -1;
            u32 eoff = s.be32(toff + 8);
            u32 elen = s.be32(toff + 12);
            highest = std::max(highest, (i64)eoff + elen);
        }
    }
    if (highest < 0) return -1;
    if (highest > end) return -1;
    return highest;
}void registerFmt_ttc(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("TTC", "ttc", "font", S("ttcf"), 64*MB, SizeMode::Container, vTtc);
      c.min_size = 16; add(c); }
}

}  // namespace ghost

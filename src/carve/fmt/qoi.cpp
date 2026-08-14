// GHOST RECOVER — qoi signature family (one file per format).
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

i64 vQoi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 4) == 0 || s.be32(off + 8) == 0) return -1;   // width/height
    u8 ch = s.byte(off + 12);
    if (ch < 3 || ch > 4) return -1;
    i64 p = off + 14;
    while (p + 8 <= off + max) {
        // The end marker (7 zero bytes + 0x01) must be checked before
        // decoding — its own zero bytes read back-to-back as index ops.
        if (s.be32(p) == 0 && s.be32(p + 4) == 1) return (p + 8) - off;
        u8 b = s.byte(p);
        if (b == 0xFE) { p += 4; continue; }   // QOI_OP_RGB
        if (b == 0xFF) { p += 5; continue; }   // QOI_OP_RGBA
        p += ((b >> 6) == 2) ? 2 : 1;          // luma takes 2 bytes, others 1
    }
    return -1;
}void registerFmt_qoi(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("QOI", "qoi", "image", S("qoif"), 256*MB, SizeMode::Heuristic, vQoi));
}

}  // namespace ghost

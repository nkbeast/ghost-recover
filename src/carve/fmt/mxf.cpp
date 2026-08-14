// GHOST RECOVER — mxf signature family (one file per format).
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

i64 vMxf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off;
    int klvs = 0;
    while (p + 17 <= off + max && klvs < 4000000) {
        auto key = s.read(p, 16);
        if (key.size() < 16 || key[0] != 0x06 || key[1] != 0x0E || key[2] != 0x2B || key[3] != 0x34)
            break;
        u8 l0 = s.byte(p + 16);
        i64 L, hdr;
        if (l0 & 0x80) {
            int nbytes = l0 & 0x7F;
            if (nbytes == 0 || nbytes > 8 || p + 17 + nbytes > off + max) return -1;
            L = 0;
            for (int k = 0; k < nbytes; k++) L = L << 8 | s.byte(p + 17 + k);
            hdr = 17 + nbytes;
        } else {
            L = l0;
            hdr = 17;
        }
        if (L < 0) return -1;
        p += hdr + L;
        klvs++;
    }
    if (klvs < 4) return -1;
    return p - off;
}void registerFmt_mxf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("MXF", "mxf", "video", B({0x06,0x0E,0x2B,0x34,0x02,0x05,0x01,0x01}), 32*GB,
           SizeMode::Container, vMxf));
}

}  // namespace ghost

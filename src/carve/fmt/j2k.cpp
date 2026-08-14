// GHOST RECOVER — j2k signature family (one file per format).
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

i64 vJ2k(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 2;                                           // after SOC
    for (int guard = 0; guard < (1 << 16); guard++) {
        if (p + 2 > off + max) return -1;
        u16 m = s.be16(p);
        if (m == 0xFFD9) return (p + 2) - off;                 // EOC
        if (m == 0xFF90) {                                     // SOT
            i64 psot = s.be32(p + 6);
            if (psot < 14) return -1;
            p += psot;                                         // skip to tile end
            continue;
        }
        if ((m >> 8) != 0xFF) return -1;
        switch (m) {
            case 0xFF51: case 0xFF52: case 0xFF53: case 0xFF5C:
            case 0xFF5D: case 0xFF5E: case 0xFF5F: case 0xFF60:
            case 0xFF61: case 0xFF62: case 0xFF63: {           // length-carrying
                u16 len = s.be16(p + 2);
                if (len < 2) return -1;
                p += 2 + len;
                break;
            }
            case 0xFF4F: case 0xFF91: case 0xFF92:             // SOC/SOP/EPH
                p += 2;
                break;
            default:
                return -1;
        }
    }
    return -1;
}void registerFmt_j2k(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("J2K", "j2k", "image", B({0xFF,0x4F,0xFF,0x51}), 256*MB, SizeMode::Header, vJ2k));
}

}  // namespace ghost

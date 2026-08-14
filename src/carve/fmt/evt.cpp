// GHOST RECOVER — evt signature family (one file per format).
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

i64 vEvt(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.le32(off + 0x10) != 0x30) return -1;                 // end-of-header
    i64 p = off + 0x30;
    for (int guard = 0; guard < (1 << 20); guard++) {
        if (p + 8 > off + max) return -1;
        u32 len = s.le32(p);
        if (len == 0) return (p + 4) - off;                    // terminator
        if (len < 0x18 || p + len > off + max) return -1;
        if (s.be32(p + 4) != 0x4C664C65) return -1;            // LfLe
        p += len;
    }
    return -1;
}void registerFmt_evt(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("EVT", "evt", "forensic", B({0x30,0x00,0x00,0x00,'L','f','L','e'}), 512*MB, SizeMode::Header, vEvt));
}

}  // namespace ghost

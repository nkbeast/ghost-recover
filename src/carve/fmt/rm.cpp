// GHOST RECOVER — rm signature family (one file per format).
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

i64 vRm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be16(off + 4) != 0) return -1;                       // version 0
    if (s.be16(off + 6) < 1) return -1;                        // headers present
    i64 p = off + 12;
    for (int guard = 0; guard < (1 << 20); guard++) {
        if (p + 8 > off + max) return -1;
        auto type = s.read(p, 4);
        if (type.size() < 4) return -1;
        bool known = std::memcmp(type.data(), "PROP", 4) == 0 ||
                     std::memcmp(type.data(), "MDPR", 4) == 0 ||
                     std::memcmp(type.data(), "CONT", 4) == 0 ||
                     std::memcmp(type.data(), "DATA", 4) == 0 ||
                     std::memcmp(type.data(), "INDX", 4) == 0;
        if (!known) return p - off;                            // file ended
        u32 size = s.be32(p + 4);
        if (size < 8 || p + 8 + size > off + max) return -1;
        p += 8 + size;
    }
    return -1;
}void registerFmt_rm(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("RM", "rm", "video", S(".RMF"), 4*GB, SizeMode::Header, vRm));
}

}  // namespace ghost

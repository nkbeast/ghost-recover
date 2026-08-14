// GHOST RECOVER — caf signature family (one file per format).
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

i64 vCaf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be16(off + 4) != 1) return -1;
    i64 p = off + 8;
    int chunks = 0;
    while (p + 12 <= off + max && chunks < 100000) {
        auto t = s.read(p, 4);
        if (t.size() < 4) return -1;
        auto szb = s.read(p + 4, 8);
        if (szb.size() < 8) return -1;
        u64 sz = 0;
        for (int k = 0; k < 8; k++) sz = sz << 8 | szb[k];
        if (sz > (u64)max) return -1;
        // Chunk types are four printable ASCII letters; a run of zeroes (the
        // gap after a deleted file) or foreign data stops the chain here.
        bool printable = true;
        for (u8 c : t)
            if (c < 0x20 || c > 0x7E) { printable = false; break; }
        if (!printable) break;
        p += 12 + (i64)sz;
        chunks++;
    }
    if (chunks == 0) return -1;
    if (p > off + max) return -1;
    return p - off;
}void registerFmt_caf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("CAF", "caf", "audio", S("caff"), 2*GB, SizeMode::Container, vCaf));
}

}  // namespace ghost

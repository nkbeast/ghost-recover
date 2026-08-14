// GHOST RECOVER — chm signature family (one file per format).
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

i64 vChm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 8) != 0x60) return -1;                    // header length
    u32 ver = s.be32(off + 4);
    if (ver != 2 && ver != 3) return -1;
    i64 p = off + 0x60;
    for (int guard = 0; guard < (1 << 16); guard++) {
        if (p + 0x800 > off + max) return -1;
        if (s.be32(p) != 0x504D474C) return -1;                // PMGL
        i64 next = s.le32(p + 8);
        if (next == 0) return (p + 0x800) - off;               // last page
        if (next != (p - off) / 0x800 + 1 || next > (1 << 16)) return -1;
        p += 0x800;
    }
    return -1;
}void registerFmt_chm(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("CHM", "chm", "document", S("ITSF"), 512*MB, SizeMode::Header, vChm));
}

}  // namespace ghost

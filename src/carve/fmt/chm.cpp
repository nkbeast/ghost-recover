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
    // The 0x38-byte ITSP directory header follows the ITSF header; its
    // chunk tree position points at the PMGL/PMGI page sequence.
    if (off + 0x60 + 0x38 > off + max) return -1;
    if (s.be32(off + 0x60) != 0x49545350) return -1;           // "ITSP"
    u32 numChunks = s.le32(off + 0x60 + 0x14);
    u32 treePos = s.le32(off + 0x60 + 0x1C);
    if (numChunks < 1 || numChunks > (1 << 24)) return -1;
    i64 p = off + (i64)treePos;
    for (u32 i = 0; i < numChunks; i++) {
        if (p + 0x800 > off + max) return -1;
        u32 sig = s.be32(p);
        if (sig != 0x504D474C && sig != 0x504D4749) return -1; // PMGL / PMGI
        u32 next = s.le32(p + 8);
        if (next == 0xFFFFFFFFu) return p + 0x800 - off;       // last page
        if (next != i + 1) return -1;
        p += 0x800;
    }
    return p - off;
}void registerFmt_chm(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("CHM", "chm", "document", S("ITSF"), 512*MB, SizeMode::Header, vChm));
}

}  // namespace ghost

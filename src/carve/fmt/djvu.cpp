// GHOST RECOVER — djvu signature family (one file per format).
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

i64 vDjvu(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = 12 + s.be32(off + 8);
    if (total < 12 || total > max) return -1;
    i64 p = off + 12;
    while (p + 8 <= off + total) {
        u32 size = s.be32(p + 4);
        if (size > (u32)(off + total - p - 8)) return -1;
        p += 8 + size + (size & 1);   // IFF pads odd chunks to an even boundary
    }
    return (p >= off + total) ? p - off : -1;
}void registerFmt_djvu(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("DJVU", "djvu", "document", S("AT&TFORM"), 512*MB, SizeMode::Header, vDjvu));
}

}  // namespace ghost

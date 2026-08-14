// GHOST RECOVER — WAD archive signatures; WAD_PWAD archive signatures.
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

i64 vWad(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 12 > off + max) return -1;
    auto h = s.read(off, 12);
    if (h.size() < 12) return -1;
    u32 lumps = 0, dirOff = 0;
    for (int i = 0; i < 4; i++) {
        lumps |= (u32)h[4 + i] << (i * 8);
        dirOff |= (u32)h[8 + i] << (i * 8);
    }
    if (lumps == 0 || lumps > 0x40000 || dirOff < 12) return -1;
    i64 total = (i64)dirOff + (i64)lumps * 16;
    if (total > max) return -1;
    return total;
}

void registerFmt_wad(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("WAD", "wad", "archive", S("IWAD"), 1*GB, SizeMode::Container, vWad); c.min_size = 12; add(c); }
    { auto c = mk("WAD_PWAD", "wad", "archive", S("PWAD"), 1*GB, SizeMode::Container, vWad); c.min_size = 12; add(c); }
}

}  // namespace ghost

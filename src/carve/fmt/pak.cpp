// GHOST RECOVER — PAK archive signatures.
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

i64 vPak(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 16 > off + max) return -1;
    auto h = s.read(off, 16);
    if (h.size() < 16) return -1;
    u32 dirOff = 0, dirSize = 0;
    for (int i = 0; i < 4; i++) {
        dirOff |= (u32)h[4 + i] << (i * 8);
        dirSize |= (u32)h[8 + i] << (i * 8);
    }
    if (dirOff < 16 || dirSize == 0 || dirSize % 64 != 0) return -1;
    i64 total = (i64)dirOff + dirSize;
    if (total > max) return -1;
    return total;
}

void registerFmt_pak(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PAK", "pak", "archive", S("PACK"), 512*MB, SizeMode::Container, vPak); c.min_size = 16; add(c); }
}

}  // namespace ghost

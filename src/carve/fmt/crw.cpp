// GHOST RECOVER — CRW image signatures.
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

i64 vCrw(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 28 > off + max) return -1;
    auto h = s.read(off, 28);
    if (h.size() < 28) return -1;
    if (h[8] != 'H' || h[9] != 'E' || h[10] != 'A' || h[11] != 'P') return -1;
    u32 dirOff = 0, n = 0;
    for (int i = 0; i < 4; i++) {
        dirOff |= (u32)h[16 + i] << (i * 8);
        n |= (u32)h[20 + i] << (i * 8);
    }
    if (dirOff < 28 || n == 0 || n > 0x10000) return -1;
    i64 dirEnd = (i64)dirOff + (i64)n * 12;
    if (dirEnd > max) return -1;
    return dirEnd;
}

void registerFmt_crw(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("CRW", "crw", "image", B({0x49, 0x49, 0x1A, 0x00, 0x00, 0x00}), 128*MB, SizeMode::Container, vCrw); c.min_size = 28; add(c); }
}

}  // namespace ghost

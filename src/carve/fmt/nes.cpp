// GHOST RECOVER — NES misc signatures.
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

i64 vNes(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 16 > off + max) return -1;
    auto h = s.read(off, 16);
    if (h.size() < 16) return -1;
    int prg = h[4], chr = h[5];
    if (prg == 0 || prg > 0x400) return -1;
    i64 total = 16 + (i64)prg * 16384 + (i64)chr * 8192;
    if (h[6] & 0x04) total += 512;                       // trainer
    if (total > max) return -1;
    return total;
}

void registerFmt_nes(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("NES", "nes", "misc", B({0x4E, 0x45, 0x53, 0x1A}), 512*MB, SizeMode::Container, vNes); c.min_size = 16; add(c); }
}

}  // namespace ghost

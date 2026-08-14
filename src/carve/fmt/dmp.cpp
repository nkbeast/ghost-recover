// GHOST RECOVER — DMP forensic signatures.
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

i64 vDmp(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 32 > off + max) return -1;
    auto h = s.read(off, 32);
    if (h.size() < 32) return -1;
    u32 n = 0, dir = 0;
    for (int i = 0; i < 4; i++) {
        n |= (u32)h[ 8 + i] << (i * 8);
        dir |= (u32)h[12 + i] << (i * 8);
    }
    if (n == 0 || n > 0x10000 || dir < 32) return -1;
    i64 p = off + dir;
    i64 dirEnd = p + (i64)n * 12;
    if (dirEnd > off + max) return -1;
    i64 end = dirEnd;
    for (u32 i = 0; i < n; i++, p += 12) {
        auto e = s.read(p, 12);
        if (e.size() < 12) return -1;
        u32 size = 0, rva = 0;
        for (int k = 0; k < 4; k++) {
            size |= (u32)e[4 + k] << (k * 8);
            rva |= (u32)e[8 + k] << (k * 8);
        }
        i64 dataEnd = off + (i64)rva + size;
        if (dataEnd > end) end = dataEnd;
    }
    if (end > off + max) return -1;
    return end - off;
}

void registerFmt_dmp(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("DMP", "dmp", "forensic", S("MDMP"), 4*GB, SizeMode::Container, vDmp); c.min_size = 32; add(c); }
}

}  // namespace ghost

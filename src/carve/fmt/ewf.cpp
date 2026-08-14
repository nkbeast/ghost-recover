// GHOST RECOVER — E01 forensic signatures; L01 forensic signatures.
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

i64 vEwf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 pos = off + 16;                                  // first section header
    i64 end = 0;
    for (int step = 0; step < 64; step++) {
        if (pos + 16 > off + max) return -1;
        auto h = s.read(pos, 16);
        if (h.size() < 16) return -1;
        u32 next = 0;
        u64 size = 0;
        for (int i = 0; i < 4; i++) next |= (u32)h[4 + i] << (i * 8);
        for (int i = 0; i < 8; i++) size |= (u64)h[8 + i] << (i * 8);
        i64 secEnd = pos + 16 + (i64)size;
        if (secEnd > off + max) return -1;
        if (secEnd > end) end = secEnd;
        if (next == 0) break;
        if (next <= (u32)(pos - off)) return -1;         // sections move forward
        pos = off + next;
    }
    return end > 0 ? end - off : -1;
}

void registerFmt_ewf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("E01", "e01", "forensic", B({0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00}), 64*GB, SizeMode::Container, vEwf); c.min_size = 32; add(c); }
    { auto c = mk("L01", "l01", "forensic", B({0x4C, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00}), 64*GB, SizeMode::Container, vEwf); c.min_size = 32; add(c); }
}

}  // namespace ghost

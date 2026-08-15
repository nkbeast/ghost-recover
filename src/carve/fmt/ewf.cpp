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
    auto fh = s.read(off, 13);
    if (fh.size() < 13) return -1;
    if (s.le32(off + 8) != 0x00010000) return -1;      // file format version 1
    // Section chain: 76-byte section headers. The "next" field (u64 at +16)
    // is the offset of the following header relative to this section's start;
    // "size" (u64 at +24) spans from this header through the section data.
    i64 pos = off + 13;
    i64 end = 0;
    for (int step = 0; step < 64; step++) {
        if (pos + 76 > off + max) return -1;
        auto h = s.read(pos, 76);
        if (h.size() < 76) return -1;
        u64 next = 0, size = 0;
        for (int i = 0; i < 8; i++) {
            next |= (u64)h[16 + i] << (8 * i);
            size |= (u64)h[24 + i] << (8 * i);
        }
        i64 secEnd = pos + (i64)size;
        if (size == 0) secEnd = pos + 76;               // "done": header only
        if (secEnd > off + max) return -1;
        end = std::max(end, secEnd);
        if (next == 0) break;
        i64 nextPos = pos + (i64)next;
        if (nextPos <= pos) return -1;
        pos = nextPos;
    }
    return end > 0 ? end - off : -1;
}

void registerFmt_ewf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("E01", "e01", "forensic", B({0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00}), 64*GB, SizeMode::Container, vEwf); c.min_size = 32; add(c); }
    { auto c = mk("L01", "l01", "forensic", B({0x4C, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00}), 64*GB, SizeMode::Container, vEwf); c.min_size = 32; add(c); }
}

}  // namespace ghost

// GHOST RECOVER — sfnt signature family (one file per format).
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

i64 vSfnt(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 numTables = s.be16(off + 4);
    // Real fonts have on the order of ten to forty tables. The searchRange /
    // entrySelector / rangeShift trio must also agree with numTables, which is
    // what separates a genuine font from a run of zeroes that happens to start
    // with 00 01 00 00.
    if (numTables < 3 || numTables > 128) return -1;
    u16 searchRange = s.be16(off + 6);
    u16 entrySelector = s.be16(off + 8);
    u16 expectedSel = 0;
    while ((1u << (expectedSel + 1)) <= numTables) expectedSel++;
    if (entrySelector != expectedSel) return -1;
    if (searchRange != (u16)((1u << expectedSel) * 16)) return -1;

    const i64 dirEnd = 12 + (i64)numTables * 16;
    i64 furthest = dirEnd;
    bool sawRequired = false;
    for (u16 i = 0; i < numTables; i++) {
        i64 e = 12 + (i64)i * 16;
        auto tag = s.read(off + e, 4);
        if (tag.size() < 4) return -1;
        for (u8 c : tag)
            if (c < 0x20 || c > 0x7E) return -1;             // tags are printable ASCII
        if (std::memcmp(tag.data(), "head", 4) == 0 || std::memcmp(tag.data(), "cmap", 4) == 0 ||
            std::memcmp(tag.data(), "glyf", 4) == 0 || std::memcmp(tag.data(), "CFF ", 4) == 0)
            sawRequired = true;
        u32 tOff = s.be32(off + e + 8);
        u32 tLen = s.be32(off + e + 12);
        if (tOff < (u32)dirEnd) return -1;                    // tables follow the directory
        if ((i64)tOff + tLen > max) return -1;
        furthest = std::max<i64>(furthest, (i64)tOff + tLen);
    }
    if (!sawRequired) return -1;
    return furthest;
}void registerFmt_sfnt(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("TTF", "ttf", "font", B({0x00,0x01,0x00,0x00,0x00}), 64*MB,
                  SizeMode::Header, vSfnt); c.min_size = 2048; add(c); }
    { auto c = mk("OTF", "otf", "font", S("OTTO"), 64*MB, SizeMode::Header, vSfnt);
      c.min_size = 128; add(c); }
}

}  // namespace ghost

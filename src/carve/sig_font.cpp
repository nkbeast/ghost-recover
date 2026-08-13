// GHOST RECOVER — carver signature specs and validators for Fonts.
//
// Part of the per-category split of the former monolithic signatures.cpp.
// Shared plumbing (mk, withConfirm, cross-category validators) lives in
// sig_common.h / sig_common.cpp; the registry aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "sig_common.h"

#include <algorithm>
#include <cstring>

namespace ghost {


// --- Fonts -----------------------------------------------------------------
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
}
i64 vWoff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 length = s.be32(off + 8);
    if (length < 44 || (i64)length > max) return -1;
    return length;
}


// --- TTF Collection: ttcf + per-font sfnt table directory --------------------
i64 vTtc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.be32(off + 4);
    if (ver != 0x00010000 && ver != 0x00020000) return -1;
    u32 nfonts = s.be32(off + 8);
    if (nfonts == 0 || nfonts > 100000) return -1;
    const i64 end = off + max;
    i64 highest = -1;
    for (u32 f = 0; f < nfonts; f++) {
        u32 foff = s.be32(off + 12 + 4 * f);
        if ((i64)foff > end) return -1;
        u16 numTables = s.be16(off + foff + 4);
        if (numTables == 0 || numTables > 4096) return -1;
        for (u16 t = 0; t < numTables; t++) {
            i64 toff = off + foff + 12 + 16 * t;
            if (toff + 16 > end) return -1;
            u32 eoff = s.be32(toff + 8);
            u32 elen = s.be32(toff + 12);
            highest = std::max(highest, (i64)eoff + elen);
        }
    }
    if (highest < 0) return -1;
    if (highest > end) return -1;
    return highest;
}

void registerFonts(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("TTF", "ttf", "font", B({0x00,0x01,0x00,0x00,0x00}), 64*MB,
                  SizeMode::Header, vSfnt); c.min_size = 2048; add(c); }
    { auto c = mk("OTF", "otf", "font", S("OTTO"), 64*MB, SizeMode::Header, vSfnt);
      c.min_size = 128; add(c); }
    { auto c = mk("TTC", "ttc", "font", S("ttcf"), 64*MB, SizeMode::Container, vTtc);
      c.min_size = 16; add(c); }
    { auto c = mk("WOFF", "woff", "font", S("wOFF"), 64*MB, SizeMode::Header, vWoff);
      c.min_size = 44; add(c); }
    { auto c = mk("WOFF2", "woff2", "font", S("wOF2"), 64*MB, SizeMode::Header, vWoff);
      c.min_size = 48; add(c); }
}

}  // namespace ghost

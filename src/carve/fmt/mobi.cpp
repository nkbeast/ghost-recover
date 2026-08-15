// GHOST RECOVER — mobi signature family (one file per format).
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

i64 vMobi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 60) != 0x424F4F4B) return -1;             // "BOOK"
    if (s.be32(off + 64) != 0x4D4F4249) return -1;             // "MOBI"
    u32 num = s.be16(off + 76);
    if (num < 1 || num > 100000) return -1;
    i64 table = off + 78;
    if (table + 8 * (i64)num > off + max) return -1;
    u32 prev = 78 + 8 * num;                   // record 0 must follow the table
    for (u32 i = 0; i < num; i++) {
        u32 o = s.be32(table + 8 * (i64)i);
        if (o < prev) return -1;
        prev = o;
    }
    // Record 0 is the MOBI header; its first 8 bytes are the PalmDoc magic.
    u32 r0 = s.be32(table);
    auto sig = s.read(off + (i64)r0, 8);
    if (sig.size() < 8 || std::memcmp(sig.data(), "TEXtREAd", 8) != 0) return -1;
    // The last record has no stored size: report an unknown size.
    return 0;
}void registerFmt_mobi(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MOBI", "mobi", "document", S("BOOKMOBI"), 256*MB, SizeMode::Header, vMobi);
      c.magic_offset = 60; add(c); }
}

}  // namespace ghost

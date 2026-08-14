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
    u32 lastOff = s.be32(table + 8 * (num - 1));
    u16 lastSize = s.be16(table + 8 * (i64)num);
    if (lastSize == 0) return -1;
    i64 total = (i64)lastOff + lastSize;
    if (total < 78 + 8 * (i64)num || total > max) return -1;
    u32 prev = 0;
    for (u32 i = 0; i < num; i++) {
        u32 o = s.be32(table + 8 * (i64)i);
        if (o < prev || o > (u32)total) return -1;
        prev = o;
    }
    return total;
}void registerFmt_mobi(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MOBI", "mobi", "document", S("BOOKMOBI"), 256*MB, SizeMode::Header, vMobi);
      c.magic_offset = 60; add(c); }
}

}  // namespace ghost

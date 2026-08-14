// GHOST RECOVER — jks signature family (one file per format).
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

i64 vJks(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.be32(off + 4);
    u32 count = s.be32(off + 8);
    if (ver != 1 && ver != 2) return -1;
    if (count < 1 || count > 1024) return -1;
    i64 p = off + 12;
    for (u32 i = 0; i < count; i++) {
        if (p + 2 > off + max) return -1;
        u32 aliasLen = s.be16(p);
        if (aliasLen > 65535 || p + 2 + aliasLen + 8 > off + max) return -1;
        p += 2 + aliasLen + 8;                                 // alias + ts
        if (p + 4 > off + max) return -1;
        u32 keyLen = s.be32(p);
        if (p + 4 + keyLen > off + max) return -1;
        p += 4 + keyLen;
        if (p + 4 > off + max) return -1;
        u32 chain = s.be32(p);
        if (chain > 1024) return -1;
        p += 4;
        for (u32 c = 0; c < chain; c++) {
            if (p + 4 > off + max) return -1;
            u32 certLen = s.be32(p);
            if (p + 4 + certLen > off + max) return -1;
            p += 4 + certLen;
        }
    }
    return p - off;
}void registerFmt_jks(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("JKS", "jks", "crypto", B({0xFE,0xED,0xFE,0xED}), 16*MB, SizeMode::Header, vJks));
}

}  // namespace ghost

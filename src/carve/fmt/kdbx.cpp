// GHOST RECOVER — kdbx signature family (one file per format).
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

i64 vKdbx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.le32(off + 8);
    if ((ver & 0xFFFF0000) != 0x00030000 && (ver & 0xFFFF0000) != 0x00040000) return -1;
    i64 p = off + 12;
    for (int guard = 0; guard < 256; guard++) {
        if (p + 5 > off + max) return -1;
        u8 type = s.byte(p);
        if (type == 0) break;                                  // END
        if (type > 7) return -1;
        u32 size = s.le32(p + 1);
        if (size > (1 << 20)) return -1;
        p += 5 + size;
    }
    u32 len = s.le32(p);
    if (len < 1 || len > (u32)max) return -1;
    i64 total = p + 4 + (i64)len;
    return (total <= off + max) ? total - off : -1;
}void registerFmt_kdbx(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("KDBX", "kdbx", "crypto", B({0x03,0xD9,0xA2,0x9A,0x67,0xFB,0x4B,0xB5}), 256*MB, SizeMode::Header, vKdbx));
}

}  // namespace ghost

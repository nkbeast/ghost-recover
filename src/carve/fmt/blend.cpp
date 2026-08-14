// GHOST RECOVER — blend signature family (one file per format).
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

i64 vBlend(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.le32(off + 18) != 4) return -1;                      // pointer size
    u8 endian = s.byte(off + 22);
    if (endian != 0x2C && endian != 0x3C) return -1;           // < or >
    i64 p = off + 31;                                          // after the version
    for (int guard = 0; guard < (1 << 20); guard++) {
        if (p + 32 > off + max) return -1;
        auto code = s.read(p, 4);
        if (code.size() < 4) return -1;
        u32 size;
        if (endian == 0x2C) size = s.le32(p + 4);
        else                size = s.be32(p + 4);
        if (size > (u32)(max - (p - off))) return -1;
        if (std::memcmp(code.data(), "ENDB", 4) == 0) return (p + 32) - off;
        p += 32 + size;
    }
    return -1;
}void registerFmt_blend(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("BLEND", "blend", "misc", S("BLENDER"), 4*GB, SizeMode::Header, vBlend));
}

}  // namespace ghost

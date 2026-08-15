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
    // 17-byte file header: "BLENDER" + "BLEND" + 3 version digits, a pointer
    // size byte ('_' = 8, '-' = 4) and an endianness byte ('v' = LE, 'V' = BE).
    auto h = s.read(off, 17);
    if (h.size() < 17) return -1;
    if (std::memcmp(h.data(), "BLENDER", 7) != 0) return -1;
    if (std::memcmp(h.data() + 7, "BLEND", 5) != 0) return -1;
    u8 ptr = h[15];
    u8 endian = h[16];
    if (ptr != '_' && ptr != '-') return -1;
    if (endian != 'v' && endian != 'V') return -1;
    const i64 bheadLen = (ptr == '_') ? 24 : 20;   // code+size+ptr+sdna+nr
    i64 p = off + 17;
    for (int guard = 0; guard < (1 << 20); guard++) {
        if (p + bheadLen > off + max) return -1;
        auto code = s.read(p, 4);
        if (code.size() < 4) return -1;
        u32 size = (endian == 'v') ? s.le32(p + 4) : s.be32(p + 4);
        if (std::memcmp(code.data(), "ENDB", 4) == 0) return p + bheadLen - off;
        if (std::memcmp(code.data(), "SDNA", 4) == 0) {
            if (p + bheadLen + (i64)size > off + max) return -1;
            return p + bheadLen + (i64)size - off;
        }
        if (size > 0x7FFFFFFF) return -1;
        if (p + bheadLen + (i64)size > off + max) return -1;
        p += bheadLen + (i64)size;
    }
    return -1;
}void registerFmt_blend(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("BLEND", "blend", "misc", S("BLENDER"), 4*GB, SizeMode::Header, vBlend));
}

}  // namespace ghost

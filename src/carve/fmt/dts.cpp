// GHOST RECOVER — dts signature family (one file per format).
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

i64 vDts(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // DTS core frame: 32-bit sync 0x7FFE8001; the 14-bit frame size field
    // sits at bit offset 24, i.e. (b3<<8|b4)>>2, in 16-bit words.
    i64 p = off;
    int frames = 0;
    while (p + 8 <= off + max && frames < 1000000) {
        auto b = s.read(p, 8);
        if (b.size() < 8) return -1;
        if (b[0] != 0x7F || b[1] != 0xFE || b[2] != 0x80 || b[3] != 0x01) break;
        i64 fsize = ((((i64)b[3] << 8) | b[4]) >> 2) & 0x3FFF;
        i64 size = (fsize + 1) * 2;
        if (size < 16 || size > 4 * MB) return -1;
        if (p + size > off + max) return -1;
        p += size;
        frames++;
    }
    if (frames == 0) return -1;
    return p - off;
}void registerFmt_dts(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("DTS", "dts", "audio", B({0x7F,0xFE,0x80,0x01}), 1*GB, SizeMode::Container, vDts));
}

}  // namespace ghost

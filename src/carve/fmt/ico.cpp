// GHOST RECOVER — ico signature family (one file per format).
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

i64 vIco(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 type = s.le16(off + 2);
    u16 count = s.le16(off + 4);
    if ((type != 1 && type != 2) || count == 0 || count > 64) return -1;
    const i64 dirEnd = 6 + (i64)count * 16;
    i64 furthest = dirEnd;
    for (u16 i = 0; i < count; i++) {
        i64 e = off + 6 + (i64)i * 16;
        u8 w = s.byte(e), h = s.byte(e + 1);
        u8 planes = s.byte(e + 4);
        u32 bytes = s.le32(e + 8);
        u32 imgOff = s.le32(e + 12);
        // Dimensions are 0 (meaning 256) or a real pixel count, colour
        // planes are 0 or 1, and image data must follow the directory.
        if (planes > 1 && type == 1) return -1;
        if (bytes < 16 || bytes > 16 * 1024 * 1024) return -1;
        if ((i64)imgOff < dirEnd) return -1;
        if ((i64)imgOff + bytes > max) return -1;
        // Each entry points at either a BMP info header (40) or a PNG stream.
        u32 hdr = s.le32(off + (i64)imgOff);
        auto sig = s.read(off + (i64)imgOff, 4);
        bool isPng = sig.size() == 4 && sig[0] == 0x89 && sig[1] == 'P';
        if (hdr != 40 && hdr != 108 && hdr != 124 && !isPng) return -1;
        furthest = std::max<i64>(furthest, (i64)imgOff + bytes);
    }
    return furthest <= max ? furthest : -1;
}void registerFmt_ico(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ICO", "ico", "image", B({0x00,0x00,0x01,0x00}), 16*MB, SizeMode::Header, vIco);
      c.min_size = 64; add(c); }
    { auto c = mk("CUR", "cur", "image", B({0x00,0x00,0x02,0x00}), 16*MB, SizeMode::Header, vIco);
      c.min_size = 64; add(c); }
}

}  // namespace ghost

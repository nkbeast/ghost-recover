// GHOST RECOVER — pcx signature family (one file per format).
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

i64 vPcx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 end = off + 128;
    if (end > off + max) return -1;
    u8 bpp = s.byte(off + 3);
    u8 planes = s.byte(off + 65);
    u16 bytesPerLine = s.le16(off + 66);
    u16 xmax = s.le16(off + 8), ymax = s.le16(off + 10);
    u16 xmin = s.le16(off + 4), ymin = s.le16(off + 6);
    if (xmax < xmin || ymax < ymin) return -1;
    if (bpp != 1 && bpp != 2 && bpp != 4 && bpp != 8 && bpp != 24) return -1;
    if (planes == 0 || planes > 4) return -1;
    if (bytesPerLine == 0 || bytesPerLine > 0x7FFF) return -1;
    u64 lines = (u64)(ymax - ymin) + 1;
    // Decoded units = rows x bytes-per-row x planes. RLE data expands to that
    // count; walk the RLE stream over the exact byte count. A 256-color
    // palette (0x0C + 768) may follow.
    u64 units = lines * (u64)bytesPerLine * planes;
    i64 p = end;
    bool any = false;
    for (u64 u = 0; u < units; u++) {
        if (p >= off + max) return -1;
        u8 c = s.byte(p++);
        if (c & 0xC0) {
            if (p >= off + max) return -1;
            p++;                                    // one run value byte
            u += (u64)(c & 0x3F) - 1;
            if (u >= units) break;
        }
        any = true;
    }
    if (!any) return -1;
    // 8-bit single-plane images end with a 768-byte VGA palette preceded by
    // the 0x0C marker.
    if (bpp == 8 && planes == 1 && s.byte(p) == 0x0C) {
        if (p + 769 > off + max) return -1;
        p += 769;
    }
    return (p <= off + max) ? p - off : -1;
}void registerFmt_pcx(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PCX", "pcx", "image", B({0x0A,0x05,0x01,0x08}), 64*MB, SizeMode::Container, vPcx);
      add(c); }
}

}  // namespace ghost

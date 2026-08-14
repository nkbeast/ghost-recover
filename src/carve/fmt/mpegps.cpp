// GHOST RECOVER — mpegps signature family (one file per format).
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

i64 vMpegPs(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off;
    int packs = 0;
    while (p + 14 <= off + max && packs < 4000000) {
        auto h = s.read(p, 14);
        if (h.size() < 14) break;
        if (h[0] || h[1] || h[2] != 1) break;
        u8 id = h[3];
        if (id == 0xBA) {                          // pack header
            if ((h[4] & 0xC0) == 0x40) {           // MPEG-2
                u8 stuffing = h[13] & 7;
                p += 14 + stuffing;
            } else {
                p += 12;                           // MPEG-1
            }
            packs++;
            continue;
        }
        if (id == 0xB9) { p += 4; break; }         // end code
        u16 len = s.be16(p + 4);
        if (len == 0) break;
        p += 6 + len;
        packs++;
    }
    if (packs < 4) return -1;
    return p - off;
}void registerFmt_mpegps(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MPEG_PS", "mpg", "video", B({0x00,0x00,0x01,0xBA}), 8*GB,
                  SizeMode::FrameStream, vMpegPs); c.min_size = 2048; add(c); }
}

}  // namespace ghost

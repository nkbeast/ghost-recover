// GHOST RECOVER — mpegves signature family (one file per format).
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

i64 vMpegVes(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 12);
    if (h.size() < 12 || h[0] || h[1] || h[2] != 1 || h[3] != 0xB3) return -1;
    u32 w = (u32)h[4] << 4 | h[5] >> 4;
    u32 ht = (u32)h[6] << 4 | h[7] >> 4;
    if (w < 8 || w > 16384 || ht < 8 || ht > 16384) return -1;
    if ((h[5] & 0xF) > 14) return -1;              // aspect ratio code
    if ((h[7] & 0xF) == 0) return -1;              // frame rate code 0 = forbidden
    i64 end = off + max;
    i64 q = off + 12;
    int total = 0, slices = 0;
    while (q + 4 <= end) {
        int zrun = 0;
        i64 zstart = -1;
        while (q + 4 <= end) {
            if (s.byte(q) == 0) { if (zstart < 0) zstart = q; zrun++; }
            else { zrun = 0; zstart = -1; }
            if (zrun >= 256) return zstart - off;  // dead space / probe pad
            if (s.byte(q) == 0 && s.byte(q + 1) == 0 && s.byte(q + 2) == 1) break;
            q++;
        }
        if (q + 4 > end) break;
        u8 id = s.byte(q + 3);
        if (id >= 0x01 && id <= 0xAF) slices++;    // slice
        else total++;
        if (id == 0xB7) return (q + 4) - off;      // sequence end code
        if (id == 0x00 || id == 0xB3 || id == 0xB5 || id == 0xB8 || (id >= 0x01 && id <= 0xAF)) {
            q += 4;
            continue;
        }
        break;
    }
    if (slices < 2 || total + slices < 6) return -1;
    return q - off;
}void registerFmt_mpegves(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MPEG_VES", "mpv", "video", B({0x00,0x00,0x01,0xB3}), 4*GB,
                  SizeMode::FrameStream, vMpegVes); c.min_size = 2048; add(c); }
}

}  // namespace ghost

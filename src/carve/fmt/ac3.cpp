// GHOST RECOVER — ac3 signature family (one file per format).
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

i64 vAc3(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // frmsizecod -> frame size in 16-bit words, per sample rate.
    static const u16 kFrameSizes[38][3] = {
        {64,69,96},{64,70,96},{80,87,120},{80,88,120},{96,104,144},{96,105,144},
        {112,121,168},{112,122,168},{128,139,192},{128,140,192},{160,174,240},{160,175,240},
        {192,208,288},{192,209,288},{224,243,336},{224,244,336},{256,278,384},{256,279,384},
        {320,348,480},{320,349,480},{384,417,576},{384,418,576},{448,487,672},{448,488,672},
        {512,557,768},{512,558,768},{640,696,960},{640,697,960},{768,835,1152},{768,836,1152},
        {896,975,1344},{896,976,1344},{1024,1114,1536},{1024,1115,1536},
        {1152,1253,1728},{1152,1254,1728},{1280,1393,1920},{1280,1394,1920}
    };
    i64 p = off, lastEnd = off;
    int frames = 0, fscod0 = -1;
    int consecResync = 0;
    const i64 kResync = 32 * 1024;
    while (p + 6 <= off + max && frames < 2000000) {
        auto h = s.read(p, 6);
        if (h.size() < 6 || h[0] != 0x0B || h[1] != 0x77) {
            // Overwritten region: resync like vMp3/vAac instead of
            // fragmenting the file at the first bad frame.
            if (frames == 0) break;
            const i64 scanEnd = std::min<i64>(off + max, p + kResync);
            auto win = s.read(p, scanEnd - p);
            bool found = false;
            for (i64 i = 0; i + 6 <= (i64)win.size(); i++) {
                if (win[(size_t)i] != 0x0B || win[(size_t)(i + 1)] != 0x77) continue;
                int f2 = (win[(size_t)(i + 4)] >> 6) & 3;
                int fs2 = win[(size_t)(i + 4)] & 0x3F;
                if (f2 != fscod0 || f2 == 3 || fs2 > 37) continue;
                i64 sz2 = (i64)kFrameSizes[fs2][f2] * 2;
                if (p + i + sz2 <= off + max) { p += i; found = true; break; }
            }
            if (!found) break;
            if (++consecResync >= 4) break;
            continue;
        }
        int fscod = (h[4] >> 6) & 3;
        int frmsizecod = h[4] & 0x3F;
        if (fscod == 3 || frmsizecod > 37) break;
        if (frames == 0) fscod0 = fscod;
        else if (fscod != fscod0) break;
        i64 size = (i64)kFrameSizes[frmsizecod][fscod] * 2;
        if (p + size > off + max) break;
        lastEnd = p + size;
        p = lastEnd;
        frames++;
        consecResync = 0;
    }
    if (frames < 4) return -1;
    return lastEnd - off;
}void registerFmt_ac3(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("AC3", "ac3", "audio", B({0x0B,0x77}), 1*GB, SizeMode::FrameStream, vAc3);
      c.min_size = 4096; add(c); }
}

}  // namespace ghost

// GHOST RECOVER — amr signature family (one file per format).
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

i64 vAmr(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 9);
    bool wb = h.size() >= 9 && std::memcmp(h.data(), "#!AMR-WB\n", 9) == 0;
    i64 p = off + (wb ? 9 : 6);
    static const int kNb[16] = {12,13,15,17,19,20,26,31,5,0,0,0,0,0,0,0};
    static const int kWb[16] = {17,23,32,36,40,46,50,58,60,5,0,0,0,0,0,0};
    int frames = 0;
    bool real = false;   // any non-zero frame TOC seen so far
    int consecResync = 0;
    const i64 kResync = 8 * 1024;
    while (p < off + max && frames < 2000000) {
        u8 toc = s.byte(p);
        int mode = (toc >> 3) & 0xF;
        // NO_DATA (mode 15) terminates most streams. A run of all-zero frame
        // units after at least four real, non-zero frames is padding (files
        // are padded with zeroes to 20 ms / 40 ms boundaries or with whole
        // dropped frames); a stream that is zero frames throughout (a synth
        // silence file like sox's) must still be walked to its end.
        u8 b1 = s.byte(p + 1), b2 = s.byte(p + 2), b3 = s.byte(p + 3);
        if (mode == 15) { p += 1; break; }   // NO_DATA terminator, 1-byte TOC only
        if (toc != 0) real = true;
        if (real && frames >= 4 && toc == 0 && b1 == 0 && b2 == 0 && b3 == 0) break;
        int sz = wb ? kWb[mode] : kNb[mode];
        if (sz == 0) {
            // Invalid/future frame mode: overwritten region. Resync over a
            // bounded window (same rationale as vMp3/vAac/vAc3).
            if (frames < 4) break;
            const i64 scanEnd = std::min<i64>(off + max, p + kResync);
            auto win = s.read(p, scanEnd - p);
            bool found = false;
            for (i64 i = 0; i < (i64)win.size(); i++) {
                int m2 = (win[(size_t)i] >> 3) & 0xF;
                int s2 = wb ? kWb[m2] : kNb[m2];
                if (m2 < 15 && s2 > 0) { p += i; found = true; break; }
            }
            if (!found) break;
            if (++consecResync >= 4) break;
            continue;
        }
        p += 1 + sz;
        frames++;
        consecResync = 0;
    }
    if (frames < 4) return -1;
    return p - off;
}void registerFmt_amr(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("AMR", "amr", "audio", S("#!AMR\n"), 256*MB, SizeMode::FrameStream, vAmr);
      c.min_size = 32; add(c); }
    { auto c = mk("AMR_WB", "amr", "audio", S("#!AMR-WB\n"), 256*MB, SizeMode::FrameStream, vAmr);
      c.min_size = 32; c.priority = 5; add(c); }
}

}  // namespace ghost

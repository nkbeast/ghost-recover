// GHOST RECOVER — aac signature family (one file per format).
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

i64 vAac(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int frames = 0, sr0 = -1, prof0 = -1, h1_0 = -1;
    int consecResync = 0;
    const i64 kResync = 32 * 1024;
    while (p + 7 <= off + max && frames < 4000000) {
        auto h = s.read(p, 7);
        if (h.size() < 7 || h[0] != 0xFF || (h[1] & 0xF0) != 0xF0) break;
        u32 len = ((u32)(h[3] & 0x03) << 11) | ((u32)h[4] << 3) | ((u32)(h[5] >> 5) & 7);
        if (len < 7 || len > 8192) break;
        int sr = (h[2] >> 2) & 0xF;
        int prof = (h[2] >> 6) & 3;
        if (sr > 12) break;
        if (frames == 0) { sr0 = sr; prof0 = prof; h1_0 = h[1]; }
        else if (sr != sr0 || prof != prof0 || h[1] != h1_0) break;
        if (p + (i64)len > off + max) break;
        lastEnd = p + len;
        p = lastEnd;
        frames++;
        consecResync = 0;
        if (frames < 4) continue;
        // Peek the next frame header; if it is not a valid frame of the same
        // layout, the bytes in between were overwritten. Resync over a bounded
        // window instead of fragmenting the file at the first bad byte
        // (deleted files are usually overwritten in cluster-sized chunks).
        auto nxt = s.read(p, 7);
        bool gap = nxt.size() < 7;
        if (!gap) {
            u32 len2 = ((u32)(nxt[3] & 0x03) << 11) | ((u32)nxt[4] << 3) |
                       ((u32)(nxt[5] >> 5) & 7);
            int sr2 = (nxt[2] >> 2) & 0xF;
            int prof2 = (nxt[2] >> 6) & 3;
            gap = nxt[0] != 0xFF || (nxt[1] & 0xF0) != 0xF0 || nxt[1] != h1_0 ||
                  len2 < 7 || len2 > 8192 || sr2 != sr0 || prof2 != prof0;
        }
        if (gap) {
            const i64 scanEnd = std::min<i64>(off + max, p + kResync);
            auto win = s.read(p, scanEnd - p);
            bool found = false;
            for (i64 i = 0; i + 7 <= (i64)win.size(); i++) {
                if (win[(size_t)i] != 0xFF || (win[(size_t)(i + 1)] & 0xF0) != 0xF0 ||
                    win[(size_t)(i + 1)] != h1_0) continue;
                u32 l2 = ((u32)(win[(size_t)(i + 3)] & 0x03) << 11) |
                         ((u32)win[(size_t)(i + 4)] << 3) | ((u32)(win[(size_t)(i + 5)] >> 5) & 7);
                if (l2 < 7 || l2 > 8192) continue;
                int s2 = (win[(size_t)(i + 2)] >> 2) & 0xF;
                int pf2 = (win[(size_t)(i + 2)] >> 6) & 3;
                if (s2 > 12 || s2 != sr0 || pf2 != prof0) continue;
                i64 nxt = i + (i64)l2;
                if (nxt + 7 > (i64)win.size()) break;
                if (win[(size_t)nxt] != 0xFF || (win[(size_t)(nxt + 1)] & 0xF0) != 0xF0) continue;
                u32 l3 = ((u32)(win[(size_t)(nxt + 3)] & 0x03) << 11) |
                         ((u32)win[(size_t)(nxt + 4)] << 3) | ((u32)(win[(size_t)(nxt + 5)] >> 5) & 7);
                if (l3 < 7 || l3 > 8192) continue;
                int s3 = (win[(size_t)(nxt + 2)] >> 2) & 0xF;
                int pf3 = (win[(size_t)(nxt + 2)] >> 6) & 3;
                if (s3 != sr0 || pf3 != prof0) continue;
                if (p + i + (i64)l2 <= off + max) { p += i; found = true; break; }
            }
            if (!found) break;
            if (++consecResync >= 4) break;
        }
    }
    if (frames < 4) return -1;
    return lastEnd - off;
}void registerFmt_aac(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("AAC", "aac", "audio", B({0xFF,0xF1}), 1*GB, SizeMode::FrameStream, vAac);
      c.min_size = 2048; add(c); }
    { auto c = mk("AAC_MPEG2", "aac", "audio", B({0xFF,0xF9}), 1*GB, SizeMode::FrameStream, vAac);
      c.min_size = 2048; add(c); }
}

}  // namespace ghost

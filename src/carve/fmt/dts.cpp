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
    auto h = s.read(off, 8);
    if (h.size() < 8) return -1;
    if (h[0] != 0x7F || h[1] != 0xFE || h[2] != 0x80 || h[3] != 0x01) return -1;
    i64 c1 = ((i64)(h[3] & 0x01) << 6) | (h[4] >> 2);        // bytes: ffmpeg dst
    i64 c2 = ((i64)(h[4] & 0x3F) << 8) | h[5];               // spec 32..45
    struct Chain { i64 len; int frames; };
    auto walk = [&](i64 field) -> Chain {
        Chain bad = {-1, 0};
        i64 size = (field + 1) * 2;                          // 16-bit words
        if (field == 0 || size < 16 || size > 4 * MB) return bad;
        i64 p = off;
        int frames = 0;
        while (p + 8 <= off + max && frames < 1000000) {
            auto b = s.read(p, 8);
            if (b.size() < 8 || b[0] != 0x7F || b[1] != 0xFE ||
                b[2] != 0x80 || b[3] != 0x01) break;
            i64 f = ((i64)(b[3] & 0x01) << 6) | (b[4] >> 2);
            size = (f + 1) * 2;
            if (size < 16 || size > 4 * MB) return bad;
            p += size;
            frames++;
            if (p > off + max) return bad;
        }
        if (frames == 0) return bad;
        return {p - off, frames};
    };
    Chain a = walk(c1), b = walk(c2);
    bool aOk = a.len >= 0, bOk = b.len >= 0;
    if (!aOk && !bOk) return -1;
    if (!aOk) return b.len;
    if (!bOk) return a.len;
    // A longer frame chain is the real file; a stray candidate usually stops
    // after one frame. Ties go to the chain that fills the region exactly.
    if (a.frames != b.frames) return (a.frames > b.frames) ? a.len : b.len;
    if (a.len == max || b.len == max) return (a.len == max) ? a.len : b.len;
    return std::max(a.len, b.len);
}void registerFmt_dts(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("DTS", "dts", "audio", B({0x7F,0xFE,0x80,0x01}), 1*GB, SizeMode::Container, vDts));
}

}  // namespace ghost

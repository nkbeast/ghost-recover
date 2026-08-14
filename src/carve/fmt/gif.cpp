// GHOST RECOVER — gif signature family (one file per format).
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

i64 vGif(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    const u8 packed = s.byte(off + 10);
    i64 p = off + 13;
    if (packed & 0x80) p += 3LL * (1 << ((packed & 0x07) + 1));   // global colour table
    int guard = 0;
    while (p < off + max && guard++ < 100000) {
        u8 b = s.byte(p);
        if (b == 0x3B) return (p + 1) - off;                      // trailer
        if (b == 0x21) {                                          // extension
            p += 2;
            while (p < off + max) {
                u8 sz = s.byte(p);
                p += 1 + sz;
                if (sz == 0) break;
            }
            continue;
        }
        if (b == 0x2C) {                                          // image descriptor
            u8 lp = s.byte(p + 9);
            p += 10;
            if (lp & 0x80) p += 3LL * (1 << ((lp & 0x07) + 1));
            p += 1;                                               // LZW min code size
            while (p < off + max) {
                u8 sz = s.byte(p);
                p += 1 + sz;
                if (sz == 0) break;
            }
            continue;
        }
        return -1;
    }
    return -1;
}void registerFmt_gif(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("GIF89a", "gif", "image", S("GIF89a"), 256*MB, SizeMode::Container, vGif);
      c.min_size = 30; add(c); }
    { auto c = mk("GIF87a", "gif", "image", S("GIF87a"), 256*MB, SizeMode::Container, vGif);
      c.min_size = 30; add(c); }
}

}  // namespace ghost

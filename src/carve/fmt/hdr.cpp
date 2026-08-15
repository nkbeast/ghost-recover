// GHOST RECOVER — hdr signature family (one file per format).
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

i64 vHdr(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto head = s.read(off, std::min<i64>(max, 4096));
    if (head.size() < 32) return -1;
    std::string text((const char*)head.data(), head.size());
    size_t pos = text.find("-Y ");
    size_t xp = (pos == std::string::npos) ? std::string::npos : text.find("+X ", pos);
    if (xp == std::string::npos) return -1;
    int h = (int)std::strtol(text.c_str() + pos + 3, nullptr, 10);
    int w = (int)std::strtol(text.c_str() + xp + 3, nullptr, 10);
    if (h < 1 || h > 16384 || w < 1 || w > 16384) return -1;
    size_t nl = text.find('\n', xp);
    if (nl == std::string::npos) return -1;
    i64 p = off + (i64)nl + 1;
    for (int r = 0; r < h; r++) {
        if (p + 4 > off + max) return -1;
        // New-style RLE scanline: 0x02 0x02 then the BE16 scanline width,
        // which must match the header width.
        if (s.byte(p) != 0x02 || s.byte(p + 1) != 0x02 || s.be16(p + 2) != w) return -1;
        p += 4;
        int out = 0;
        const int need = 4 * w;               // 4 components per pixel
        while (out < need) {
            if (p >= off + max) return -1;
            u8 b = s.byte(p++);
            if (b < 128) { out++; }           // literal component
            else { int n = b & 0x7F; out += n; p += n; }
            if (out > need || p > off + max) return -1;
        }
    }
    return p - off;
}void registerFmt_hdr(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("HDR", "hdr", "image", S("#?RADIANCE"), 256*MB, SizeMode::Header, vHdr));
}

}  // namespace ghost

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
        if (p + 5 > off + max) return -1;
        if (s.byte(p) != 0x02 || s.byte(p + 1) != 0x02 || s.be16(p + 2) != 1) return -1;
        if ((int)s.byte(p + 4) != w) return -1;
        p += 5 + 4 * (i64)w;
    }
    return p - off;
}void registerFmt_hdr(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("HDR", "hdr", "image", S("#?RADIANCE"), 256*MB, SizeMode::Header, vHdr));
}

}  // namespace ghost

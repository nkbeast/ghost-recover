// GHOST RECOVER — XPM image signatures.
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

i64 vXpm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off;
    i64 end = -1;
    const i64 kStep = 64 * KB;
    while (p < off + max && end < 0) {
        auto buf = s.read(p, std::min(kStep, off + max - p));
        if (buf.empty()) break;
        for (size_t i = 0; i + 1 < buf.size(); i++) {
            if (buf[i] == '}' && buf[i + 1] == ';') { end = p + (i64)i + 2; break; }
        }
        i64 adv = (i64)buf.size() - 1;                   // rescan the seam
        if (adv <= 0) break;
        p += adv;
    }
    if (end < 0) return -1;
    while (end < off + max) {
        u8 c = s.byte(end);
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        end++;
    }
    return end - off;
}

void registerFmt_xpm(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("XPM", "xpm", "image", B({0x2F, 0x2A, 0x20, 0x58, 0x50, 0x4D, 0x20, 0x2A, 0x2F}), 16*MB, SizeMode::Container, vXpm); c.min_size = 64; add(c); }
}

}  // namespace ghost

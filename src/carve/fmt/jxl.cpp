// GHOST RECOVER — jxl signature family (one file per format).
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

i64 vJxl(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 7);
    if (h.size() < 7) return -1;
    if (h[0] != 0xFF || h[1] != 0x0A) return -1;
    u32 len = ((u32)h[2] << 24) | ((u32)h[3] << 16) | ((u32)h[4] << 8) | (u32)h[5];
    if (len < 8 || len > max - 6) return -1;
    // A conforming codestream opens with a zero byte (entropy-coded layer
    // header); random data fails this almost always.
    if (h[6] != 0x00) return -1;
    return 6 + (i64)len;
}void registerFmt_jxl(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("JXL", "jxl", "image", B({0xFF,0x0A}), 256*MB, SizeMode::Header, vJxl));
}

}  // namespace ghost

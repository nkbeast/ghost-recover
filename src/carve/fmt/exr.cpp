// GHOST RECOVER — exr signature family (one file per format).
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

i64 vExr(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.le32(off + 4);
    if ((ver & 0xFF) != 2) return -1;                          // file version 2
    i64 p = off + 8;
    i64 yMax = -1;
    for (int guard = 0; guard < (1 << 16); guard++) {
        if (p + 2 > off + max) return -1;
        i64 nLen = 0;
        while (s.byte(p + nLen) != 0) { if (++nLen > 256) return -1; }
        if (nLen == 0) break;                                  // end of attrs
        i64 tLen = 0;
        while (s.byte(p + nLen + 1 + tLen) != 0) { if (++tLen > 64) return -1; }
        u32 sz = s.le32(p + nLen + 1 + tLen + 1);
        if (sz > 16 * 1024 * 1024) return -1;
        auto name = s.read(p, nLen);
        if (name.size() == (size_t)nLen && nLen == 10 &&
            std::memcmp(name.data(), "dataWindow", 10) == 0) {
            auto v = s.read(p + nLen + 1 + tLen + 1 + 4, 16);
            if (v.size() >= 16)                                // box2i: x y x y
                yMax = (i64)((u32)v[12] | (u32)v[13] << 8 | (u32)v[14] << 16 | (u32)v[15] << 24);
        }
        p += nLen + 1 + tLen + 1 + 4 + sz;
    }
    if (yMax < 0 || yMax > (1 << 20)) return -1;
    for (int rows = 0; rows < (1 << 24); rows++) {
        i64 y = (i64)s.le32(p);
        u32 size = s.le32(p + 4);
        if (y < 0 || y > yMax || size == 0 || p + 8 + (i64)size > off + max) return -1;
        p += 8 + size;
        if (y == yMax) return p - off;
    }
    return -1;
}void registerFmt_exr(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("EXR", "exr", "image", B({0x76,0x2F,0x31,0x01}), 512*MB, SizeMode::Header, vExr));
}

}  // namespace ghost

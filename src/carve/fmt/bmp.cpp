// GHOST RECOVER — bmp signature family (one file per format).
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

i64 vBmp(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 size = s.le32(off + 2);
    u32 dataOff = s.le32(off + 10);
    u32 dibSize = s.le32(off + 14);
    if (dibSize != 12 && dibSize != 40 && dibSize != 52 && dibSize != 56 &&
        dibSize != 64 && dibSize != 108 && dibSize != 124) return -1;
    if (dataOff < 14 + dibSize) return -1;
    if (size < dataOff || (i64)size > max) return -1;
    return size;
}void registerFmt_bmp(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("BMP", "bmp", "image", B({'B','M'}), 512*MB, SizeMode::Header, vBmp);
      c.min_size = 54; add(c); }
}

}  // namespace ghost

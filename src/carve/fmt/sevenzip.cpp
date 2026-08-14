// GHOST RECOVER — sevenzip signature family (one file per format).
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

i64 v7z(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 32);
    if (h.size() < 32) return -1;
    u64 nextHeaderOffset = 0, nextHeaderSize = 0;
    for (int i = 0; i < 8; i++) nextHeaderOffset |= (u64)h[12 + i] << (i * 8);
    for (int i = 0; i < 8; i++) nextHeaderSize |= (u64)h[20 + i] << (i * 8);
    i64 total = 32 + (i64)nextHeaderOffset + (i64)nextHeaderSize;
    if (total < 32 || total > max) return -1;
    return total;
}void registerFmt_sevenzip(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("7Z", "7z", "archive", B({'7','z',0xBC,0xAF,0x27,0x1C}), 8*GB,
                  SizeMode::Header, v7z); c.min_size = 32; add(c); }
}

}  // namespace ghost

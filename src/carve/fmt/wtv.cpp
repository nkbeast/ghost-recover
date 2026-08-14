// GHOST RECOVER — WTV video signatures.
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

i64 vWtv(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 24 > off + max) return -1;
    auto h = s.read(off, 24);
    if (h.size() < 24) return -1;
    u64 size = 0;
    for (int i = 0; i < 8; i++) size |= (u64)h[16 + i] << (i * 8);
    if (size < 0x100) return -1;
    if ((i64)size > max) return -1;
    return (i64)size;
}

void registerFmt_wtv(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("WTV", "wtv", "video", B({0xB7, 0xD8, 0x00, 0x20, 0x37, 0x49, 0xDA, 0x11, 0xA6, 0x4E, 0x00, 0x07, 0xE9, 0x5E, 0xAD, 0x8D}), 64*GB, SizeMode::Container, vWtv); c.min_size = 24; add(c); }
}

}  // namespace ghost

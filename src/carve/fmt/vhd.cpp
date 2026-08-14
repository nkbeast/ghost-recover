// GHOST RECOVER — vhd signature family (one file per format).
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

i64 vVhd(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 512 + 512) return -1;
    i64 scanEnd = std::min<i64>(max, 512LL * 1024 * 1024);
    i64 pos = 512;
    while (pos + 512 <= scanEnd) {
        auto b = s.read(off + pos, 16);
        if (b.size() < 8) break;
        bool isFooter = std::memcmp(b.data(), "conectix", 8) == 0;
        if (isFooter) {
            // File format version: footer bytes 12..15 = 0x00010000.
            u16 hi = (u16)(s.byte(off + pos + 12) << 8 | s.byte(off + pos + 13));
            if (hi == 0x0001) {
                i64 fileSize = pos + 512;
                if (fileSize > max) return -1;
                return fileSize;
            }
        }
        pos += 512;
    }
    return -1;
}void registerFmt_vhd(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("VHD", "vhd", "vm", S("conectix"), 64*GB,
                  SizeMode::Footer, vVhd); c.min_size = 1024; add(c); }
}

}  // namespace ghost

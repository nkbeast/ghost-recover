// GHOST RECOVER — pe signature family (one file per format).
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

i64 vPe(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 lfanew = s.le32(off + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x10000) return -1;
    auto sig = s.read(off + lfanew, 4);
    if (sig.size() < 4 || sig[0] != 'P' || sig[1] != 'E' || sig[2] || sig[3]) return -1;
    i64 pe = (i64)lfanew;
    u16 sections = s.le16(off + pe + 6);
    u16 optSize = s.le16(off + pe + 20);
    if (sections == 0 || sections > 4096) return -1;
    i64 table = pe + 24 + optSize;
    i64 furthest = table + (i64)sections * 40;
    for (u16 i = 0; i < sections; i++) {
        i64 e = table + (i64)i * 40;
        if (e + 40 > max) return -1;
        u32 rawSize = s.le32(off + e + 16);
        u32 rawPtr  = s.le32(off + e + 20);
        if (rawPtr && rawSize) furthest = std::max<i64>(furthest, (i64)rawPtr + rawSize);
    }
    if (furthest > max) return -1;
    return furthest;
}void registerFmt_pe(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PE", "exe", "executable", B({'M','Z'}), 2*GB, SizeMode::Header, vPe);
      c.min_size = 512; add(c); }
}

}  // namespace ghost

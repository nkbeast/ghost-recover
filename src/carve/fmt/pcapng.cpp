// GHOST RECOVER — pcapng signature family (one file per format).
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

i64 vPcapng(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 bom = s.le32(off + 8);
    bool swapped = (bom == 0x4D3C2B1A);
    auto rd32 = [&](i64 o) { return swapped ? s.be32(off + o) : s.le32(off + o); };
    if (bom != 0x1A2B3C4D && bom != 0x4D3C2B1A) return -1;
    i64 p = 0;
    int blocks = 0;
    while (p + 12 <= max && blocks < 10000000) {
        u32 total = rd32(p + 4);
        if (total < 12 || (total & 3) || p + (i64)total > max) break;
        p += total;
        blocks++;
    }
    if (blocks < 1) return -1;
    return p;
}void registerFmt_pcapng(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PCAPNG", "pcapng", "forensic", B({0x0A,0x0D,0x0D,0x0A}), 8*GB,
                  SizeMode::Container, vPcapng); c.min_size = 28; add(c); }
}

}  // namespace ghost

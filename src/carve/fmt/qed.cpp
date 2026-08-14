// GHOST RECOVER — QED vm signatures.
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

i64 vQed(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 16 > off + max) return -1;
    auto h = s.read(off, 16);
    if (h.size() < 16) return -1;
    u32 cluster = 0, tableSize = 0, headerSize = 0;
    for (int i = 0; i < 4; i++) {
        cluster |= (u32)h[4 + i] << (i * 8);
        tableSize |= (u32)h[8 + i] << (i * 8);
        headerSize |= (u32)h[12 + i] << (i * 8);
    }
    if (cluster < 512 || cluster > 0x400000) return -1;
    if (tableSize == 0 || tableSize % 8 != 0) return -1;
    if (headerSize < 64 || headerSize > 0x100000) return -1;
    // The L1 table starts at the next cluster boundary after the header.
    auto align = [&](i64 x) { return ((x + cluster - 1) / cluster) * cluster; };
    i64 total = align((i64)headerSize) + tableSize;
    if (total > max) return -1;
    return total;
}

void registerFmt_qed(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("QED", "qed", "vm", B({0x51, 0x45, 0x44, 0x00}), 64*GB, SizeMode::Container, vQed); c.min_size = 16; add(c); }
}

}  // namespace ghost

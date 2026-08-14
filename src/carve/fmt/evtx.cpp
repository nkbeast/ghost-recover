// GHOST RECOVER — evtx signature family (one file per format).
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

i64 vEvtx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 hdrSize = s.le16(off + 0x28);
    if (hdrSize < 4096) return -1;
    u16 chunkCount = s.le16(off + 0x2A);
    if (chunkCount == 0) return -1;
    i64 total = (i64)hdrSize + (i64)chunkCount * 65536;
    if (total > max) return -1;
    auto c0 = s.read(off + hdrSize, 8);
    if (c0.size() < 8 || c0[0] != 'E' || c0[1] != 'l' || c0[2] != 'f'
        || c0[3] != 'C' || c0[4] != 'h' || c0[5] != 'n' || c0[6] != 'k') return -1;
    return total;
}void registerFmt_evtx(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("EVTX", "evtx", "forensic", S("ElfFile\0"), 4*GB, SizeMode::Header, vEvtx);
      c.min_size = 4096; add(c); }
}

}  // namespace ghost

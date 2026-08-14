// GHOST RECOVER — lzma signature family (one file per format).
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

i64 vLzmaAlone(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 29) return -1;
    u8 props = s.byte(off);
    u32 dict = s.le32(off + 1);
    u64 usize = 0;
    for (int k = 0; k < 8; k++) usize |= (u64)s.byte(off + 5 + k) << (8 * k);
    i64 lc = props % 9, lp = (props / 9) % 5, pb = props / 45;
    if (lc + lp > 4 || pb > 4) return -1;         // LZMA SDK/xz parameter range
    if (dict < 4096 || dict > (u32)(1 << 30)) return -1;
    if (usize == 0) return -1;                    // empty stream: pointless
    if (usize != 0xFFFFFFFFFFFFFFFFull && usize > (4ull << 30)) return -1;
    return 0;   // valid header: length unknown, clamp to the next signature
}void registerFmt_lzma(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("LZMA_ALONE", "lzma", "archive", B({0x5D,0x00,0x00}), 8*GB, SizeMode::Heuristic, vLzmaAlone);
      c.min_size = 29; add(c); }
}

}  // namespace ghost

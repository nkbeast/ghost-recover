// GHOST RECOVER — mpc signature family (one file per format).
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

i64 vMpc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 16) return -1;
    if (s.byte(off) == 'M' && s.byte(off + 1) == 'P' && s.byte(off + 2) == 'C' &&
        s.byte(off + 3) == 'K') {
        i64 size = (i64)s.le32(off + 8);
        if (size < 12 || size > max) return -1;
        return size;
    }
    if (s.byte(off + 3) != 0x07) return -1;
    i64 size = (i64)s.be32(off + 4);
    if (size < 16 || size > max) return -1;
    return size;
}void registerFmt_mpc(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MPC", "mpc", "audio", S("MPCK"), 512*MB, SizeMode::Header, vMpc);
      c.min_size = 32; add(c); }
    { auto c = mk("MPC_SV7", "mpc", "audio", S("MP+"), 512*MB, SizeMode::Header, vMpc);
      c.min_size = 32; add(c); }
}

}  // namespace ghost

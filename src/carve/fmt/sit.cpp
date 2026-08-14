// GHOST RECOVER — sit signature family (one file per format).
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

i64 vSit(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.byte(off + 82) != 0x05) return -1;                   // version byte
    i64 p = off + 91;
    for (int guard = 0; guard < (1 << 20); guard++) {
        if (p + 5 > off + max) return -1;
        u8 n = s.byte(p);
        if (n == 0) return p - off;                            // end of archive
        if (p + 1 + n + 4 > off + max) return -1;
        u32 len = s.le32(p + 1 + n);
        if (p + 1 + n + 4 + len > off + max) return -1;
        p += 1 + n + 4 + len;
    }
    return -1;
}void registerFmt_sit(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("SIT", "sit", "archive", S("StuffIt"), 512*MB, SizeMode::Header, vSit));
}

}  // namespace ghost

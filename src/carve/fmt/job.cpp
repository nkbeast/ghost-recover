// GHOST RECOVER — job signature family (one file per format).
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

i64 vJob(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 product = s.le16(off + 4);
    u16 version = s.le16(off + 6);
    if (product < 1 || product > 2 || version < 1 || version > 4) return -1;
    i64 p = off + 0x3C;
    while (p + 4 <= off + max) {
        u32 z = s.le32(p);
        if (z == 0) return p + 4 - off;
        if (p - off > max) return -1;
        p++;
    }
    return -1;
}void registerFmt_job(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("JOB", "job", "forensic", B({0x01,0x05,0x01,0x00}), 4*MB, SizeMode::Header, vJob));
}

}  // namespace ghost

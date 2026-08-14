// GHOST RECOVER — dmg signature family (one file per format).
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

i64 vDmg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off) != 0x6B6F6C79) return -1;                  // koly
    if (s.be32(off + 4) != 4) return -1;                       // version
    if (s.be32(off + 8) != 512) return -1;                     // header size
    if (s.be32(off + 12) != 1) return -1;                      // flags
    i64 dataLen = (i64)s.be64(off + 40);                       // data fork length
    if (dataLen <= 0 || dataLen >= off) return -1;
    if (dataLen + 512 > max) return -1;
    s.setBackscan(dataLen);
    return 512;
}void registerFmt_dmg(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("DMG_KOLY", "dmg", "archive", S("koly"), 16*GB, SizeMode::Header, vDmg));
}

}  // namespace ghost

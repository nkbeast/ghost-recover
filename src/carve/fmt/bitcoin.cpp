// GHOST RECOVER — bitcoin signature family (one file per format).
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

i64 vBdb(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 8) != 0x00053162) return -1;              // DB magic
    u32 pageSize = s.le32(off + 16);
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0) return -1;
    if (s.byte(off + 20) != 1) return -1;                      // meta page
    u32 lastPgno = s.le32(off + 26);
    if (lastPgno > 1000000) return -1;
    i64 total = ((i64)lastPgno + 1) * pageSize;
    return (total <= max) ? total : -1;
}void registerFmt_bitcoin(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("BITCOIN_WALLET", "dat", "crypto", B({0x00,0x05,0x31,0x62,0x00,0x09,0x00,0x00}), 512*MB, SizeMode::Header, vBdb));
}

}  // namespace ghost

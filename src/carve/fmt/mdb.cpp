// GHOST RECOVER — mdb signature family (one file per format).
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

i64 vMdb(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 pageSize = s.le32(off + 0x14);
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0) return -1;
    u32 nPages = s.le32(off + 0x3C);
    if (nPages < 1 || nPages > 1000000) return -1;
    i64 total = 64 + (i64)pageSize * nPages;
    return (total <= max) ? total : -1;
}void registerFmt_mdb(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("MDB", "mdb", "database", B({0x00,0x01,0x00,0x00,'S','t','a','n','d','a','r','d',' ','J','e','t'}), 4*GB, SizeMode::Header, vMdb));
    add(mk("ACCDB", "accdb", "database", B({0x00,0x01,0x00,0x00,'S','t','a','n','d','a','r','d',' ','A','C','E'}), 4*GB, SizeMode::Header, vMdb));
}

}  // namespace ghost

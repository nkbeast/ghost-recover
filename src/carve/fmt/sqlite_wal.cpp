// GHOST RECOVER — sqlite_wal signature family (one file per format).
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

i64 vWal(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 pageSize = s.be32(off + 8);
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0) return -1;
    // Header: magic, version, page size, checkpoint sequence, salt-1, salt-2,
    // checksum — the salts live at +20/+24, not at +16/+20.
    u32 salt1 = s.be32(off + 20), salt2 = s.be32(off + 24);
    i64 p = off + 32;
    int frames = 0;
    while (p + 24 <= off + max && frames < (1 << 26)) {
        auto fh = s.read(p, 24);
        if (fh.size() < 24) return -1;
        u32 pageNo = s.be32(p);
        if (pageNo == 0) return p + 24 - off;       // end marker frame is part of the WAL
        if (pageNo > (1u << 31)) return -1;
        if (s.be32(p + 8) != salt1 || s.be32(p + 12) != salt2)
            return p - off;                        // uncommitted garbage tail
        p += 24 + (i64)pageSize;
        frames++;
    }
    return (p - off <= max) ? p - off : -1;
}void registerFmt_sqlite_wal(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("SQLite_WAL", "sqlite-wal", "database", B({0x37,0x7F,0x06,0x82}), 2*GB, SizeMode::Header, vWal));
    add(mk("SQLite_WAL_BE", "sqlite-wal", "database", B({0x37,0x7F,0x06,0x83}), 2*GB, SizeMode::Header, vWal));
}

}  // namespace ghost

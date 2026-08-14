// GHOST RECOVER — sqlite signature family (one file per format).
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

i64 vSqlite(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 pageSizeRaw = s.be16(off + 16);
    i64 pageSize = (pageSizeRaw == 1) ? 65536 : pageSizeRaw;
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1))) return -1;
    u32 pageCount = s.be32(off + 28);
    if (pageCount == 0 || (i64)pageCount * pageSize > max) {
        // A file still open when it was deleted may have a stale page count.
        return 0;
    }
    return (i64)pageCount * pageSize;
}void registerFmt_sqlite(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("SQLite", "sqlite", "database", S("SQLite format 3\0"), 8*GB,
                  SizeMode::Header, vSqlite); c.min_size = 512; add(c); }
}

}  // namespace ghost

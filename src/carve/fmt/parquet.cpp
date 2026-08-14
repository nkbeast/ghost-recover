// GHOST RECOVER — parquet signature family (one file per format).
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

i64 vParquet(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = -1;
    i64 p = off + 4;
    while (p + 4 <= off + max) {
        auto m = s.read(p, 4);
        if (m.size() >= 4 && std::memcmp(m.data(), "PAR1", 4) == 0) {
            u32 size = s.le32(p - 4);
            if ((i64)size >= 4 && (i64)size <= p - 4 - (off + 4))
                total = p + 4 - off;
        }
        p++;
    }
    return (total > 0 && total <= max) ? total : -1;
}void registerFmt_parquet(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("Parquet", "parquet", "database", S("PAR1"), 8*GB, SizeMode::Header, vParquet));
}

}  // namespace ghost

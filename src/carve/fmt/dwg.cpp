// GHOST RECOVER — dwg signature family (one file per format).
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

i64 vDwg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    static const char* kVersions[] = {"AC1012", "AC1014", "AC1015", "AC1018", "AC1021", "AC1024", "AC1027"};
    auto v = s.read(off, 6);
    bool known = false;
    for (const char* k : kVersions)
        if (v.size() >= 6 && std::memcmp(v.data(), k, 6) == 0) { known = true; break; }
    if (!known) return -1;
    if (s.byte(off + 6) != 0x1F) return -1;                    // end-of-header
    u32 pageSize = s.le32(off + 0x30);
    if (pageSize != 0x1000 && pageSize != 0x2000) return -1;
    u32 count = s.le32(off + 0x38);
    if (count < 2 || count > 128) return -1;
    i64 total = 0;
    for (u32 i = 0; i < count; i++) {
        i64 e = off + 0x3C + 0x20 * (i64)i;
        if (e + 0x20 > off + max) return -1;
        u16 type = s.le16(e);
        if (type > 0x18) return -1;
        i64 aoff = (i64)s.le64(e + 0x10);
        i64 size = (i64)s.le64(e + 0x18);
        if (size > max || size < 2) return -1;
        i64 end = aoff + size;
        if (end > total) total = end;
    }
    return (total > 0 && total <= max) ? total : -1;
}void registerFmt_dwg(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("DWG", "dwg", "misc", S("AC10"), 512*MB, SizeMode::Header, vDwg));
}

}  // namespace ghost

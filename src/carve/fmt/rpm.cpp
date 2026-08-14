// GHOST RECOVER — rpm signature family (one file per format).
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

i64 vRpm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 96) != 0x8EADE801 && s.be32(off + 96) != 0x8EADE802) return -1;
    i64 p = off + 96;
    auto walkHeader = [&](i64 h, i64& next, i64* sizeTag) -> bool {
        u32 nindex = s.be32(h + 8);
        u32 hsize = s.be32(h + 12);
        if (nindex > 100000) return false;
        i64 entries = h + 16, dataStart = entries + 16 * (i64)nindex;
        if (dataStart + hsize > off + max) return false;
        for (u32 i = 0; i < nindex; i++) {
            u32 tag = s.be32(entries + 16 * (i64)i);
            u32 type = s.be32(entries + 16 * (i64)i + 4);
            u32 offs = s.be32(entries + 16 * (i64)i + 8);
            if (type == 4 && tag == 1002 && sizeTag) {
                *sizeTag = s.le32(dataStart + offs);
            }
        }
        next = dataStart + hsize;
        return true;
    };
    i64 sigNext = 0, payloadSize = -1;
    if (!walkHeader(p, sigNext, &payloadSize)) return -1;
    i64 mainNext = 0;
    if (!walkHeader(sigNext, mainNext, nullptr)) return -1;
    if (payloadSize < 0) return -1;
    i64 total = mainNext + payloadSize;
    return (total <= off + max) ? total - off : -1;
}void registerFmt_rpm(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("RPM", "rpm", "archive", B({0xED,0xAB,0xEE,0xDB}), 2*GB, SizeMode::Header, vRpm));
}

}  // namespace ghost

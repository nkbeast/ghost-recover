// GHOST RECOVER — bigtiff signature family (one file per format).
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

i64 vBigTiff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.le16(off + 4) != 8) return -1;                       // offset size
    i64 p = (i64)s.le64(off + 8);                              // first IFD
    if (p < 16 || p > max - 8) return -1;
    u64 n = s.le64(off + p);
    if (n == 0 || n > 100000) return -1;
    i64 stripOff = -1, stripBytes = 0;
    i64 q = p + 8;
    for (u64 i = 0; i < n; i++) {
        if (q + 20 > max) return -1;
        u16 tag = s.le16(off + q);
        u16 type = s.le16(off + q + 2);
        if (type == 4) {                                       // LONG
            u32 v = s.le32(off + q + 12);
            if (tag == 273) stripOff = v;
            if (tag == 279) stripBytes = v;
        } else if (type == 16) {                               // LONG8
            i64 v = (i64)s.le64(off + q + 12);
            if (tag == 273) stripOff = v;
            if (tag == 279) stripBytes = v;
        }
        q += 20;
    }
    if (stripOff < 0) return -1;
    i64 total = std::max(q + 8, stripOff + stripBytes);
    return (total <= max) ? total : -1;
}void registerFmt_bigtiff(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("BigTIFF", "tif", "image", B({'I','I',0x2B,0x00}), 2*GB, SizeMode::Header, vBigTiff));
}

}  // namespace ghost

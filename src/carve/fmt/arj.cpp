// GHOST RECOVER — ARJ archive signatures.
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

i64 vArj(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 pos = off;
    for (int step = 0; step < 4096; step++) {
        if (pos + 4 > off + max) return -1;
        if (s.byte(pos) != 0x60 || s.byte(pos + 1) != 0xEA) return -1;
        u16 hdrSize = s.le16(pos + 2);            // includes the 4 header bytes
        if (hdrSize == 0) return pos + 4 - off;   // end-of-archive marker
        if (pos + 30 > off + max) return -1;
        u8 firstHdr = s.byte(pos + 4);
        u8 flags = s.byte(pos + 8);
        u8 method = s.byte(pos + 9);
        u8 ftype = s.byte(pos + 10);
        u32 comp = s.le32(pos + 16);
        if (hdrSize < 26 || hdrSize > 65535) return -1;
        if (firstHdr < 24 || firstHdr > 128) return -1;
        if (method > 4) return -1;
        if (ftype > 4) return -1;
        if (pos + hdrSize > off + max) return -1;
        pos += hdrSize;                           // header + filename
        if (ftype == 3 || ftype == 4) continue;   // comment/special: no data
        if (flags & 0x02) continue;               // volume end / no data
        // Optional extended-header chain: {u16 id, u16 size, data} entries
        // terminated by an empty (0,0) header.
        for (int ex = 0; ex < 16; ex++) {
            if (pos + 4 > off + max) return -1;
            u16 id = s.le16(pos);
            u16 sz = s.le16(pos + 2);
            if (id == 0 && sz == 0) { pos += 4; break; }
            if (sz == 0 || sz > 4096) return -1;
            if (pos + 4 + (i64)sz > off + max) return -1;
            pos += 4 + sz;
        }
        if (comp > 0x7FFFFFFF) return -1;
        if (pos + (i64)comp > off + max) return -1;
        pos += comp;
    }
    return -1;
}

void registerFmt_arj(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ARJ", "arj", "archive", B({0x60, 0xEA}), 4*GB, SizeMode::Container, vArj); c.min_size = 30; add(c); }
}

}  // namespace ghost

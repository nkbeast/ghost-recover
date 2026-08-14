// GHOST RECOVER — rar signature family (one file per format).
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

static i64 rar5Vint(ByteSource& s, i64 at, i64 base, i64 hi, int& width) {
    width = 0;
    u64 v = 0;
    for (int i = 0; i < 10; i++) {
        u8 b = s.byte(base + at + i);
        v |= (u64)(b & 0x7F) << (7 * i);
        width = i + 1;
        if (!(b & 0x80)) return (v <= (u64)hi) ? (i64)v : -1;
    }
    return -1;
}i64 vRar(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 8);
    if (h.size() < 8) return -1;
    bool v5 = (h[6] == 0x01 && h[7] == 0x00);
    if (!v5) {
        i64 p = off + 7;
        int blocks = 0;
        while (p + 7 <= off + max && blocks < 100000) {
            u16 size = s.le16(p + 5);
            u8 type = s.byte(p + 2);
            if (size < 7) break;
            i64 add = 0;
            if (type == 0x74 || (s.le16(p + 3) & 0x8000)) add = s.le32(p + 7);
            p += size + add;
            blocks++;
            if (type == 0x7B) break;                // end-of-archive
        }
        if (blocks < 1) return -1;
        return p - off;
    }
    // RAR 5.0: walk header blocks to the End-of-archive header (type 5).
    // RAR reads nothing after it, so its end is the archive's end. Only the
    // size-bearing fields are consumed; block-specific fields are covered by
    // the Header size vint itself.
    i64 p = off + 8;
    int blocks = 0;
    while (p + 6 <= off + max && blocks < 1000000) {
        i64 hp = p - off;
        int w = 0;
        i64 hdrSize = rar5Vint(s, hp + 4, off, 2 * MB, w);
        if (hdrSize < 0 || w == 0) return -1;
        i64 q = hp + 4 + w;
        int tw = 0;
        i64 type = rar5Vint(s, q, off, 5, tw);
        if (type < 0 || tw == 0) return -1;
        q += tw;
        int fw = 0;
        i64 flags = rar5Vint(s, q, off, 0xFFFF, fw);
        if (flags < 0 || fw == 0) return -1;
        q += fw;
        if (flags & 0x0001) {                       // extra area: skip its size field
            int ew = 0;
            i64 extraSize = rar5Vint(s, q, off, 2 * MB, ew);
            if (extraSize < 0 || ew == 0) return -1;
            q += ew;
        }
        i64 dataSize = 0;
        if (flags & 0x0002) {                       // data area present
            int dw = 0;
            dataSize = rar5Vint(s, q, off, 64 * GB, dw);
            if (dataSize < 0 || dw == 0) return -1;
        }
        i64 end = hp + 4 + w + hdrSize + dataSize;
        if (end <= hp || end > max) return -1;
        p = off + end;
        blocks++;
        if (getenv("GHOST_DEBUG_RAR"))
            fprintf(stderr, "vRar5 @%lld size=%lld type=%lld flags=%lld data=%lld end=%lld\n",
                    (long long)hp, (long long)hdrSize, (long long)type,
                    (long long)flags, (long long)dataSize, (long long)end);
        if (type == 5) return end;                  // end-of-archive header
    }
    return -1;
}void registerFmt_rar(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("RAR4", "rar", "archive", B({'R','a','r','!',0x1A,0x07,0x00}), 8*GB,
                  SizeMode::Header, vRar); c.min_size = 32; add(c); }
    { auto c = mk("RAR5", "rar", "archive", B({'R','a','r','!',0x1A,0x07,0x01,0x00}), 8*GB,
                  SizeMode::Header, vRar); c.min_size = 32; add(c); }
}

}  // namespace ghost

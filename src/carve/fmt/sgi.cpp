// GHOST RECOVER — SGI image signatures.
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

i64 vSgi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 512 > off + max) return -1;
    auto h = s.read(off, 512);
    if (h.size() < 512) return -1;
    if (h[0] != 0x01 || h[1] != 0xDA) return -1;
    u8 storage = h[2];
    if (storage > 1) return -1;
    u8 bpc = h[3];
    if (bpc < 1 || bpc > 2) return -1;
    u16 dim = (u16)h[4] << 8 | h[5];
    if (dim < 1 || dim > 3) return -1;
    u16 x = (u16)h[6] << 8 | h[7], y = (u16)h[8] << 8 | h[9], z = (u16)h[10] << 8 | h[11];
    if (x == 0 || y == 0 || z == 0) return -1;
    if (dim == 1 && z > 1) return -1;
    i64 nRows = (i64)z * y;
    i64 tablesEnd = 512 + 8 * nRows;               // lengths + offset tables
    if (tablesEnd > max) return -1;
    if (storage == 0) {
        i64 end = 512 + (i64)x * y * z * bpc;
        return end <= max ? end : -1;
    }
    // RLE: the offset table (after the length table) holds each row's start;
    // walk the last row's run-length stream to the end of the file.
    u32 lastRowStart = s.be32(off + 512 + 4 * nRows + 4 * (nRows - 1));
    if (lastRowStart < tablesEnd) return -1;
    i64 p = off + lastRowStart;
    i64 want = (i64)x * bpc;
    i64 have = 0;
    while (have < want) {
        if (p + 1 > off + max) return -1;
        u8 code = s.byte(p++);
        if (code > 0x80) {
            i64 n = (i64)code - 0x80;
            if (p + 1 > off + max) return -1;
            p += 1;                                // one repeated value byte
            have += n;
        } else {
            if (p + (i64)code > off + max) return -1;
            p += code;                             // literal bytes
            have += code;
        }
    }
    if (have != want) return -1;
    return (p - off) <= max ? p - off : -1;
}

void registerFmt_sgi(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("SGI", "sgi", "image", B({0x01, 0xDA}), 512*MB, SizeMode::Container, vSgi); c.min_size = 512; add(c); }
}

}  // namespace ghost

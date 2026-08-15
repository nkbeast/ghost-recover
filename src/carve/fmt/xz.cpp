// GHOST RECOVER — xz signature family (one file per format).
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

// Parses one XZ vint (up to 9 bytes, little-endian 7-bit groups: the first
// byte carries the least significant bits). Returns the byte length
// consumed and stores the value; 0 on malformed input.
static int xzVint(const u8* b, size_t n, i64* out) {
    i64 v = 0;
    size_t i = 0;
    for (; i < n && i < 9; i++) {
        if (i == 8) return 0;
        v |= (i64)(b[i] & 0x7F) << (7 * i);
        if ((b[i] & 0x80) == 0) break;
    }
    if (i >= n || (b[i] & 0x80) != 0) return 0;
    *out = v;
    return (int)i + 1;
}

// Validates the XZ footer block that ends 12 bytes before the "YZ" at
// `pos`: stream flags must equal the header flags, the size field must
// agree with crc32(size+flags), and the index between header and footer
// must parse (indicator, record count, records, 0x00 padding, crc32).
// Returns the absolute end of the stream (footer + 12) or -1.
static i64 xzCheckFooter(ByteSource& s, i64 off, i64 max, i64 pos, u16 hFlags) {
    const i64 fstart = pos - 12;
    if (fstart < 12 + 8) return -1;                    // header + room for index
    auto fb = s.read(off + fstart, 12);
    if (fb.size() < 12) return -1;
    if (fb[10] != 'Y' || fb[11] != 'Z') return -1;
    const u16 fFlags = (u16)fb[8] | ((u16)fb[9] << 8);
    if (fFlags != hFlags) return -1;                   // flags == header flags
    u32 backsz = (u32)fb[4] | ((u32)fb[5] << 8) | ((u32)fb[6] << 16) | ((u32)fb[7] << 24);
    if (backsz > (1u << 24)) return -1;
    u32 wantCrc = (u32)fb[0] | ((u32)fb[1] << 8) | ((u32)fb[2] << 16) | ((u32)fb[3] << 24);
    u32 haveCrc = crc32(fb.data() + 4, 6);
    if (haveCrc != wantCrc) return -1;
    const i64 indexSize = (i64)(backsz + 1) * 4;
    const i64 indexEnd = fstart;                     // footer starts after index
    const i64 iStart = indexEnd - indexSize;
    if (iStart < 12) return -1;
    if (iStart + indexSize > max) return -1;
    auto idx = s.read(off + iStart, indexSize);
    if (idx.size() < (size_t)indexSize) return -1;
    if (idx[0] != 0x00) return -1;                     // index indicator
    i64 count = 0;
    int n = xzVint(idx.data() + 1, idx.size() - 1, &count);
    if (n <= 0 || count < 0 || count > (1 << 20)) return -1;
    i64 p = 1 + n;
    const i64 kMaxSize = i64(1) << 44;
    for (i64 r = 0; r < count; r++) {
        i64 unp = 0, un = 0;
        if (p + 4 > indexSize) return -1;
        int a = xzVint(idx.data() + p, idx.size() - p, &unp);
        if (a <= 0 || unp > kMaxSize) return -1;
        p += a;
        if (p + 2 > indexSize) return -1;
        int b = xzVint(idx.data() + p, idx.size() - p, &un);
        if (b <= 0 || un > kMaxSize) return -1;
        p += b;
    }
    while (p < indexSize - 4 && idx[p] == 0x00) p++;   // 0x00 padding to 4B
    if (p > indexSize - 4 || (indexSize - p) != 4) return -1;
    const u32 idxCrc = (u32)idx[indexSize - 4] | ((u32)idx[indexSize - 3] << 8) |
                       ((u32)idx[indexSize - 2] << 16) | ((u32)idx[indexSize - 1] << 24);
    if (crc32(idx.data(), indexSize - 4) != idxCrc) return -1;
    return off + fstart + 12;
}

i64 vXz(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 12);
    if (h.size() < 12) return -1;
    const u16 hFlags = (u16)h[6] | ((u16)h[7] << 8);   // check type + reserved
    u32 wantCrc = (u32)h[8] | ((u32)h[9] << 8) | ((u32)h[10] << 16) | ((u32)h[11] << 24);
    if (crc32(h.data() + 6, 2) != wantCrc) return -1;
    static const u8 kFooter[2] = {'Y', 'Z'};
    i64 lastEnd = -1;
    int streams = 0;
    const i64 kStep = 1 * MB;
    for (i64 base = 0; base < max && streams < 256; base += kStep - 16) {
        auto buf = s.read(off + base, std::min(kStep, max - base));
        if (buf.size() < 12) break;
        for (size_t i = 0; i + 2 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, kFooter, 2) != 0) continue;
            const i64 pos = base + (i64)i + 2;
            const i64 end = xzCheckFooter(s, off, max, pos, hFlags);
            if (end < 0) continue;
            if (end > lastEnd) lastEnd = end;
            streams++;
        }
        if ((i64)buf.size() < std::min(kStep, max - base)) break;
    }
    return lastEnd - off;
}void registerFmt_xz(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("XZ", "xz", "archive", B({0xFD,'7','z','X','Z',0x00}), 8*GB,
                  SizeMode::Heuristic, vXz); c.min_size = 32; add(c); }
}

}  // namespace ghost

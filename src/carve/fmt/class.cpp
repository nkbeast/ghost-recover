// GHOST RECOVER — class signature family (one file per format).
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

i64 vClass(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 minor = s.be16(off + 4);
    u16 major = s.be16(off + 6);
    (void)minor;
    if (major < 45 || major > 80) return -1;
    u16 cpCount = s.be16(off + 8);
    if (cpCount < 2 || cpCount > 65534) return -1;
    auto rd16 = [&](i64 p) { return s.be16(off + p); };
    auto rd32 = [&](i64 p) { return s.be32(off + p); };
    i64 p = 10;
    // Constant pool: a UTF8 entry self-describes; long/double take two slots.
    for (u16 ci = 1; ci < cpCount; ci++) {
        if (p + 1 > max) return -1;
        u8 tag = s.byte(off + p);
        p += 1;
        switch (tag) {
            case 1: {                               // Utf8: u16 len + bytes
                if (p + 2 > max) return -1;
                u16 n = rd16(p);
                p += 2;
                if (p + (i64)n > max) return -1;
                p += n;
                break;
            }
            case 3: case 4: case 9: case 10: case 11:
            case 12: case 17: case 18:              // 4-byte payloads
                p += 4;
                break;
            case 5: case 6:                         // long/double: 8 + 2 slots
                p += 8;
                ci++;
                break;
            case 7: case 8: case 16: case 19: case 20:
                p += 2;
                break;
            case 15:                                // method handle: 1 + 2
                p += 3;
                break;
            default:
                return -1;
        }
        if (p > max) return -1;
    }
    if (p + 8 > max) return -1;
    p += 6;                                         // access, this, super
    u16 ifaces = rd16(p);
    p += 2;
    if (p + 2 * (i64)ifaces > max) return -1;
    p += 2 * (i64)ifaces;
    auto attrs = [&](i64 at) -> i64 {
        if (at + 2 > max) return -1;
        u16 n = rd16(at);
        at += 2;
        for (u16 i = 0; i < n; i++) {
            if (at + 6 > max) return -1;
            u32 len = rd32(at + 2);
            at += 6;
            if ((i64)len > max - at) return -1;
            at += len;
        }
        return at;
    };
    // fields, methods: each member is a 6-byte header (access, name, desc)
    // followed by its own attribute table.
    for (int sec = 0; sec < 2; sec++) {
        if (p + 2 > max) return -1;
        u16 n = rd16(p);
        p += 2;
        if (p + 6 * (i64)n > max) return -1;
        for (u16 i = 0; i < n; i++) {
            p += 6;                                 // access, name, desc
            p = attrs(p);
            if (p < 0) return -1;
        }
    }
    // Class attributes follow directly: count then plain attribute frames.
    p = attrs(p);
    return p;
}void registerFmt_class(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("JavaClass", "class", "executable", B({0xCA,0xFE,0xBA,0xBE}), 64*MB,
                  SizeMode::Heuristic, vClass); c.min_size = 32; add(c); }
}

}  // namespace ghost

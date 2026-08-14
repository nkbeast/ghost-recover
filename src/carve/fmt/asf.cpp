// GHOST RECOVER — asf signature family (one file per format).
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

i64 vAsf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // The header object's field at +16 is the total header size; the file size
    // lives in the File Properties object inside it.
    auto h = s.read(off, 30);
    if (h.size() < 30) return -1;
    u64 headerSize = 0;
    for (int i = 0; i < 8; i++) headerSize |= (u64)h[16 + i] << (i * 8);
    if (headerSize < 30 || (i64)headerSize > max) return -1;
    // Look for the File Properties GUID inside the header for the real length.
    static const u8 kFileProps[16] = {0xA1,0xDC,0xAB,0x8C,0x47,0xA9,0xCF,0x11,
                                      0x8E,0xE4,0x00,0xC0,0x0C,0x20,0x53,0x65};
    auto hdr = s.read(off, std::min<i64>((i64)headerSize, 1 * MB));
    for (size_t i = 0; i + 40 < hdr.size(); i++) {
        if (std::memcmp(hdr.data() + i, kFileProps, 16) != 0) continue;
        u64 fileSize = 0;
        for (int k = 0; k < 8; k++) fileSize |= (u64)hdr[i + 40 + k] << (k * 8);
        if (fileSize >= headerSize && (i64)fileSize <= max) return (i64)fileSize;
        break;
    }
    // Fall back to walking the top-level object chain.
    i64 p = off + (i64)headerSize;
    int objects = 0;
    while (p + 24 <= off + max && objects < 4096) {
        auto o = s.read(p, 24);
        if (o.size() < 24) break;
        u64 sz = 0;
        for (int i = 0; i < 8; i++) sz |= (u64)o[16 + i] << (i * 8);
        if (sz < 24 || p + (i64)sz > off + max) break;
        p += (i64)sz;
        objects++;
    }
    return p - off;
}void registerFmt_asf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("WMA", "wma", "audio",
                  B({0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C}),
                  2*GB, SizeMode::Container, vAsf);
      withConfirm(c, B({0x40,0x9E,0x69,0xF8,0x4D,0x5B,0xCF,0x11}), -1, 65536); c.priority = 20;
      c.min_size = 1024; add(c); }
    { auto c = mk("WMV", "wmv", "video",
                  B({0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C}),
                  8*GB, SizeMode::Container, vAsf);
      withConfirm(c, B({0xC0,0xEF,0x19,0xBC,0x4D,0x5B,0xCF,0x11}), -1, 65536); c.priority = 20;
      c.min_size = 1024; add(c); }
    { auto c = mk("ASF", "asf", "video",
                  B({0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C}),
                  8*GB, SizeMode::Container, vAsf); c.min_size = 1024; add(c); }
}

}  // namespace ghost

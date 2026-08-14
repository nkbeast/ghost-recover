// GHOST RECOVER — elf signature family (one file per format).
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

i64 vElf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 64);
    if (h.size() < 52) return -1;
    u8 cls = h[4], data = h[5];
    if ((cls != 1 && cls != 2) || (data != 1 && data != 2)) return -1;
    bool be = data == 2;
    bool x64 = cls == 2;
    auto rd16 = [&](i64 o) { return be ? s.be16(off + o) : s.le16(off + o); };
    auto rd32 = [&](i64 o) { return be ? s.be32(off + o) : s.le32(off + o); };
    auto rd64 = [&](i64 o) -> u64 {
        auto v = s.read(off + o, 8);
        if (v.size() < 8) return 0;
        u64 r = 0;
        if (be) for (int i = 0; i < 8; i++) r = (r << 8) | v[i];
        else    for (int i = 7; i >= 0; i--) r = (r << 8) | v[i];
        return r;
    };
    i64 furthest = x64 ? 64 : 52;
    u64 shoff = x64 ? rd64(0x28) : rd32(0x20);
    u16 shentsize = rd16(x64 ? 0x3A : 0x2E);
    u16 shnum = rd16(x64 ? 0x3C : 0x30);
    u64 phoff = x64 ? rd64(0x20) : rd32(0x1C);
    u16 phentsize = rd16(x64 ? 0x36 : 0x2A);
    u16 phnum = rd16(x64 ? 0x38 : 0x2C);
    if (shnum && shentsize) furthest = std::max<i64>(furthest, (i64)shoff + (i64)shnum * shentsize);
    if (phnum && phentsize) furthest = std::max<i64>(furthest, (i64)phoff + (i64)phnum * phentsize);
    // Section contents can extend past the table.
    for (u16 i = 0; i < shnum && i < 4096; i++) {
        i64 e = (i64)shoff + (i64)i * shentsize;
        if (e + shentsize > max) break;
        u32 type = x64 ? (be ? s.be32(off + e + 4) : s.le32(off + e + 4))
                       : (be ? s.be32(off + e + 4) : s.le32(off + e + 4));
        if (type == 8) continue;                              // SHT_NOBITS occupies no file space
        u64 sOff = x64 ? rd64(e + 0x18) : rd32(e + 0x10);
        u64 sSize = x64 ? rd64(e + 0x20) : rd32(e + 0x14);
        if (sOff + sSize <= (u64)max) furthest = std::max<i64>(furthest, (i64)(sOff + sSize));
    }
    if (furthest > max) return -1;
    return furthest;
}void registerFmt_elf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ELF", "elf", "executable", B({0x7F,'E','L','F'}), 2*GB, SizeMode::Header, vElf);
      c.min_size = 52; add(c); }
}

}  // namespace ghost

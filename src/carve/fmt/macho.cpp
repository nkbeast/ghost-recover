// GHOST RECOVER — macho signature family (one file per format).
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

i64 vMachO(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 magic = s.le32(off);
    bool x64 = (magic == 0xFEEDFACF);
    bool be = (magic == 0xCEFAEDFE || magic == 0xCFFAEDFE);
    auto rd32 = [&](i64 o) { return be ? s.be32(off + o) : s.le32(off + o); };
    u32 ncmds = rd32(16);
    u32 sizeofcmds = rd32(20);
    if (ncmds == 0 || ncmds > 8192) return -1;
    i64 hdr = x64 ? 32 : 28;
    i64 furthest = hdr + sizeofcmds;
    i64 p = hdr;
    for (u32 i = 0; i < ncmds; i++) {
        if (p + 8 > max) break;
        u32 cmd = rd32(p);
        u32 cmdSize = rd32(p + 4);
        if (cmdSize < 8 || p + cmdSize > max) break;
        if (cmd == 0x01 || cmd == 0x19) {                     // LC_SEGMENT / _64
            u64 fileOff = x64 ? ((u64)rd32(p + 40) | ((u64)rd32(p + 44) << 32))
                              : (u64)rd32(p + 32);
            u64 fileSize = x64 ? ((u64)rd32(p + 48) | ((u64)rd32(p + 52) << 32))
                               : (u64)rd32(p + 36);
            // Sum in unsigned so two hostile near-2^63 offsets cannot invoke
            // signed-overflow UB; an oversized result simply fails to extend
            // `furthest` and the file is rejected below.
            if (fileSize > 0 && fileOff <= (u64)max - fileSize)
                furthest = std::max(furthest, (i64)(fileOff + fileSize));
        }
        p += cmdSize;
    }
    if (furthest > max) return -1;
    return furthest;
}i64 vMachOFat(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 nfat = s.be32(off + 4);
    if (nfat < 1 || nfat > 128) return -1;
    i64 total = 0;
    for (u32 i = 0; i < nfat; i++) {
        i64 e = off + 8 + 20 * (i64)i;
        if (e + 20 > off + max) return -1;
        u32 aoff = s.be32(e + 8);
        u32 size = s.be32(e + 12);
        if (size == 0 || (i64)aoff + size > total) total = (i64)aoff + size;
    }
    return (total > 8 && total <= max) ? total : -1;
}void registerFmt_macho(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MachO64", "macho", "executable", B({0xCF,0xFA,0xED,0xFE}), 2*GB,
                  SizeMode::Header, vMachO); c.min_size = 32; add(c); }
    { auto c = mk("MachO32", "macho", "executable", B({0xCE,0xFA,0xED,0xFE}), 2*GB,
                  SizeMode::Header, vMachO); c.min_size = 28; add(c); }
    add(mk("MachO_FAT", "macho", "executable", B({0xCA,0xFE,0xBA,0xBF}), 2*GB, SizeMode::Header, vMachOFat));
}

}  // namespace ghost

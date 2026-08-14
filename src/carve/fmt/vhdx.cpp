// GHOST RECOVER — vhdx signature family (one file per format).
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

i64 vVhdx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto sig = s.read(off, 8);
    if (sig.size() < 8 || std::memcmp(sig.data(), "vhdxfile", 8) != 0) return -1;
    i64 hdr = -1;
    for (i64 h : {0x10000LL, 0x20000LL}) {
        if (h + 84 > max) continue;
        auto b = s.read(off + h, 84);
        if (b.size() < 84 || std::memcmp(b.data(), "head", 4) != 0) continue;
        u16 logVer = (u16)(b[68] | (u16)b[69] << 8);
        u16 ver = (u16)(b[70] | (u16)b[71] << 8);
        if (ver != 1 && ver != 16) continue;   // 1 = spec, 16 = qemu's writer
        if (logVer > 1) continue;
        hdr = h;
        break;
    }
    if (hdr < 0) return -1;
    i64 end = 0x30000 + 0x10000;   // at least through the region table
    auto rt = s.read(off + 0x30000, 16 + 2047 * 32);
    if (rt.size() < 20 || std::memcmp(rt.data(), "regi", 4) != 0) return -1;
    u32 count = (u32)rt[8] | (u32)rt[9] << 8 | (u32)rt[10] << 16 | (u32)rt[11] << 24;
    if (count < 1 || count > 2047) return -1;
    u64 batOff = 0, batLen = 0, metaOff = 0;
    bool hasMeta = false;
    for (u32 i = 0; i < count; i++) {
        const u8* e = rt.data() + 16 + i * 32;
        u64 fo = 0;
        for (int k = 0; k < 8; k++) fo |= (u64)e[16 + k] << (8 * k);   // VHDX is little-endian
        u32 len = (u32)e[24] | (u32)e[25] << 8 | (u32)e[26] << 16 | (u32)e[27] << 24;
        if (fo == 0 || len == 0) continue;
        // Known region GUIDs: BAT and Metadata Region (MS GUID byte order).
        static const u8 kBATGuid[16]   = {0x66,0x77,0xc2,0x2d,0x23,0xf6,0x00,0x42,
                                          0x9d,0x64,0x11,0x5e,0x9b,0xfd,0x4a,0x08};
        static const u8 kMetaGuid[16]  = {0x06,0xa2,0x7c,0x8b,0x90,0x47,0x9a,0x4b,
                                          0xb8,0xfe,0x57,0x5f,0x05,0x0f,0x88,0x6e};
        if (std::memcmp(e, kBATGuid, 16) == 0) { batOff = fo; batLen = len; }
        if (std::memcmp(e, kMetaGuid, 16) == 0) { metaOff = fo; hasMeta = true; }
        u64 rEnd = fo + len;
        if (rEnd >= (u64)max) rEnd = (u64)max;
        if ((i64)rEnd > end) end = (i64)rEnd;
    }
    // Read the block size from the File Parameters metadata item so we know
    // where the data region starts (aligned up to a block from the end of the
    // region table extents) and how big fully-present BAT blocks are.
    u64 blockSize = 0;
    if (hasMeta && metaOff < (u64)max) {
        auto md = s.read(off + (i64)metaOff, 32 + 2047 * 32);
        if (md.size() >= 32 && std::memcmp(md.data(), "metadata", 8) == 0) {
            u16 mcnt = (u16)(md[10] | (u16)md[11] << 8);
            static const u8 kFileParamGuid[16] = {0x37,0x67,0xa1,0xca,0x36,0xfa,0x43,0x4d,
                                                  0xb3,0xb6,0x33,0xf0,0xaa,0x44,0xe7,0x6b};
            for (u16 i = 0; i < mcnt && 32 + (u32)i * 32 + 28 <= md.size(); i++) {
                const u8* e = md.data() + 32 + i * 32;
                if (std::memcmp(e, kFileParamGuid, 16) != 0) continue;
                u32 rel = (u32)e[16] | (u32)e[17] << 8 | (u32)e[18] << 16 | (u32)e[19] << 24;
                u32 ln = (u32)e[20] | (u32)e[21] << 8 | (u32)e[22] << 16 | (u32)e[23] << 24;
                if (ln < 4 || rel + 4 > (u64)max - metaOff) continue;
                auto pb = s.read(off + (i64)metaOff + rel, 4);
                if (pb.size() < 4) continue;
                u64 bs = (u64)pb[0] | (u64)pb[1] << 8 | (u64)pb[2] << 16 | (u64)pb[3] << 24;
                if (bs >= 1024 * 1024 && bs <= 256ULL * 1024 * 1024) blockSize = bs;
                break;
            }
        }
    }
    // Payload blocks are appended 1 MiB-aligned past the header/region area,
    // and the data region starts on a block-size boundary there.
    if (blockSize) {
        u64 dataBase = ((u64)end + blockSize - 1) / blockSize * blockSize;
        if (dataBase > (u64)end && dataBase < (u64)max) end = (i64)dataBase;
    }
    // Walk the BAT: 64-bit entries, low 3 bits = block state
    // (6 = PAYLOAD_BLOCK_FULLY_PRESENT), remaining bits = 1 MiB-aligned byte
    // offset of the payload block (masked by 0xFFFFFFFFFFF00000).
    if (batOff && batLen && batOff < (u64)max && blockSize) {
        i64 n = std::min<i64>((i64)(batLen / 8), max - (i64)batOff);
        for (i64 i = 0; i < n; i += 2048) {
            auto blk = s.read(off + (i64)batOff + i, std::min<i64>(16384, n - i));
            if (blk.size() < (size_t)std::min<i64>(16384, n - i)) break;
            for (size_t j = 0; j + 8 <= blk.size(); j += 8) {
                u64 e = 0;
                for (int k = 0; k < 8; k++) e |= (u64)blk[j + k] << (8 * k);   // LE entries
                if ((e & 7) != 6) continue;      // FULLY_PRESENT only
                u64 cl = e & 0xFFFFFFFFFFF00000ULL;
                if (cl == 0 || cl >= (u64)max) continue;
                i64 cEnd = (i64)std::min<u64>(cl + blockSize, (u64)max);
                if (cEnd > end) end = cEnd;
            }
        }
    }
    return end;
}void registerFmt_vhdx(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("VHDX", "vhdx", "vm", S("vhdxfile"), 64*GB, SizeMode::Heuristic, vVhdx);
      add(c); }
}

}  // namespace ghost

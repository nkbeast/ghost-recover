// GHOST RECOVER — vdi signature family (one file per format).
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

i64 vVdi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 512);
    if (b.size() < 512) return -1;
    static const char* kMagic[] = {
        "<<< Oracle VM VirtualBox Disk Image >>>",
        "<<< QEMU VM Virtual Disk Image >>>",
        nullptr};
    bool magicOk = false;
    for (int m = 0; kMagic[m]; m++)
        if (std::memcmp(b.data(), kMagic[m], std::strlen(kMagic[m])) == 0) { magicOk = true; break; }
    if (!magicOk) return -1;
    auto le32v = [&](u32 o) {
        return (u32)b[o] | (u32)b[o + 1] << 8 | (u32)b[o + 2] << 16 | (u32)b[o + 3] << 24;
    };
    auto be32v = [&](u32 o) {
        return (u32)b[o] << 24 | (u32)b[o + 1] << 16 | (u32)b[o + 2] << 8 | b[o + 3];
    };
    auto le64v = [&](u32 o) {
        u64 v = 0;
        for (int k = 0; k < 8; k++) v |= (u64)b[o + k] << (8 * k);
        return v;
    };
    auto be64v = [&](u32 o) {
        u64 v = 0;
        for (int k = 0; k < 8; k++) v = v << 8 | b[o + k];
        return v;
    };
    // qemu/block/vdi.c header (all fields little-endian): signature @0x40,
    // version @0x44, header_size @0x48, image_type @0x4c, flags @0x50,
    // description [256] @0x54, offset_bmap @0x154, offset_data @0x158,
    // disk_size @0x170, block_size @0x178, blocks_in_image @0x180,
    // blocks_allocated @0x184.
    u32 sig = le32v(0x40);
    if (sig != 0xbeda107f && be32v(0x40) != 0xbeda107f) return -1;
    u32 version = le32v(0x44);
    if (version != 0x00010001 && version != 0x00010002 &&
        be32v(0x44) != 0x00010001 && be32v(0x44) != 0x00010002)
        return -1;
    u32 hdrSize = le32v(0x48);
    if (hdrSize == 0) hdrSize = be32v(0x48);
    if (hdrSize == 0 || hdrSize > 2048) return -1;
    u64 diskSize = le64v(0x170);
    if (diskSize == 0) diskSize = be64v(0x170);
    if (diskSize == 0) return -1;
    u64 blockSize = le32v(0x178);
    if (blockSize == 0) blockSize = be32v(0x178);
    if (blockSize == 0 || blockSize > (1ULL << 40)) return -1;
    u64 blocksTotal = le32v(0x180);
    if (blocksTotal == 0) blocksTotal = be32v(0x180);
    u64 blocksAlloc = le32v(0x184);
    if (blocksAlloc == 0) blocksAlloc = be32v(0x184);
    u32 imageType = le32v(0x4c);
    if (imageType != 1 && imageType != 2) imageType = be32v(0x4c);
    u64 dataOff = le32v(0x158);
    if (dataOff == 0) dataOff = be32v(0x158);
    // A static image is fully allocated: its physical end is data + all
    // blocks. A dynamic one holds only the blocks its bmap claims.
    u64 end = dataOff;
    u64 used = imageType == 2 ? blocksTotal : blocksAlloc;
    if (used && used < (1u << 30)) end += used * blockSize;
    if (!end || end > (u64)max) end = (u64)max;
    u64 hdrEnd = (u64)hdrSize;
    if (end < hdrEnd) end = hdrEnd;
    if (end > (u64)max) end = (u64)max;
    if (end < 512) end = 512;
    return (i64)end;
}void registerFmt_vdi(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("VDI", "vdi", "vm", S("<<< Oracle VM VirtualBox Disk Image >>>"), 64*GB,
                  SizeMode::Header, vVdi); c.min_size = 512; add(c); }
    { auto c = mk("VDI_QEMU", "vdi", "vm", S("<<< QEMU VM Virtual Disk Image >>>"), 64*GB,
                  SizeMode::Header, vVdi); c.min_size = 512; add(c); }
}

}  // namespace ghost

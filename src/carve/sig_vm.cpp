// GHOST RECOVER — carver signature specs and validators for Virtual disks.
//
// Part of the per-category split of the former monolithic signatures.cpp.
// Shared plumbing (mk, withConfirm, cross-category validators) lives in
// sig_common.h / sig_common.cpp; the registry aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "sig_common.h"

#include <algorithm>
#include <cstring>

namespace ghost {


// --- QCOW2 -----------------------------------------------------------------
// Walks the real qcow2 layout: header, L1 table, each L2 table, the refcount
// table and its blocks, and the snapshot list. The file ends at the last
// cluster any of those refer to. (In a raw carved file every pointer lies
// below the true file size, so the walk is bounded and honest.)
i64 vQcow(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 72);
    if (b.size() < 72) return -1;
    if (b[0] != 'Q' || b[1] != 'F' || b[2] != 'I' || b[3] != 0xfb) return -1;
    auto be32v = [&](const u8* p) {
        return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3];
    };
    auto be64v = [&](const u8* p) {
        u64 v = 0;
        for (int k = 0; k < 8; k++) v = v << 8 | p[k];
        return v;
    };
    u32 version = be32v(b.data() + 4);
    if (version != 2 && version != 3) return -1;
    if (version == 3) {
        u32 hsize = be32v(b.data() + 68);
        if (hsize != 0 && hsize < 104) return -1;   // writers may leave 0
    }
    u32 clusterBits = be32v(b.data() + 20);
    if (clusterBits < 9 || clusterBits > 21) return -1;
    const u64 cluster = 1ULL << clusterBits;
    if (be64v(b.data() + 24) == 0) return -1;   // disk size must be nonzero
    u64 l1Off = be64v(b.data() + 40), l1Size = be32v(b.data() + 36);
    u64 refcOff = be64v(b.data() + 48), refcClust = be32v(b.data() + 56);
    u64 snapOff = be64v(b.data() + 64), snapCount = be32v(b.data() + 60);
    u64 backOff = be64v(b.data() + 8), backSize = be32v(b.data() + 16);
    auto endOf = [&](u64 p, u64 len) -> i64 {
        if (p == 0 || len == 0) return 0;
        if (p >= (u64)max) return max;
        u64 e = p + len;
        return e >= (u64)max ? max : (i64)e;
    };
    i64 end = endOf(refcOff, refcClust * cluster);
    end = std::max(end, endOf(backOff, backSize));
    // The L1 table itself is part of the file even when no L2 entry refers
    // beyond it (qemu sparsifies exactly this way: the L1 cluster is written
    // last, at the physical end of the image).
    if (l1Off > 0 && l1Off < (u64)max && l1Size > 0 && (i64)l1Size * 8 <= max - (i64)l1Off)
        end = std::max(end, endOf(l1Off, (i64)l1Size * 8));
    if (snapCount <= 0x10000) end = std::max(end, endOf(snapOff, snapCount * 184));
    if (l1Size > 0 && l1Off == 0) return -1;
    if (l1Size > 0x100000) l1Size = 0x100000;   // don't chase absurd tables
    auto l1 = s.read(off + (i64)l1Off, std::min<i64>((i64)l1Size * 8, max - (i64)l1Off));
    if (l1.size() < (size_t)l1Size * 8) l1Size = (u32)(l1.size() / 8);
    for (u32 i = 0; i < l1Size; i++) {
        u64 e = be64v(l1.data() + i * 8);
        if (e == 0) continue;
        u64 l2Off = (e >> 9) & 0x3FFFFFFFFFFFFFULL;   // bits 9..62 = cluster addr
        if (l2Off == 0 || l2Off * cluster >= (u64)max) continue;
        end = std::max(end, endOf(l2Off * cluster, cluster));
        auto l2 = s.read(off + (i64)(l2Off * cluster), cluster);
        if (l2.size() < 8) continue;
        size_t n = std::min<size_t>(cluster / 8, l2.size() / 8);
        for (size_t j = 0; j < n; j++) {
            u64 d = be64v(l2.data() + j * 8);
            if (d == 0) continue;
            u64 dOff = (d >> 9) & 0x3FFFFFFFFFFFFFULL;
            if (dOff == 0 || dOff * cluster >= (u64)max) continue;
            end = std::max(end, endOf(dOff * cluster, cluster));
        }
    }
    if (refcOff && refcClust && refcClust < 0x10000) {
        auto rt = s.read(off + (i64)refcOff, std::min<i64>((i64)(refcClust * cluster / 8) * 8, max - (i64)refcOff));
        size_t n = std::min<size_t>(rt.size() / 8, (size_t)(refcClust * cluster / 8));
        for (size_t j = 0; j < n; j++) {
            u64 e = be64v(rt.data() + j * 8);
            if (e == 0) continue;
            // Refcount table entries are byte offsets of refcount blocks.
            u64 bOff = e;
            if (bOff == 0 || bOff >= (u64)max) continue;
            end = std::max(end, endOf(bOff, cluster));
        }
    }
    if (end < 512) return -1;
    return end;
}

// --- VHD: the footer "conectix" copy lies at the end of the file itself, so
// the header candidate scans forward for the nearest valid footer within it.
// (Scanning the tail of the extent cannot work: the extent usually extends
// well past the file's end.) The footer's own 8-byte Current Size and the
// copy's position both describe the file; the position is authoritative.
i64 vVhd(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 512 + 512) return -1;
    i64 scanEnd = std::min<i64>(max, 512LL * 1024 * 1024);
    i64 pos = 512;
    while (pos + 512 <= scanEnd) {
        auto b = s.read(off + pos, 16);
        if (b.size() < 8) break;
        bool isFooter = std::memcmp(b.data(), "conectix", 8) == 0;
        if (isFooter) {
            // File format version: footer bytes 12..15 = 0x00010000.
            u16 hi = (u16)(s.byte(off + pos + 12) << 8 | s.byte(off + pos + 13));
            if (hi == 0x0001) {
                i64 fileSize = pos + 512;
                if (fileSize > max) return -1;
                return fileSize;
            }
        }
        pos += 512;
    }
    return -1;
}

// --- VHDX: validated against the real layout -------------------------------
// -- File identifier + one of the two valid headers (signature + version) +
// -- the region table at 192 KiB (count field at +8, entries at +16) + the
// -- BAT extent walk. The length is the furthest cluster any location table
// -- refers to, exactly like the qcow2 walk above.
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
}

// --- VDI: QEMU's dynamic disk header -----------------------------------------
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
}

void registerVm(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("QCOW2", "qcow2", "vm", B({'Q','F','I',0xFB}), 64*GB,
                  SizeMode::Heuristic, vQcow); c.min_size = 72; add(c); }
    add(mk("VMDK_SPARSE", "vmdk", "vm", B({'K','D','M','V'}), 64*GB));
    add(mk("VMDK_DESC", "vmdk", "vm", S("# Disk DescriptorFile"), 1*MB));
    { auto c = mk("VDI", "vdi", "vm", S("<<< Oracle VM VirtualBox Disk Image >>>"), 64*GB,
                  SizeMode::Header, vVdi); c.min_size = 512; add(c); }
    { auto c = mk("VDI_QEMU", "vdi", "vm", S("<<< QEMU VM Virtual Disk Image >>>"), 64*GB,
                  SizeMode::Header, vVdi); c.min_size = 512; add(c); }
    { auto c = mk("VHD", "vhd", "vm", S("conectix"), 64*GB,
                  SizeMode::Footer, vVhd); c.min_size = 1024; add(c); }
    { auto c = mk("VHDX", "vhdx", "vm", S("vhdxfile"), 64*GB, SizeMode::Heuristic, vVhdx);
      add(c); }
    { auto c = mk("OVA", "ova", "vm", S("ustar"), 64*GB, SizeMode::Container, vTar);
      c.magic_offset = 257; c.min_size = 1024; add(c); }
}

}  // namespace ghost

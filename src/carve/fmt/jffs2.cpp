// GHOST RECOVER — jffs2 signature family (one file per format).
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

// The JFFS2 header checksum is the kernel crc32 convention: the register
// starts at 0 and there is no final inversion (mkfs.jffs2 computes
// crc32(0, node, 8)). The shared helper applies the inverted convention,
// so derive the raw register result.
static u32 jffs2Crc(const u8* d, size_t n) {
    return ~crc32(d, n, 0xFFFFFFFFu);
}

// JFFS2 raw image layout: each node starts with magic 0x1985 (LE 0x85 0x19),
// nodetype u16 LE, totlen u32 LE, header_crc u32 LE (= crc32 of the first
// 8 bytes). Nodes are packed; between erase blocks the remaining space is
// filled with 0xFF. The image end is the last valid node, padded to the
// erase-block boundary with 0xFF bytes.
i64 vJffs2(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 4);
    if (h.size() < 4) return -1;
    if (h[0] != 0x85 || h[1] != 0x19) return -1;
    i64 p = off;
    i64 lastEnd = off;
    bool any = false;
    int nodes = 0;
    while (nodes < 4000000) {
        auto nh = s.read(p, 12);
        if (nh.size() < 12) break;
        if (nh[0] != 0x85 || nh[1] != 0x19) break;
        const u32 type = (u32)nh[2] | ((u32)nh[3] << 8);
        u32 totlen = (u32)nh[4] | ((u32)nh[5] << 8) | ((u32)nh[6] << 16) | ((u32)nh[7] << 24);
        const u32 hdrCrc = (u32)nh[8] | ((u32)nh[9] << 8) |
                           ((u32)nh[10] << 16) | ((u32)nh[11] << 24);
        bool typeOk = (type == 0x2003 ||   // CLEANMARKER
                       type == 0x2004 ||   // PADDING
                       type == 0x2006 ||   // SUMMARY
                       type == 0xE001 ||   // DIRENT
                       type == 0xE002 ||   // INODE
                       type == 0xE008 ||   // XATTR
                       type == 0xE009);    // XREF
        if (!typeOk) break;
        if (totlen < 12 || totlen > 16 * 1024 * 1024) break;
        if (p + totlen > off + max) break;
        if (jffs2Crc(nh.data(), 8) != hdrCrc) break;   // header checksum
        lastEnd = p + totlen;
        // Nodes are 4-byte aligned; skip inter-node 0xFF/0x00 filler (only
        // the filler — a node already ends on a boundary when totlen % 4).
        p = lastEnd;
        while (p < off + max) {
            auto c = s.read(p, 1);
            if (c.size() != 1) break;
            if (c[0] != 0xFF && c[0] != 0x00) break;
            p++;
        }
        nodes++;
        any = true;
        if (p >= off + max) break;
    }
    if (!any || nodes < 2) return -1;
    // Erase-block padding: the tail after the last node is 0xFF up to the
    // aligned boundary; accept the largest power-of-two block (4K..512K)
    // that yields an all-0xFF region ending inside the bound.
    i64 end = lastEnd;
    for (i64 block = 4 * 1024; block <= 512 * 1024; block *= 2) {
        const i64 aligned = ((lastEnd - off + block - 1) / block) * block + off;
        if (aligned > off + max) continue;
        auto tail = s.read(lastEnd, aligned - lastEnd);
        if (tail.size() != (size_t)(aligned - lastEnd)) continue;
        bool allFF = true;
        for (size_t i = 0; i < tail.size(); i++)
            if (tail[i] != 0xFF) { allFF = false; break; }
        if (allFF) end = aligned;
    }
    return end - off;
}

void registerFmt_jffs2(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("JFFS2", "jffs2", "filesystem", B({0x85,0x19}), 4*GB,
                  SizeMode::Container, vJffs2); c.min_size = 24; add(c); }
}

}  // namespace ghost

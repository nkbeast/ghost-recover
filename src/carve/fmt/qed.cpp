// GHOST RECOVER — QED vm signatures.
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

// QED (qemu) layout, per qemu block/qed.h:
//   header 64B: magic "QED\0", cluster_size u32 LE, table_size u32 LE
//   (in clusters!), header_size u32 LE (in clusters!), features u64 LE,
//   compat_features u64 LE, autoclear_features u64 LE, l1_table_offset u64
//   LE (0 when no L1 is allocated), image_size u64 LE.
//   L1/L2 tables hold table_size*cluster/8 little-endian u64 entries; each
//   entry is 0 (unallocated) or a cluster-aligned table/data offset.
i64 vQed(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 56 > off + max) return -1;
    auto h = s.read(off, 56);
    if (h.size() < 56) return -1;
    auto u32le = [&](int at) {
        return (u32)h[at] | ((u32)h[at + 1] << 8) | ((u32)h[at + 2] << 16) |
               ((u32)h[at + 3] << 24);
    };
    auto u64le = [&](int at) {
        return (i64)u32le(at) | ((i64)u32le(at + 4) << 32);
    };
    const u32 cluster = u32le(4);
    const u32 tableSize = u32le(8);
    const u32 headerSize = u32le(12);
    const i64 features = u64le(16);
    const i64 compat = u64le(24);
    const i64 autoclear = u64le(32);
    const i64 l1 = u64le(40);
    const i64 imageSize = u64le(48);
    if (cluster < 4096 || cluster > (64u << 20) || (cluster & (cluster - 1)) != 0)
        return -1;
    if (tableSize == 0 || tableSize > 16) return -1;
    if (headerSize == 0 || headerSize > 64) return -1;
    if (features < 0 || features > 0x07) return -1;      // spec: 0..(7)
    if (compat != 0) return -1;
    if (autoclear != 0) return -1;
    if (imageSize < 0 || imageSize > (i64(1) << 56)) return -1;
    const i64 headerEnd = (i64)headerSize * cluster;
    if (l1 == 0) {                                       // no L1: preallocated area
        const i64 total = headerEnd + (i64)tableSize * cluster;
        return total <= max ? total : -1;
    }
    if (l1 < headerEnd || l1 % cluster != 0 ||
        off + l1 + (i64)tableSize * cluster > off + max)
        return -1;
    // A hostile header could claim huge tables; the physical file bounds the
    // reads, but cap the per-table scan to keep hostile images cheap.
    const i64 entries = std::min<i64>((i64)tableSize * cluster / 8,
                                      (i64(1) << 23));
    const i64 l1Abs = off + l1;
    const i64 l1End = l1Abs + (i64)tableSize * cluster;
    i64 end = l1End;
    for (i64 i = 0; i < entries; i++) {
        auto e = s.read(l1Abs + i * 8, 8);
        if (e.size() < 8) break;
        u64 v = 0;
        for (int k = 0; k < 8; k++) v |= (u64)e[k] << (8 * k);
        i64 vv = (i64)v;
        if (vv == 0) continue;
        if (vv < headerEnd || vv % cluster != 0) return -1;
        if (off + vv + (i64)tableSize * cluster > off + max) return -1;
        const i64 l2Abs = off + vv;
        end = std::max(end, l2Abs + (i64)tableSize * cluster);      // L2 table span
        for (i64 j = 0; j < entries; j++) {
            auto e2 = s.read(l2Abs + j * 8, 8);
            if (e2.size() < 8) break;
            u64 v2 = 0;
            for (int k = 0; k < 8; k++) v2 |= (u64)e2[k] << (8 * k);
            i64 vv2 = (i64)v2;
            if (vv2 == 0) continue;
            if (vv2 < headerEnd || vv2 % cluster != 0) return -1;
            if (off + vv2 + cluster > off + max) return -1;
            end = std::max(end, off + vv2 + cluster);                 // data cluster
        }
    }
    return end - off;
}

void registerFmt_qed(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("QED", "qed", "vm", B({0x51, 0x45, 0x44, 0x00}), 64*GB, SizeMode::Container, vQed); c.min_size = 16; add(c); }
}

}  // namespace ghost

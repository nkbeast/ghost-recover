// GHOST RECOVER — qcow signature family (one file per format).
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
        if (l2Off == 0 || l2Off >= (u64)max / cluster) continue;   // no overflow
        end = std::max(end, endOf(l2Off * cluster, cluster));
        auto l2 = s.read(off + (i64)(l2Off * cluster), cluster);
        if (l2.size() < 8) continue;
        size_t n = std::min<size_t>(cluster / 8, l2.size() / 8);
        for (size_t j = 0; j < n; j++) {
            u64 d = be64v(l2.data() + j * 8);
            if (d == 0) continue;
            u64 dOff = (d >> 9) & 0x3FFFFFFFFFFFFFULL;
            if (dOff == 0 || dOff >= (u64)max / cluster) continue;
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
}void registerFmt_qcow(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("QCOW2", "qcow2", "vm", B({'Q','F','I',0xFB}), 64*GB,
                  SizeMode::Heuristic, vQcow); c.min_size = 72; add(c); }
}

}  // namespace ghost

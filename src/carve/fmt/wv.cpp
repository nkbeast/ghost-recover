// GHOST RECOVER — wv signature family (one file per format).
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

i64 vWv(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // WavPack: a chain of wvpk blocks; each block's ckSize spans everything
    // after its own 8-byte header, so p += 8 + ckSize lands exactly on the
    // next block. The final block sets flag 0x1000 (FINAL_BLOCK); without it
    // (some encoders omit the flag), the chain runs to the region boundary,
    // where the byte right after the last block is not another wvpk header.
    i64 p = off;
    int blocks = 0;
    while (p + 32 <= off + max && blocks < 1000000) {
        auto h = s.read(p, 32);
        if (h.size() < 32) return -1;
        if (h[0] != 'w' || h[1] != 'v' || h[2] != 'p' || h[3] != 'k') return -1;
        u32 ckSize = s.le32(p + 4);
        if (ckSize < 24) return -1;
        u16 ver = s.le16(p + 8);
        if (ver < 0x400 || ver > 0x4FF) return -1;    // WavPack 4.x
        if (p + 8 + (i64)ckSize > off + max) return -1;
        u32 flags = s.le32(p + 24);                   // flags live at +24
        p += 8 + (i64)ckSize;
        blocks++;
        if (flags & 0x1000) break;                    // FINAL_BLOCK
        if (p + 4 <= off + max) {
            auto nx = s.read(p, 4);
            if (nx.size() < 4 || memcmp(nx.data(), "wvpk", 4) != 0) break;
        }
    }
    if (blocks == 0) return -1;
    return p - off;
}void registerFmt_wv(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("WV", "wv", "audio", S("wvpk"), 1*GB, SizeMode::Container, vWv));
}

}  // namespace ghost

// GHOST RECOVER — ivf signature family (one file per format).
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

i64 vIvf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 32);
    if (h.size() < 32) return -1;
    if (h[0] != 'D' || h[1] != 'K' || h[2] != 'I' || h[3] != 'F') return -1;
    u16 hdrSize = s.le16(off + 6);
    if (hdrSize < 32 || hdrSize > 4096) return -1;
    u32 nframes = s.le32(off + 24);
    if (nframes == 0 || nframes > 2000000) return -1;
    i64 p = off + (i64)hdrSize;
    for (u32 f = 0; f < nframes; f++) {
        if (p + 12 > off + max) return -1;
        u32 frame = s.le32(p);
        if (frame == 0 || frame > 512 * MB) return -1;
        p += 12 + (i64)frame;
    }
    return (p <= off + max) ? p - off : -1;
}void registerFmt_ivf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("IVF", "ivf", "video", S("DKIF"), 4*GB, SizeMode::Container, vIvf));
}

}  // namespace ghost

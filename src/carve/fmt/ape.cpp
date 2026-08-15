// GHOST RECOVER — ape signature family (one file per format).
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

i64 vApe(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 44);
    if (h.size() < 44) return -1;
    u32 version = s.le32(off + 4);
    if (version < 3800 || version > 3990) return -1;
    if (version < 3980) {
        // Old header layout (no descriptor): audio header right after the
        // magic, and no reliable total length. Validate and report unknown.
        u16 bps = s.le16(off + 8 + 20);
        u16 chans = s.le16(off + 8 + 22);
        if (bps != 8 && bps != 16 && bps != 24 && bps != 32) return -1;
        if (chans < 1 || chans > 16) return -1;
        return 0;
    }
    // 3.98+: the descriptor's length fields sum to the exact file size.
    u32 descBytes = s.le32(off + 8);
    u32 hdrBytes = s.le32(off + 12);
    u32 seekBytes = s.le32(off + 16);
    u32 hdrData = s.le32(off + 20);
    u32 frameBytes = s.le32(off + 24);
    u32 globalBytes = s.le32(off + 28);
    u32 localBytes = s.le32(off + 32);
    u32 padBytes = s.le32(off + 36);
    if (descBytes < 52 || descBytes > 4096) return -1;
    i64 total = (i64)descBytes + hdrBytes + seekBytes + hdrData + frameBytes +
                globalBytes + localBytes + padBytes;
    if (total < 76 || total > max) return -1;
    i64 hdr = off + (i64)descBytes;
    if (hdr + 24 > off + max) return -1;
    u32 frames = s.le32(hdr + 16);
    u16 bps = s.le16(hdr + 20);
    u16 chans = s.le16(hdr + 22);
    if (frames < 1 || frames > 100000000) return -1;
    if (bps != 8 && bps != 16 && bps != 24 && bps != 32) return -1;
    if (chans < 1 || chans > 16) return -1;
    return total;
}void registerFmt_ape(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("APE", "ape", "audio", S("MAC "), 1*GB, SizeMode::Header, vApe));
}

}  // namespace ghost

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
    u32 descSize = s.le32(off + 8);
    u32 hdrSize = s.le32(off + 12);
    if (descSize < 52 || descSize > max) return -1;
    if (hdrSize < 24 || hdrSize > max) return -1;
    u32 version = s.le32(off + 4);
    if (version < 3800 || version > 4000) return -1;
    i64 hdr = off + descSize;
    if (hdr + hdrSize > off + max) return -1;
    u32 frames = s.le32(hdr + 22);
    u32 hBytes = s.le32(hdr + 14);
    u32 tBytes = s.le32(hdr + 18);
    u32 blocks = s.le32(hdr + 30);
    u16 chans = s.le16(hdr + 8);
    if (chans < 1 || chans > 16 || frames > 100000000) return -1;
    u32 bps = s.le16(hdr + 34);
    if (bps != 8 && bps != 16 && bps != 24 && bps != 32) return -1;
    i64 front = off + descSize + hdrSize + 4 * (i64)frames + hBytes + tBytes +
                (i64)blocks * chans * (bps / 8);
    if (front > off + max) return -1;
    // Scan for the last APETAGEX footer (footer, not header: version 2000 or
    // 3980 with a matching tag size field).
    i64 total = -1;
    i64 p = front;
    while (p + 32 <= off + max) {
        auto m = s.read(p, 8);
        if (m.size() >= 8 && std::memcmp(m.data(), "APETAGEX", 8) == 0) {
            u32 ver = s.le32(p + 8);
            u32 tagSize = s.le32(p + 12);
            if ((ver == 2000 || ver == 3980) && (i64)tagSize == p - 32 - front)
                total = p + 32 - off;
        }
        p++;
    }
    return (total > 0 && total <= max) ? total : -1;
}void registerFmt_ape(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("APE", "ape", "audio", S("MAC "), 1*GB, SizeMode::Header, vApe));
}

}  // namespace ghost

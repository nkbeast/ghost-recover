// GHOST RECOVER — mpegts signature family (one file per format).
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

i64 vMpegTs(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    constexpr int kPkt = 188;
    i64 p = off;
    int pkts = 0;
    while (p + kPkt <= off + max && pkts < 8000000) {
        if (s.byte(p) != 0x47) break;
        p += kPkt;
        pkts++;
    }
    if (pkts < 16) return -1;         // 16 consecutive packets = real TS
    return p - off;
}void registerFmt_mpegts(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MPEG_TS", "ts", "video", B({0x47,0x40,0x00}), 16*GB, SizeMode::FrameStream, vMpegTs);
      c.min_size = 188 * 16; c.min_entropy = 1.0; add(c); }
    { auto c = mk("MPEG_TS1", "ts", "video", B({0x47,0x41,0x01}), 16*GB, SizeMode::FrameStream, vMpegTs);
      c.min_size = 188 * 16; c.min_entropy = 1.0; add(c); }
}

}  // namespace ghost

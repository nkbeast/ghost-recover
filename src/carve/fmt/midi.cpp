// GHOST RECOVER — midi signature family (one file per format).
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

i64 vMidi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 hdrLen = s.be32(off + 4);
    if (hdrLen != 6) return -1;
    u16 tracks = s.be16(off + 10);
    if (tracks == 0 || tracks > 4096) return -1;
    i64 p = off + 14;
    int seen = 0;
    while (seen < tracks && p + 8 <= off + max) {
        auto t = s.read(p, 4);
        if (t.size() < 4 || std::memcmp(t.data(), "MTrk", 4) != 0) break;
        u32 len = s.be32(p + 4);
        if (len > 64 * MB) break;
        p += 8 + (i64)len;
        seen++;
    }
    if (seen == 0) return -1;
    return p - off;
}void registerFmt_midi(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MIDI", "mid", "audio", S("MThd"), 64*MB, SizeMode::Container, vMidi);
      c.min_size = 22; add(c); }
}

}  // namespace ghost

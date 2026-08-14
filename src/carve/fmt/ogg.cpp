// GHOST RECOVER — ogg signature family (one file per format).
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

i64 vOgg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int pages = 0;
    while (p + 27 <= off + max && pages < 4000000) {
        auto h = s.read(p, 27);
        if (h.size() < 27) break;
        if (h[0] != 'O' || h[1] != 'g' || h[2] != 'g' || h[3] != 'S' || h[4] != 0) break;
        u8 segs = h[26];
        auto seg = s.read(p + 27, segs);
        if ((int)seg.size() < segs) break;
        i64 dataSize = 0;
        for (u8 x : seg) dataSize += x;
        i64 pageSize = 27 + segs + dataSize;
        if (p + pageSize > off + max) break;
        lastEnd = p + pageSize;
        p = lastEnd;
        pages++;
    }
    if (pages < 1) return -1;
    return lastEnd - off;
}void registerFmt_ogg(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("OPUS", "opus", "audio", S("OggS"), 1*GB, SizeMode::Container, vOgg);
      withConfirm(c, S("OpusHead"), -1, 512); c.priority = 22; c.min_size = 512; add(c); }
    { auto c = mk("OGA", "oga", "audio", S("OggS"), 1*GB, SizeMode::Container, vOgg);
      withConfirm(c, S("vorbis"), -1, 512); c.priority = 20; c.min_size = 512; add(c); }
    { auto c = mk("SPX", "spx", "audio", S("OggS"), 512*MB, SizeMode::Container, vOgg);
      withConfirm(c, S("Speex"), -1, 512); c.priority = 20; c.min_size = 512; add(c); }
    { auto c = mk("OGG", "ogg", "audio", S("OggS"), 4*GB, SizeMode::Container, vOgg);
      c.min_size = 512; add(c); }
    { auto c = mk("OGV", "ogv", "video", S("OggS"), 4*GB, SizeMode::Container, vOgg);
      withConfirm(c, S("theora"), -1, 512); c.priority = 20; c.min_size = 512; add(c); }
}

}  // namespace ghost

// GHOST RECOVER — au signature family (one file per format).
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

i64 vAu(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 dataOff = s.be32(off + 4);
    u32 dataSize = s.be32(off + 8);
    u32 encoding = s.be32(off + 12);
    u32 rate = s.be32(off + 16);
    u32 chans = s.be32(off + 20);
    if (encoding > 27) return -1;
    if (rate == 0 || rate > 200000 || chans == 0 || chans > 256) return -1;
    if (dataSize == 0xFFFFFFFFu) return -1;         // unknown: can't size it
    if (dataOff < 24 || dataOff > 32 * 1024) return -1;
    i64 end = off + (i64)dataOff + (i64)dataSize;
    return (end <= off + max) ? end - off : -1;
}void registerFmt_au(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("AU", "au", "audio", B({0x2E,'s','n','d'}), 512*MB, SizeMode::Container, vAu));
}

}  // namespace ghost

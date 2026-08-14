// GHOST RECOVER — iso signature family (one file per format).
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

i64 vIso(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off + 32768, 2048);
    if (b.size() < 134) return -1;
    if (std::memcmp(b.data() + 1, "CD001", 5) != 0) return -1;
    if (b[6] != 1) return -1;                       // PVD (type 1, not terminator)
    u16 block = (u16)b[128] | (u16)b[129] << 8;
    if (block != 512 && block != 1024 && block != 2048 && block != 4096) return -1;
    u64 vol = (u64)b[80] | (u64)b[81] << 8 | (u64)b[82] << 16 | (u64)b[83] << 24;
    if (vol < 16) return -1;
    u64 size = vol * block;
    if (size > (u64)max) size = (u64)max;
    if (size < 2048) return -1;
    return (i64)size;
}void registerFmt_iso(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ISO9660", "iso", "archive", S("CD001"), 16*GB,
                  SizeMode::Header, vIso);
      c.magic_offset = 32769; add(c); }
}

}  // namespace ghost

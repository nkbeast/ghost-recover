// GHOST RECOVER — kdb signature family (one file per format).
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

i64 vKdb(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 16);
    if (h.size() < 16) return -1;
    u32 flags = s.le32(off + 8);          // dwFlags: bit 0 = SHA-256 seed
    u32 ver = s.le32(off + 12);           // dwVersion, not the flags field
    if (flags & ~0x3u) return -1;
    if ((ver >> 16) < 1 || (ver >> 16) > 3) return -1;
    // KDB v1 carries no file length: the extent is bounded by the next
    // signature and trailing-zero trim.
    return 0;
}void registerFmt_kdb(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("KDB", "kdb", "crypto", B({0x03,0xD9,0xA2,0x9A,0x65,0xFB,0x4B,0xB5}), 256*MB, SizeMode::Header, vKdb));
}

}  // namespace ghost

// GHOST RECOVER — lzip signature family (one file per format).
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

i64 vLzip(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.byte(off + 4) < 1 || s.byte(off + 4) > 3) return -1;  // version
    // Walk the member for its trailing 20-byte trailer (CRC32 + data size +
    // member size). The member size field must equal the member's own length,
    // which can only be known once the trailer is found; the walk used to
    // advance one byte at a time, so a false "LZIP" hit at the head of a
    // large file scanned the whole window byte-by-byte (up to 8 GB of tiny
    // reads). Scan in 1 MiB blocks with an overlap instead and cap the total
    // walked distance: real members are rarely huge, and anything past 1 GiB
    // is junk or a hostile length claim.
    const i64 kStep = 1 * MB;
    const i64 kOverlap = 20;
    const i64 kWalkLimit = 1024 * 1024 * 1024;
    for (i64 base = 0; base + kOverlap < max && base < kWalkLimit; base += kStep - kOverlap) {
        i64 want = std::min(kStep, max - base);
        auto buf = s.read(off + base, want);
        if (buf.size() < 20) break;
        for (size_t i = 0; i + 20 <= buf.size(); i++) {
            i64 msize = (i64)s.be64(off + base + (i64)i + 12);
            if (msize >= 20 && msize == base + (i64)i + 20) return base + (i64)i + 20;
        }
        if ((i64)buf.size() < want) break;
        if (want <= kOverlap) break;
    }
    return -1;
}void registerFmt_lzip(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("LZIP", "lz", "archive", S("LZIP"), 8*GB, SizeMode::Header, vLzip));
}

}  // namespace ghost

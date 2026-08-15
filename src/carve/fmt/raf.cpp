// GHOST RECOVER — raf signature family (one file per format).
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

i64 vRaf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // The header carries the embedded JPEG extent, but metadata trailers
    // commonly follow it, so no single field yields the true file size:
    // report an unknown size and let the next-signature bound and trailing
    // zero trim size the carve.
    return 0;
}void registerFmt_raf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("RAF", "raf", "image", S("FUJIFILMCCD-RAW "), 256*MB, SizeMode::Header, vRaf));
}

}  // namespace ghost

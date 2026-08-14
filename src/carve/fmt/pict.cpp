// GHOST RECOVER — PICT image signatures.
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

void registerFmt_pict(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PICT", "pct", "image", B({0x00, 0x11, 0x02, 0xFF, 0x0C, 0x00, 0x00, 0x00}), 64*MB); add(c); }
}

}  // namespace ghost

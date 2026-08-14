// GHOST RECOVER — FDF document signatures.
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

void registerFmt_fdf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("FDF", "fdf", "document", B({0x25, 0x46, 0x44, 0x46, 0x2D}), 64*MB, SizeMode::Text, vText); c.min_size = 64; add(c); }
}

}  // namespace ghost

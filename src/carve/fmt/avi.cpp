// GHOST RECOVER — avi signature family (one file per format).
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

void registerFmt_avi(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("AVI", "avi", "video", S("RIFF"), 8*GB, SizeMode::Header, vRiff);
      withConfirm(c, S("AVI "), 8); c.priority = 20; c.min_size = 1024; add(c); }
}

}  // namespace ghost

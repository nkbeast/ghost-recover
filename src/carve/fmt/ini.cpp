// GHOST RECOVER — ini signature family (one file per format).
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

void registerFmt_ini(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("INI_UNIT", "service", "code", S("[Unit]\n"), 1*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("GIT_CONFIG", "gitconfig", "code", S("[core]\n"), 1*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
}

}  // namespace ghost

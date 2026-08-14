// GHOST RECOVER — shebang signature family (one file per format).
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

void registerFmt_shebang(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("SHEBANG_SH", "sh", "code", S("#!/bin/sh"), 8*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("SHEBANG_BASH", "sh", "code", S("#!/bin/bash"), 8*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("SHEBANG_ENV", "sh", "code", S("#!/usr/bin/env "), 8*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
}

}  // namespace ghost

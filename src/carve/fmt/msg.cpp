// GHOST RECOVER — msg signature family (one file per format).
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

void registerFmt_msg(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MSG", "msg", "email", B({0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}), 512*MB,
                  SizeMode::Header, vOle2);
      withConfirm(c, U16("__nameid"), -1, 16384); c.priority = 30; add(c); }
}

}  // namespace ghost

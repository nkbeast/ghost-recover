// GHOST RECOVER — wav signature family (one file per format).
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

void registerFmt_wav(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("WAV", "wav", "audio", S("RIFF"), 4*GB, SizeMode::Header, vRiff);
      withConfirm(c, S("WAVE"), 8); c.priority = 20; c.min_size = 44; add(c); }
}

}  // namespace ghost

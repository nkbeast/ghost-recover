// GHOST RECOVER — zip signature family (one file per format).
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

void registerFmt_zip(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ZIP", "zip", "archive", B({'P','K',0x03,0x04}), 8*GB, SizeMode::Header, vZip);
      c.min_size = 100; add(c); }
    { auto c = mk("JAR", "jar", "archive", B({'P','K',0x03,0x04}), 2*GB, SizeMode::Header, vZip);
      withConfirm(c, S("META-INF/MANIFEST"), -1, 8192); c.priority = 25; add(c); }
    { auto c = mk("APK", "apk", "archive", B({'P','K',0x03,0x04}), 4*GB, SizeMode::Header, vZip);
      withConfirm(c, S("AndroidManifest"), -1, 16384); c.priority = 28; add(c); }
}

}  // namespace ghost

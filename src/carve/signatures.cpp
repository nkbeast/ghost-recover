// GHOST RECOVER — carver signature registry aggregator.
//
// The per-format specs live in sig_<category>.cpp (one file per category);
// this file only assembles them into the program-wide registry and owns the
// debug probe harness. Specs are registered with stable ids ordered by
// priority so the engine prefers the most specific spec when several match
// at the same offset.
#include "ghost/carve.h"
#include "sig_common.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace ghost {

namespace {

std::vector<CarveSpec> buildRegistry() {
    std::vector<CarveSpec> r;
    registerImages(r);
    registerVideo(r);
    registerAudio(r);
    registerDocuments(r);
    registerEmail(r);
    registerArchives(r);
    registerDatabases(r);
    registerCrypto(r);
    registerExecutables(r);
    registerForensic(r);
    registerVm(r);
    registerFonts(r);
    registerMisc(r);
    registerCode(r);
    // Assign a stable id order: higher priority first so the engine prefers the
    // most specific spec when several match at the same offset.
    std::stable_sort(r.begin(), r.end(),
                     [](const CarveSpec& a, const CarveSpec& b) { return a.priority > b.priority; });
    return r;
}

}  // namespace


const std::vector<CarveSpec>& carverRegistry() {
    static const std::vector<CarveSpec> reg = buildRegistry();
    return reg;
}

std::vector<std::string> carverCategories() {
    std::vector<std::string> out;
    for (const auto& c : carverRegistry()) {
        if (std::find(out.begin(), out.end(), c.category) == out.end()) out.push_back(c.category);
    }
    std::sort(out.begin(), out.end());
    return out;
}

}  // namespace ghost

// Debugging probe: run one named validator over a ByteSource. Used by the
// standalone validator harness in tests; never called from the engine.
namespace ghost {
i64 probeValidate(const std::string& name, ByteSource& bs, i64 off, i64 max) {
    for (const auto& c : carverRegistry()) {
        if (c.name != name || !c.validator) continue;
        return c.validator(bs, off, max, c);
    }
    return -999;
}
}  // namespace ghost

